//! Canonical serialization and content addressing.
//!
//! The contract this whole crate exists to check. Written from the format
//! description rather than from the primary implementation's source, because
//! an implementation that agrees by construction proves nothing about the
//! format -- it only proves the two files are copies.
//!
//! The format:
//!
//! - Object keys sorted by code point, no insignificant whitespace, UTF-8.
//! - Non-ASCII stays raw; it is never `\u`-escaped.
//! - Escapes: `"` and `\`, the five short forms `\b \t \n \f \r`, and every
//!   other control character below 0x20 as `\u00XX`. DEL and `/` are not
//!   escaped.
//! - Integers only. No float variant exists, so a float cannot enter a record
//!   at all: IEEE-754 doubles do not round-trip identically through every JSON
//!   implementation, which is precisely the disagreement this format forbids.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest as _, Sha256};

pub const DIGEST_PREFIX: &str = "sha256:";

/// Recursion ceiling for the decoder. A deliberately deep document must be
/// refused rather than overflow the stack.
const MAX_DEPTH: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i128),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalError(pub String);

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CanonicalError {}

impl Value {
    pub fn object<I, K>(pairs: I) -> Value
    where
        I: IntoIterator<Item = (K, Value)>,
        K: Into<String>,
    {
        Value::Object(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }

    pub fn string(text: impl Into<String>) -> Value {
        Value::String(text.into())
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(map) => map.get(key),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(text) => Some(text),
            _ => None,
        }
    }

    /// Integers only, and never a bool. Many languages conflate the two; a
    /// format whose ids must match across them cannot.
    pub fn as_i128(&self) -> Option<i128> {
        match self {
            Value::Int(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.as_i128().and_then(|v| i64::try_from(v).ok())
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_i128().and_then(|v| u64::try_from(v).ok())
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, Value>> {
        match self {
            Value::Object(map) => Some(map),
            _ => None,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_string().into_bytes()
    }

    pub fn canonical_string(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    pub fn digest(&self) -> String {
        digest_bytes(&self.canonical_bytes())
    }

    fn write(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Int(value) => out.push_str(&value.to_string()),
            Value::String(text) => escape(text, out),
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                // BTreeMap iterates in UTF-8 byte order, which for UTF-8 is
                // code-point order -- the order the format specifies.
                for (index, (key, item)) in map.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    escape(key, out);
                    out.push(':');
                    item.write(out);
                }
                out.push('}');
            }
        }
    }

    /// Parse JSON into a canonical value, refusing floats at the boundary.
    ///
    /// Hand-rolled, like the encoder. Handing a JSON library authority over
    /// what a record's bytes mean would give that library's private
    /// conventions consensus weight -- a real failure the primary
    /// implementation hit, where a library decoded an object whose first key
    /// was its own internal number token as a *number*.
    pub fn from_json(text: &str) -> Result<Value, CanonicalError> {
        let mut parser = Parser {
            bytes: text.as_bytes(),
            text,
            at: 0,
        };
        parser.skip_space();
        let value = parser.value(0, "$")?;
        parser.skip_space();
        if parser.at != text.len() {
            return Err(parser.bad("trailing characters after the value"));
        }
        Ok(value)
    }
}

fn escape(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            other if (other as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", other as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// Lowercase hex, two characters per byte.
///
/// `sha2` 0.11's output type dropped the `LowerHex` impl the previous
/// `format!("{:x}", ..)` spelling relied on. Spelled out here rather than
/// reached for from the primary implementation: the hex text of a digest *is*
/// a record id, and this crate exists to derive those independently.
pub fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn digest_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{DIGEST_PREFIX}{}", hex_lower(&hasher.finalize()))
}

/// Display form. By characters, never bytes: these strings come from records
/// other people wrote, and slicing one mid-character panics.
pub fn short(identifier: &str) -> String {
    match identifier.strip_prefix(DIGEST_PREFIX) {
        Some(rest) => format!(
            "{DIGEST_PREFIX}{}",
            rest.chars().take(8).collect::<String>()
        ),
        None => identifier.chars().take(8).collect(),
    }
}

/// Binary Merkle root over pre-hashed leaves.
///
/// An odd node is **promoted**, not duplicated. Duplicating the last leaf lets
/// two different leaf sets produce one root -- Bitcoin's CVE-2012-2459.
pub fn merkle_root(leaves: &[String]) -> Option<String> {
    if leaves.is_empty() {
        return None;
    }
    let mut level: Vec<String> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut index = 0;
        while index + 1 < level.len() {
            next.push(digest_bytes(
                format!("{}{}", level[index], level[index + 1]).as_bytes(),
            ));
            index += 2;
        }
        if level.len() % 2 == 1 {
            next.push(level[level.len() - 1].clone());
        }
        level = next;
    }
    Some(level.remove(0))
}

/// The widths of every level of a tree with `leaves` leaves, bottom up.
///
/// The tree's shape is fully determined by its leaf count, and the shape is
/// what decides which levels promote. Computing it up front makes both
/// [`merkle_proof`] and [`Inclusion::verify`] straight walks over a list, and
/// -- more to the point -- it is a *different* decomposition from the primary
/// implementation, which recomputes the width as it folds. Two implementations
/// that arrange the same rule differently are two chances to catch the rule
/// being wrong.
fn level_widths(leaves: usize) -> Vec<usize> {
    let mut widths = Vec::new();
    let mut width = leaves;
    while width > 1 {
        widths.push(width);
        width = width.div_ceil(2);
    }
    widths
}

/// A path from one leaf to a [`merkle_root`].
///
/// See the primary implementation for the argument about why `leaves` is a
/// shape parameter rather than a commitment. The two must agree exactly:
/// `scripts/differential.sh` checks that each accepts what the other emits,
/// because a challenger and a holder who disagree about a proof's validity
/// slash an honest node or pay a lying one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inclusion {
    pub index: usize,
    pub leaves: usize,
    pub siblings: Vec<String>,
}

/// The path proving `leaves[index]` is under `merkle_root(leaves)`.
pub fn merkle_proof(leaves: &[String], index: usize) -> Option<Inclusion> {
    if index >= leaves.len() {
        return None;
    }
    let mut siblings = Vec::new();
    let mut level: Vec<String> = leaves.to_vec();
    let mut at = index;
    for width in level_widths(leaves.len()) {
        // The odd node at the end of a level has no partner: it rises unchanged
        // and contributes nothing to the path.
        if !(width % 2 == 1 && at == width - 1) {
            let partner = if at.is_multiple_of(2) { at + 1 } else { at - 1 };
            siblings.push(level[partner].clone());
        }
        let mut next = Vec::with_capacity(width.div_ceil(2));
        let mut i = 0;
        while i + 1 < width {
            next.push(digest_bytes(
                format!("{}{}", level[i], level[i + 1]).as_bytes(),
            ));
            i += 2;
        }
        if width % 2 == 1 {
            next.push(level[width - 1].clone());
        }
        level = next;
        at /= 2;
    }
    Some(Inclusion {
        index,
        leaves: leaves.len(),
        siblings,
    })
}

impl Inclusion {
    /// Walk this path from `leaf` and report whether it arrives at `root`.
    ///
    /// The leaf is an argument rather than something the path carries: this
    /// tree has no domain separation between leaves and internal nodes, so a
    /// prover who could name the leaf could offer an internal node as one.
    pub fn verify(&self, leaf: &str, root: &str) -> bool {
        if self.index >= self.leaves {
            return false;
        }
        let mut hash = leaf.to_string();
        let mut at = self.index;
        let mut supplied = self.siblings.iter();
        for width in level_widths(self.leaves) {
            if width % 2 == 1 && at == width - 1 {
                at /= 2;
                continue;
            }
            let Some(sibling) = supplied.next() else {
                return false;
            };
            let joined = if at.is_multiple_of(2) {
                format!("{hash}{sibling}")
            } else {
                format!("{sibling}{hash}")
            };
            hash = digest_bytes(joined.as_bytes());
            at /= 2;
        }
        // Leftover siblings mean the two sides disagree about the tree's shape,
        // and a proof that reads two ways is not a proof.
        supplied.next().is_none() && hash == root
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("index", Value::Int(self.index as i128)),
            ("leaves", Value::Int(self.leaves as i128)),
            (
                "siblings",
                Value::Array(self.siblings.iter().cloned().map(Value::string).collect()),
            ),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Inclusion, String> {
        let count = |name: &str| -> Result<usize, String> {
            value
                .get(name)
                .and_then(Value::as_i128)
                .and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| format!("inclusion needs a non-negative {name}"))
        };
        let siblings = match value.get("siblings") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_string)
                        .ok_or_else(|| String::from("every sibling must be a string"))
                })
                .collect::<Result<Vec<String>, String>>()?,
            _ => return Err(String::from("inclusion needs a siblings array")),
        };
        Ok(Inclusion {
            index: count("index")?,
            leaves: count("leaves")?,
            siblings,
        })
    }
}

// -- decoding ---------------------------------------------------------------

struct Parser<'a> {
    bytes: &'a [u8],
    text: &'a str,
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn skip_space(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn bad(&self, why: &str) -> CanonicalError {
        CanonicalError(format!("malformed JSON: {why} at byte {}", self.at))
    }

    fn value(&mut self, depth: usize, path: &str) -> Result<Value, CanonicalError> {
        if depth > MAX_DEPTH {
            return Err(CanonicalError("malformed JSON: too deeply nested".into()));
        }
        match self.peek() {
            Some(b'n') => self.literal("null", Value::Null),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'"') => self.string().map(Value::String),
            Some(b'[') => self.array(depth, path),
            Some(b'{') => self.map(depth, path),
            Some(b'-' | b'0'..=b'9') => self.number(path),
            Some(_) => Err(self.bad("unexpected character")),
            None => Err(self.bad("unexpected end of input")),
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, CanonicalError> {
        if self.text[self.at..].starts_with(word) {
            self.at += word.len();
            Ok(value)
        } else {
            Err(self.bad("invalid literal"))
        }
    }

    fn array(&mut self, depth: usize, path: &str) -> Result<Value, CanonicalError> {
        self.at += 1;
        self.skip_space();
        let mut out = Vec::new();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Array(out));
        }
        loop {
            out.push(self.value(depth + 1, &format!("{path}[{}]", out.len()))?);
            self.skip_space();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.skip_space();
                }
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Array(out));
                }
                _ => return Err(self.bad("expected ',' or ']'")),
            }
        }
    }

    fn map(&mut self, depth: usize, path: &str) -> Result<Value, CanonicalError> {
        self.at += 1;
        self.skip_space();
        let mut out = BTreeMap::new();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(out));
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(self.bad("expected a string key"));
            }
            let key = self.string()?;
            self.skip_space();
            if self.peek() != Some(b':') {
                return Err(self.bad("expected ':'"));
            }
            self.at += 1;
            self.skip_space();
            let value = self.value(depth + 1, &format!("{path}.{key}"))?;
            // Last wins, which is what `json.loads` does.
            out.insert(key, value);
            self.skip_space();
            match self.peek() {
                Some(b',') => {
                    self.at += 1;
                    self.skip_space();
                }
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Object(out));
                }
                _ => return Err(self.bad("expected ',' or '}'")),
            }
        }
    }

    fn number(&mut self, path: &str) -> Result<Value, CanonicalError> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.at += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.bad("leading zero"));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.at += 1;
                }
            }
            _ => return Err(self.bad("expected a digit")),
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.at += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.bad("expected a digit after '.'"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.at += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_float = true;
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.bad("expected a digit in the exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.at += 1;
            }
        }
        if is_float {
            return Err(CanonicalError(format!(
                "{path}: float values are not canonically serializable"
            )));
        }
        self.text[start..self.at]
            .parse::<i128>()
            .map(Value::Int)
            .map_err(|_| {
                CanonicalError(format!(
                    "{path}: integer outside the signed 128-bit canonical range"
                ))
            })
    }

    fn string(&mut self) -> Result<String, CanonicalError> {
        self.at += 1;
        let mut out = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(self.bad("unterminated string"));
            };
            match byte {
                b'"' => {
                    self.at += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.at += 1;
                    let Some(escape) = self.peek() else {
                        return Err(self.bad("unterminated escape"));
                    };
                    self.at += 1;
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(self.bad("unknown escape")),
                    }
                }
                0x00..=0x1F => return Err(self.bad("raw control character in string")),
                byte if byte < 0x80 => {
                    out.push(byte as char);
                    self.at += 1;
                }
                _ => {
                    // Input is a &str, so the sequence is already valid UTF-8.
                    let ch = self.text[self.at..].chars().next().expect("valid utf-8");
                    out.push(ch);
                    self.at += ch.len_utf8();
                }
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, CanonicalError> {
        let high = self.hex4()?;
        if (0xDC00..=0xDFFF).contains(&high) {
            return Err(self.bad("lone trailing surrogate"));
        }
        if (0xD800..=0xDBFF).contains(&high) {
            if self.peek() != Some(b'\\') {
                return Err(self.bad("lone leading surrogate"));
            }
            self.at += 1;
            if self.peek() != Some(b'u') {
                return Err(self.bad("lone leading surrogate"));
            }
            self.at += 1;
            let low = self.hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(self.bad("lone leading surrogate"));
            }
            let code = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
            return char::from_u32(code).ok_or_else(|| self.bad("invalid escape"));
        }
        char::from_u32(high).ok_or_else(|| self.bad("invalid escape"))
    }

    fn hex4(&mut self) -> Result<u32, CanonicalError> {
        let slice = self
            .text
            .get(self.at..self.at + 4)
            .filter(|s| s.bytes().all(|b| b.is_ascii_hexdigit()))
            .ok_or_else(|| self.bad("expected four hex digits"))?;
        self.at += 4;
        Ok(u32::from_str_radix(slice, 16).expect("checked hex"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn del_and_slash_are_not_escaped() {
        // The two an encoder is most likely to escape out of habit -- many
        // JSON writers escape `/`, and several escape DEL as a control
        // character. This format does neither, and a digest computed either
        // way is a digest nobody else reproduces.
        assert_eq!(Value::string("/").canonical_string(), "\"/\"");
        assert_eq!(Value::string("\u{7f}").canonical_string(), "\"\u{7f}\"");
    }

    #[test]
    fn control_characters_use_the_five_short_forms_then_u00xx() {
        let cases = [
            ("\u{08}", "\"\\b\""),
            ("\t", "\"\\t\""),
            ("\n", "\"\\n\""),
            ("\u{0c}", "\"\\f\""),
            ("\r", "\"\\r\""),
            ("\u{00}", "\"\\u0000\""),
            ("\u{01}", "\"\\u0001\""),
            ("\u{1f}", "\"\\u001f\""),
        ];
        for (raw, want) in cases {
            assert_eq!(Value::string(raw).canonical_string(), want, "{raw:?}");
        }
    }

    #[test]
    fn non_ascii_stays_raw() {
        // Escaping it would be valid JSON and the wrong bytes.
        assert_eq!(Value::string("é😀").canonical_string(), "\"é😀\"");
    }

    #[test]
    fn keys_sort_by_code_point() {
        // Uppercase before lowercase, digits before both, and `_`/`~` where
        // ASCII puts them -- not where a locale-aware collation would.
        let value = Value::object([
            ("~", Value::Int(1)),
            ("a", Value::Int(2)),
            ("Z", Value::Int(3)),
            ("_", Value::Int(4)),
            ("0", Value::Int(5)),
            ("é", Value::Int(6)),
        ]);
        assert_eq!(
            value.canonical_string(),
            "{\"0\":5,\"Z\":3,\"_\":4,\"a\":2,\"~\":1,\"é\":6}"
        );
    }

    #[test]
    fn floats_are_refused_at_the_boundary() {
        for text in ["1.5", "1e3", "1E3", "-0.0", "[1,2.5]", "{\"a\":1.0}"] {
            assert!(Value::from_json(text).is_err(), "{text} parsed");
        }
    }

    #[test]
    fn integers_span_i128_and_refuse_beyond_it() {
        assert_eq!(
            Value::from_json(&i128::MAX.to_string()),
            Ok(Value::Int(i128::MAX))
        );
        assert_eq!(
            Value::from_json(&i128::MIN.to_string()),
            Ok(Value::Int(i128::MIN))
        );
        assert!(Value::from_json(&(i128::MAX as u128 + 1).to_string()).is_err());
    }

    #[test]
    fn malformed_json_is_refused() {
        for text in [
            "",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "01",
            "1.",
            ".5",
            "+1",
            "nul",
            "NaN",
            "Infinity",
            "'x'",
            "\"unterminated",
            "\"\\q\"",
            "1 2",
            "\"\\ud800\"",
            "\"\\udc00\"",
        ] {
            assert!(Value::from_json(text).is_err(), "{text:?} parsed");
        }
    }

    #[test]
    fn surrogate_pairs_combine_and_raw_control_characters_do_not() {
        assert_eq!(
            Value::from_json("\"\\ud83d\\ude00\"").unwrap(),
            Value::string("😀")
        );
        assert!(Value::from_json("\"\u{01}\"").is_err());
    }

    #[test]
    fn the_encoder_round_trips_through_the_decoder() {
        // Anything this implementation writes it must be able to read back,
        // or a log it produced would be one it cannot audit.
        let value = Value::object([
            (
                "ctrl",
                Value::string("\t\n\r\u{08}\u{0c}\u{00}\u{1f}\u{7f}"),
            ),
            ("uni", Value::string("é 日本 😀")),
            (
                "nums",
                Value::Array(vec![
                    Value::Int(i128::MIN),
                    Value::Int(0),
                    Value::Int(i128::MAX),
                ]),
            ),
            (
                "nested",
                Value::object([("/", Value::Null), ("\\", Value::Bool(true))]),
            ),
        ]);
        let text = value.canonical_string();
        assert_eq!(Value::from_json(&text).unwrap(), value);
        assert_eq!(Value::from_json(&text).unwrap().canonical_string(), text);
    }

    #[test]
    fn merkle_promotes_the_odd_node_rather_than_duplicating_it() {
        // Duplicating the last leaf lets two leaf sets share a root --
        // Bitcoin's CVE-2012-2459.
        let a = digest_bytes(b"a");
        let b = digest_bytes(b"b");
        let three = merkle_root(&[a.clone(), b.clone(), a.clone()]).unwrap();
        let four = merkle_root(&[a.clone(), b.clone(), a.clone(), a.clone()]).unwrap();
        assert_ne!(three, four);
        assert_eq!(merkle_root(&[]), None);
        assert_eq!(merkle_root(std::slice::from_ref(&a)), Some(a));
    }

    #[test]
    fn every_leaf_of_every_shape_proves_against_its_own_root() {
        // Exhaustive over shapes: the promotion rule fires on a different set
        // of levels for every odd width, so a proof that works for eight
        // leaves says nothing about seven. This is also the property the two
        // implementations must share exactly -- see scripts/differential.sh.
        for count in 1..=40usize {
            let leaves: Vec<String> = (0..count).map(|i| format!("leaf-{i}")).collect();
            let root = merkle_root(&leaves).expect("non-empty");
            for index in 0..count {
                let proof = merkle_proof(&leaves, index).expect("in range");
                assert!(
                    proof.verify(&leaves[index], &root),
                    "leaf {index} of {count} did not verify"
                );
            }
        }
    }

    #[test]
    fn a_proof_is_about_one_leaf_and_one_shape() {
        let leaves: Vec<String> = (0..9).map(|i| format!("leaf-{i}")).collect();
        let root = merkle_root(&leaves).expect("non-empty");
        let proof = merkle_proof(&leaves, 3).expect("in range");
        for (index, leaf) in leaves.iter().enumerate() {
            assert_eq!(proof.verify(leaf, &root), index == 3, "leaf {index}");
        }

        // A path with the wrong number of hashes is refused rather than
        // ignored: a proof that reads two ways is not a proof.
        let mut short = proof.clone();
        short.siblings.pop();
        assert!(!short.verify(&leaves[3], &root));
        let mut long = proof.clone();
        long.siblings.push(digest_bytes(b"extra"));
        assert!(!long.verify(&leaves[3], &root));

        assert_eq!(merkle_proof(&leaves, 9), None);
        assert_eq!(merkle_proof(&[], 0), None);
    }

    #[test]
    fn a_promoted_node_carries_no_sibling_for_that_level() {
        // [a,b,c] pairs a+b and promotes c, so c's path is one hash shorter.
        let leaves: Vec<String> = (0..3).map(|i| format!("leaf-{i}")).collect();
        let root = merkle_root(&leaves).expect("non-empty");
        assert_eq!(
            merkle_proof(&leaves, 0).expect("in range").siblings.len(),
            2
        );
        assert_eq!(
            merkle_proof(&leaves, 1).expect("in range").siblings.len(),
            2
        );
        let promoted = merkle_proof(&leaves, 2).expect("in range");
        assert_eq!(promoted.siblings.len(), 1);
        assert!(promoted.verify(&leaves[2], &root));
    }

    #[test]
    fn an_inclusion_survives_the_trip_through_json() {
        let leaves: Vec<String> = (0..6).map(|i| format!("leaf-{i}")).collect();
        let proof = merkle_proof(&leaves, 4).expect("in range");
        let text = proof.to_value().canonical_string();
        let decoded =
            Inclusion::from_value(&Value::from_json(&text).expect("parse")).expect("decode");
        assert_eq!(decoded, proof);
        assert!(decoded.verify(&leaves[4], &merkle_root(&leaves).expect("non-empty")));
        // A stranger controls this input, so a negative count is refused
        // rather than wrapped into a plausible-looking one.
        let bad = Value::from_json(r#"{"index":-1,"leaves":6,"siblings":[]}"#).expect("parse");
        assert!(Inclusion::from_value(&bad).is_err());
    }

    #[test]
    fn short_never_panics_on_multi_byte_identifiers() {
        assert_eq!(short("sha256:1234567é9"), "sha256:1234567é");
        assert_eq!(short("é234567890"), "é2345678");
    }
}
