//! Lowercase hex, written out here rather than pulled in.
//!
//! Every digest this crate prints -- record ids, blob addresses, epoch beacons,
//! settlement ranks -- is hex text that other implementations must reproduce
//! byte for byte, so the encoder is part of the wire format and belongs in the
//! repository that pins it. `sha2` 0.11 removed the `LowerHex` impl its output
//! type used to carry, which is what made the previous `format!("{:x}", ..)`
//! spelling stop compiling; that formatter was never the contract, this is.
//!
//! **Not constant time**: it branches per nibble. Every value it is applied to
//! is published. No secret in this crate has a hex or `Display` form, precisely
//! so that this function cannot be pointed at one.

/// Encode `bytes` as lowercase hex, two characters per byte, no prefix.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(digit(byte >> 4));
        out.push(digit(byte & 0x0f));
    }
    out
}

fn digit(value: u8) -> char {
    match value {
        0..=9 => char::from(b'0' + value),
        10..=15 => char::from(b'a' + value - 10),
        // Unreachable: callers pass a nibble. Total anyway, because a panic in a
        // formatter is a worse outcome than an odd character.
        _ => '?',
    }
}

#[cfg(test)]
mod tests {
    use super::encode;

    #[test]
    fn encodes_lowercase_two_characters_per_byte() {
        assert_eq!(encode(&[]), "");
        assert_eq!(encode(&[0x00]), "00");
        assert_eq!(encode(&[0x0f, 0xf0]), "0ff0");
        assert_eq!(encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }

    #[test]
    fn every_byte_round_trips_through_the_table() {
        for byte in 0u8..=255 {
            let text = encode(&[byte]);
            assert_eq!(text.len(), 2);
            assert_eq!(u8::from_str_radix(&text, 16).unwrap(), byte);
            assert!(text
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        }
    }
}
