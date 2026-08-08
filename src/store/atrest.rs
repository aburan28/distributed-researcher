//! Encryption of the local store, at rest.
//!
//! # What this defends against, stated narrowly
//!
//! A node's data directory ends up in places its operator did not think hard
//! about: a cloud-synced folder, a laptop backup, an external drive, a machine
//! that gets sold. [`crate::store::mirror`] exists precisely to put a copy
//! somewhere else, which makes the question urgent rather than theoretical.
//! Encrypting at rest means those copies are inert.
//!
//! It does **not** defend against an attacker with live access to a running
//! node. The key has to be readable for the node to work, so anyone who can run
//! code as the operator can read it. Saying otherwise would be the kind of
//! oversold confidentiality claim `crate::crypto` opens by warning about.
//!
//! The property that makes this worth anything is therefore not the cipher --
//! it is that **the key can live somewhere the data does not**. A key file
//! inside the directory you sync to Dropbox has bought you nothing, so
//! [`crate::store::mirror`] refuses to copy it and says why.
//!
//! # Why per-line rather than per-file
//!
//! The log is append-only ([`crate::ledger`]), and that is not an
//! implementation detail -- it is what makes an append `O(1)` and what makes a
//! torn tail detectable rather than corrupting. Encrypting the file as a unit
//! would mean decrypt-append-reencrypt-rewrite on every record: `O(n)` per
//! append, a full rewrite window in which a crash loses the whole log, and the
//! end of the property that entry *n* is at line *n*.
//!
//! So each line is sealed on its own:
//!
//! ```text
//! pwenc1:<nonce hex>:<ciphertext hex>
//! ```
//!
//! Appending stays appending. The hash chain is untouched, because it covers
//! *plaintext* -- encryption is a storage concern and the chain is an integrity
//! one, and keeping them separate means [`crate::ledger::Ledger::verify_chain`]
//! needed no changes at all.
//!
//! # The AEAD associated data is doing real work
//!
//! Each line's associated data binds its **position in the file**. Without it,
//! ciphertext lines are independent blobs: an attacker holding the encrypted log
//! could reorder them, delete one from the middle, or splice in a line from a
//! different log, and every line would still decrypt perfectly. The hash chain
//! would catch it afterwards -- but only after decrypting, and only if somebody
//! ran `verify_chain`. Binding the index makes it a decryption failure at the
//! exact line, which is both earlier and more specific.
//!
//! # Nonces are random, not derived from the index
//!
//! Deriving the nonce from the line number would be smaller on disk and is a
//! trap: truncate a log and append again -- a crash, a restore from backup, a
//! resumed sync -- and index 12 is reused under the same key. ChaCha20-Poly1305
//! does not merely leak under nonce reuse, it collapses: two messages under one
//! nonce expose their XOR and, worse, permit forgery. Twelve random bytes per
//! line costs 24 hex characters and removes the failure mode.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use rand_core::{CryptoRng, RngCore};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use crate::crypto::Secret32;

/// Bytes in a ChaCha20-Poly1305 key.
const KEY_LEN: usize = 32;
/// Bytes in a ChaCha20-Poly1305 nonce.
const NONCE_LEN: usize = 12;
/// Bytes of salt for the passphrase KDF.
const SALT_LEN: usize = 16;

/// Prefix on an encrypted log line. Version it, because a format that cannot say
/// which version it is cannot be changed later without guessing.
pub const LINE_PREFIX: &str = "pwenc1:";
/// Prefix on a key file holding a bare key.
const KEY_PREFIX: &str = "pwkey1:";
/// Prefix on a key file wrapped with a passphrase.
const WRAPPED_PREFIX: &str = "pwkey1a:";

/// Associated data for a wrapped key file.
const KEY_AAD: &[u8] = b"proofwork-keyfile-v1";
/// Associated data prefix for a log line; the line index is appended.
const LINE_AAD: &str = "proofwork-log-v1:";

/// Argon2id cost parameters.
///
/// 64 MiB and three passes is the OWASP baseline, chosen over something showier
/// for a specific reason: this key file has to be openable on the machine that
/// wrote it, and a node operator running in a small container who cannot unlock
/// their own store has lost their data. The cost is recorded *in the file*, so
/// raising it later does not orphan existing key files.
const ARGON_MEMORY_KIB: u32 = 64 * 1024;
const ARGON_PASSES: u32 = 3;
const ARGON_LANES: u32 = 1;

/// Everything that can go wrong storing or retrieving a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtRestError {
    /// The key file does not exist.
    NoKeyFile { path: PathBuf },
    /// The key file exists but is not a key file this version understands.
    MalformedKeyFile { path: PathBuf, reason: String },
    /// A passphrase was needed and not supplied, or supplied and wrong.
    ///
    /// Deliberately one variant rather than two. Distinguishing "this file is
    /// passphrase-wrapped" from "your passphrase is wrong" is fine -- the first
    /// is structural and the file says so in the clear -- but distinguishing
    /// *which* passphrase attempt failed is an oracle, so the failure is
    /// uniform.
    Passphrase { path: PathBuf },
    /// A line is not in the encrypted format at all.
    ///
    /// The common cause is the honest one: an unencrypted log opened with a key.
    NotEncrypted { line: u64 },
    /// A line is in the encrypted format and did not authenticate.
    ///
    /// Wrong key, tampering, reordering, or a line spliced in from another log
    /// -- indistinguishable by design, and all of them mean "do not trust this".
    Undecryptable { line: u64 },
    /// The key file could not be read or written.
    Io { context: String, reason: String },
    /// The KDF refused its own parameters, which means the build is wrong
    /// rather than the input.
    Kdf(String),
}

impl fmt::Display for AtRestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AtRestError::NoKeyFile { path } => write!(
                f,
                "no key file at {}; create one with `proofwork keygen`",
                path.display()
            ),
            AtRestError::MalformedKeyFile { path, reason } => {
                write!(f, "{}: not a proofwork key file: {reason}", path.display())
            }
            AtRestError::Passphrase { path } => write!(
                f,
                "{} is passphrase-wrapped and the passphrase was missing or wrong",
                path.display()
            ),
            AtRestError::NotEncrypted { line } => write!(
                f,
                "line {line} is not encrypted, but a key was supplied; this log \
                 is in plaintext -- open it without a key, or run `proofwork \
                 store encrypt` to convert it"
            ),
            AtRestError::Undecryptable { line } => write!(
                f,
                "line {line} did not authenticate: wrong key, or the log has \
                 been altered, reordered, or spliced"
            ),
            AtRestError::Io { context, reason } => write!(f, "{context}: {reason}"),
            AtRestError::Kdf(reason) => write!(f, "key derivation failed: {reason}"),
        }
    }
}

impl std::error::Error for AtRestError {}

/// A key that seals the local store.
///
/// Wraps [`Secret32`], so the bytes are zeroed on drop and never appear in a
/// `Debug` rendering. Clone is deliberately not derived: a key with an unknown
/// number of copies is a key whose lifetime cannot be reasoned about.
pub struct Cipher {
    key: Secret32,
}

impl fmt::Debug for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cipher(<redacted>)")
    }
}

impl Cipher {
    /// Build a cipher from raw key bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Cipher {
        Cipher {
            key: Secret32::new(bytes),
        }
    }

    /// A fresh random key.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Cipher {
        let mut bytes = [0u8; KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Cipher::from_bytes(bytes)
    }

    /// Seal one log line. `index` is its zero-based position in the file.
    ///
    /// The plaintext is `&[u8]` rather than `&str` so this stays honest about
    /// what it protects: whatever bytes the caller had, not "a string".
    pub fn seal_line<R: RngCore + CryptoRng>(
        &self,
        index: u64,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<String, AtRestError> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce_bytes);
        let aad = line_aad(index);
        let cipher = ChaCha20Poly1305::new(self.key.expose().into());
        let sealed = cipher
            .encrypt(
                (&nonce_bytes).into(),
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            // AEAD encryption fails only on a length that cannot arise from a
            // log line. Reported rather than unwrapped, because "cannot arise"
            // is an argument about today's callers.
            .map_err(|_| AtRestError::Io {
                context: format!("sealing line {index}"),
                reason: String::from("payload too large to encrypt"),
            })?;
        Ok(format!(
            "{LINE_PREFIX}{}:{}",
            hex_encode(&nonce_bytes),
            hex_encode(&sealed)
        ))
    }

    /// Open one sealed log line.
    pub fn open_line(&self, index: u64, line: &str) -> Result<Vec<u8>, AtRestError> {
        let rest = line
            .strip_prefix(LINE_PREFIX)
            .ok_or(AtRestError::NotEncrypted { line: index })?;
        let (nonce_hex, ciphertext_hex) = rest
            .split_once(':')
            .ok_or(AtRestError::Undecryptable { line: index })?;
        // Fixed-size on the spot rather than a `Vec` with a length check beside
        // it: the AEAD wants an array-shaped nonce, and converting here means
        // the wrong length is refused in the one place it can be.
        let nonce_bytes: [u8; NONCE_LEN] = hex_decode(nonce_hex)
            .and_then(|bytes| <[u8; NONCE_LEN]>::try_from(bytes).ok())
            .ok_or(AtRestError::Undecryptable { line: index })?;
        let ciphertext =
            hex_decode(ciphertext_hex).ok_or(AtRestError::Undecryptable { line: index })?;
        let aad = line_aad(index);
        let cipher = ChaCha20Poly1305::new(self.key.expose().into());
        cipher
            .decrypt(
                (&nonce_bytes).into(),
                Payload {
                    msg: &ciphertext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| AtRestError::Undecryptable { line: index })
    }

    /// Write this key to `path`, optionally wrapped with a passphrase.
    ///
    /// Refuses to overwrite. A key file that silently replaced its predecessor
    /// would render every byte sealed under the old one unreadable, and there is
    /// no undo for that.
    pub fn write_key_file<R: RngCore + CryptoRng>(
        &self,
        path: &Path,
        passphrase: Option<&str>,
        rng: &mut R,
    ) -> Result<(), AtRestError> {
        if path.exists() {
            return Err(AtRestError::Io {
                context: format!("writing {}", path.display()),
                reason: String::from(
                    "a key file is already there; move it aside deliberately, \
                     because anything sealed under it becomes unreadable",
                ),
            });
        }
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| AtRestError::Io {
                    context: format!("creating {}", parent.display()),
                    reason: error.to_string(),
                })?;
            }
        }
        let text = match passphrase {
            None => format!("{KEY_PREFIX}{}\n", hex_encode(self.key.expose())),
            Some(passphrase) => {
                let mut salt = [0u8; SALT_LEN];
                rng.fill_bytes(&mut salt);
                let mut nonce_bytes = [0u8; NONCE_LEN];
                rng.fill_bytes(&mut nonce_bytes);
                let wrapping = derive(passphrase, &salt)?;
                let cipher = ChaCha20Poly1305::new(wrapping.expose().into());
                let sealed = cipher
                    .encrypt(
                        (&nonce_bytes).into(),
                        Payload {
                            msg: self.key.expose(),
                            aad: KEY_AAD,
                        },
                    )
                    .map_err(|_| AtRestError::Kdf(String::from("wrapping the key failed")))?;
                format!(
                    "{WRAPPED_PREFIX}{ARGON_MEMORY_KIB}:{ARGON_PASSES}:{ARGON_LANES}:{}:{}:{}\n",
                    hex_encode(&salt),
                    hex_encode(&nonce_bytes),
                    hex_encode(&sealed)
                )
            }
        };
        write_private(path, text.as_bytes())
    }

    /// Read a key file, supplying the passphrase if it is wrapped.
    pub fn read_key_file(path: &Path, passphrase: Option<&str>) -> Result<Cipher, AtRestError> {
        if !path.exists() {
            return Err(AtRestError::NoKeyFile {
                path: path.to_path_buf(),
            });
        }
        let text = fs::read_to_string(path).map_err(|error| AtRestError::Io {
            context: format!("reading {}", path.display()),
            reason: error.to_string(),
        })?;
        let text = text.trim();

        if let Some(hex) = text.strip_prefix(KEY_PREFIX) {
            let bytes = hex_decode(hex).ok_or_else(|| AtRestError::MalformedKeyFile {
                path: path.to_path_buf(),
                reason: String::from("key is not hexadecimal"),
            })?;
            let bytes: [u8; KEY_LEN] =
                bytes
                    .try_into()
                    .map_err(|_| AtRestError::MalformedKeyFile {
                        path: path.to_path_buf(),
                        reason: format!("key must be {KEY_LEN} bytes"),
                    })?;
            return Ok(Cipher::from_bytes(bytes));
        }

        if let Some(rest) = text.strip_prefix(WRAPPED_PREFIX) {
            let passphrase = passphrase.ok_or_else(|| AtRestError::Passphrase {
                path: path.to_path_buf(),
            })?;
            return unwrap_key_file(path, rest, passphrase);
        }

        Err(AtRestError::MalformedKeyFile {
            path: path.to_path_buf(),
            reason: format!("expected a line starting {KEY_PREFIX:?} or {WRAPPED_PREFIX:?}"),
        })
    }

    /// Whether a key file needs a passphrase, without needing the passphrase.
    ///
    /// The wrapping is visible in the clear on purpose: a caller has to be able
    /// to decide whether to prompt, and making that require a successful decrypt
    /// would mean prompting for a passphrase that may not be wanted.
    pub fn key_file_is_wrapped(path: &Path) -> Result<bool, AtRestError> {
        let text = fs::read_to_string(path).map_err(|error| AtRestError::Io {
            context: format!("reading {}", path.display()),
            reason: error.to_string(),
        })?;
        Ok(text.trim_start().starts_with(WRAPPED_PREFIX))
    }
}

fn unwrap_key_file(path: &Path, rest: &str, passphrase: &str) -> Result<Cipher, AtRestError> {
    let malformed = |reason: &str| AtRestError::MalformedKeyFile {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    };
    let fields: Vec<&str> = rest.split(':').collect();
    let [memory, passes, lanes, salt, nonce, ciphertext] = fields.as_slice() else {
        return Err(malformed(
            "expected memory:passes:lanes:salt:nonce:ciphertext",
        ));
    };
    // The cost parameters come from the file rather than from these constants,
    // so raising the defaults later does not orphan key files written today.
    let memory: u32 = memory.parse().map_err(|_| malformed("bad memory cost"))?;
    let passes: u32 = passes.parse().map_err(|_| malformed("bad pass count"))?;
    let lanes: u32 = lanes.parse().map_err(|_| malformed("bad lane count"))?;
    let salt = hex_decode(salt).ok_or_else(|| malformed("salt is not hexadecimal"))?;
    let nonce_bytes = hex_decode(nonce).ok_or_else(|| malformed("nonce is not hexadecimal"))?;
    let nonce_bytes = <[u8; NONCE_LEN]>::try_from(nonce_bytes)
        .map_err(|_| malformed("nonce is the wrong length"))?;
    let ciphertext =
        hex_decode(ciphertext).ok_or_else(|| malformed("ciphertext is not hexadecimal"))?;

    let wrapping = derive_with(passphrase, &salt, memory, passes, lanes)?;
    let cipher = ChaCha20Poly1305::new(wrapping.expose().into());
    let opened = cipher
        .decrypt(
            (&nonce_bytes).into(),
            Payload {
                msg: &ciphertext,
                aad: KEY_AAD,
            },
        )
        .map_err(|_| AtRestError::Passphrase {
            path: path.to_path_buf(),
        })?;
    let bytes: [u8; KEY_LEN] = opened
        .try_into()
        .map_err(|_| malformed("wrapped key is the wrong length"))?;
    Ok(Cipher::from_bytes(bytes))
}

fn derive(passphrase: &str, salt: &[u8]) -> Result<Secret32, AtRestError> {
    derive_with(
        passphrase,
        salt,
        ARGON_MEMORY_KIB,
        ARGON_PASSES,
        ARGON_LANES,
    )
}

fn derive_with(
    passphrase: &str,
    salt: &[u8],
    memory: u32,
    passes: u32,
    lanes: u32,
) -> Result<Secret32, AtRestError> {
    let params = Params::new(memory, passes, lanes, Some(KEY_LEN))
        .map_err(|error| AtRestError::Kdf(error.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut derived = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), salt, &mut derived)
        .map_err(|error| AtRestError::Kdf(error.to_string()))?;
    Ok(Secret32::new(derived))
}

/// Associated data for line `index`.
fn line_aad(index: u64) -> String {
    format!("{LINE_AAD}{index}")
}

/// Is this line in the sealed format?
pub fn is_sealed_line(line: &str) -> bool {
    line.trim_start().starts_with(LINE_PREFIX)
}

/// Write a file only the owner can read.
///
/// The mode is set *before* the secret is written, not after, so there is no
/// window in which the key exists at the umask's default permissions. On
/// non-unix targets the mode cannot be set and the caller is not told
/// otherwise -- see [`private_permissions_supported`].
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), AtRestError> {
    let io = |context: String, error: std::io::Error| AtRestError::Io {
        context,
        reason: error.to_string(),
    };
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let mut handle = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| io(format!("creating {}", path.display()), error))?;
        handle
            .write_all(bytes)
            .map_err(|error| io(format!("writing {}", path.display()), error))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes).map_err(|error| io(format!("writing {}", path.display()), error))
    }
}

/// Whether this platform can restrict the key file to its owner.
///
/// Reported rather than assumed, so a caller on a platform that cannot do it
/// says so out loud instead of implying a protection that is not there.
pub fn private_permissions_supported() -> bool {
    cfg!(unix)
}

/// True if `path` is readable by anyone other than its owner.
pub fn is_world_readable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match fs::metadata(path) {
            Ok(metadata) => metadata.permissions().mode() & 0o077 != 0,
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        false
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(nibble(byte >> 4));
        out.push(nibble(byte & 0x0f));
    }
    out
}

fn nibble(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'a' + value - 10) as char,
    }
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    // `% 2` rather than `is_multiple_of`, which stabilised after this crate's
    // pinned 1.85 toolchain.
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks(2) {
        let high = value_of(pair[0])?;
        let low = value_of(pair[1])?;
        out.push((high << 4) | low);
    }
    Some(out)
}

fn value_of(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn cipher() -> Cipher {
        Cipher::from_bytes([7u8; KEY_LEN])
    }

    fn scratch(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "proofwork-atrest-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&path).expect("create scratch dir");
        path
    }

    #[test]
    fn a_sealed_line_round_trips() {
        let cipher = cipher();
        let line = cipher
            .seal_line(0, b"{\"seq\":0}", &mut OsRng)
            .expect("seals");
        assert!(is_sealed_line(&line));
        assert!(!line.contains("seq"), "the plaintext must not be visible");
        assert_eq!(
            cipher.open_line(0, &line).expect("opens"),
            b"{\"seq\":0}".to_vec()
        );
    }

    #[test]
    fn the_same_plaintext_seals_differently_every_time() {
        // Random nonces, so an observer cannot tell that two entries are equal
        // -- and, more importantly, so a truncate-and-reappend never reuses one.
        let cipher = cipher();
        let first = cipher.seal_line(3, b"same", &mut OsRng).expect("seals");
        let second = cipher.seal_line(3, b"same", &mut OsRng).expect("seals");
        assert_ne!(first, second);
        assert_eq!(cipher.open_line(3, &first).expect("opens"), b"same");
        assert_eq!(cipher.open_line(3, &second).expect("opens"), b"same");
    }

    #[test]
    fn a_line_moved_to_another_position_does_not_open() {
        // The reason the associated data binds the index. Without it these
        // blobs would be freely reorderable and the hash chain would be the
        // only thing standing in the way.
        let cipher = cipher();
        let line = cipher.seal_line(5, b"payload", &mut OsRng).expect("seals");
        assert_eq!(
            cipher.open_line(6, &line),
            Err(AtRestError::Undecryptable { line: 6 })
        );
        assert_eq!(
            cipher.open_line(4, &line),
            Err(AtRestError::Undecryptable { line: 4 })
        );
        assert!(cipher.open_line(5, &line).is_ok());
    }

    #[test]
    fn the_wrong_key_is_a_failure_and_not_garbage() {
        let line = cipher()
            .seal_line(0, b"payload", &mut OsRng)
            .expect("seals");
        let other = Cipher::from_bytes([8u8; KEY_LEN]);
        assert_eq!(
            other.open_line(0, &line),
            Err(AtRestError::Undecryptable { line: 0 })
        );
    }

    #[test]
    fn a_tampered_byte_is_caught() {
        let cipher = cipher();
        let line = cipher.seal_line(0, b"payload", &mut OsRng).expect("seals");
        let mut bytes: Vec<char> = line.chars().collect();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == 'a' { 'b' } else { 'a' };
        let tampered: String = bytes.into_iter().collect();
        assert_eq!(
            cipher.open_line(0, &tampered),
            Err(AtRestError::Undecryptable { line: 0 })
        );
    }

    #[test]
    fn a_plaintext_line_is_reported_as_plaintext_rather_than_as_corruption() {
        // The diagnostic that matters most in practice: somebody points a key
        // at a log that was never encrypted. "Not encrypted" is actionable;
        // "authentication failed" sends them looking for a lost key.
        let cipher = cipher();
        assert_eq!(
            cipher.open_line(2, "{\"seq\":2}"),
            Err(AtRestError::NotEncrypted { line: 2 })
        );
        assert!(!is_sealed_line("{\"seq\":2}"));
    }

    #[test]
    fn a_truncated_or_non_hex_line_is_refused() {
        let cipher = cipher();
        assert_eq!(
            cipher.open_line(0, "pwenc1:nocolon"),
            Err(AtRestError::Undecryptable { line: 0 })
        );
        assert_eq!(
            cipher.open_line(0, "pwenc1:zz:00"),
            Err(AtRestError::Undecryptable { line: 0 })
        );
        assert_eq!(
            cipher.open_line(0, "pwenc1:00:00"),
            Err(AtRestError::Undecryptable { line: 0 }),
            "a short nonce is refused before it reaches the cipher"
        );
    }

    #[test]
    fn a_bare_key_file_round_trips_and_is_owner_only() {
        let dir = scratch("bare");
        let path = dir.join("key");
        let cipher = Cipher::generate(&mut OsRng);
        cipher
            .write_key_file(&path, None, &mut OsRng)
            .expect("writes");
        if private_permissions_supported() {
            assert!(!is_world_readable(&path), "key file must be owner-only");
        }
        assert!(!Cipher::key_file_is_wrapped(&path).expect("reads"));
        let reopened = Cipher::read_key_file(&path, None).expect("reads");
        let line = cipher.seal_line(0, b"x", &mut OsRng).expect("seals");
        assert_eq!(reopened.open_line(0, &line).expect("opens"), b"x");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wrapped_key_file_needs_its_passphrase() {
        let dir = scratch("wrapped");
        let path = dir.join("key");
        let cipher = Cipher::generate(&mut OsRng);
        cipher
            .write_key_file(&path, Some("correct horse"), &mut OsRng)
            .expect("writes");
        assert!(Cipher::key_file_is_wrapped(&path).expect("reads"));

        assert_eq!(
            Cipher::read_key_file(&path, None).expect_err("needs a passphrase"),
            AtRestError::Passphrase { path: path.clone() }
        );
        assert_eq!(
            Cipher::read_key_file(&path, Some("wrong")).expect_err("wrong passphrase"),
            AtRestError::Passphrase { path: path.clone() },
            "a wrong passphrase and a missing one are the same error"
        );

        let opened = Cipher::read_key_file(&path, Some("correct horse")).expect("reads");
        let line = cipher.seal_line(1, b"y", &mut OsRng).expect("seals");
        assert_eq!(opened.open_line(1, &line).expect("opens"), b"y");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_wrapped_key_file_never_contains_the_key() {
        let dir = scratch("opaque");
        let path = dir.join("key");
        let cipher = Cipher::from_bytes([0xab; KEY_LEN]);
        cipher
            .write_key_file(&path, Some("passphrase"), &mut OsRng)
            .expect("writes");
        let text = fs::read_to_string(&path).expect("reads");
        assert!(
            !text.contains(&"ab".repeat(KEY_LEN)),
            "the wrapped file leaked the key"
        );
        assert!(!text.contains("passphrase"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_cost_parameters_travel_with_the_file() {
        // So raising the defaults later does not orphan key files written now.
        let dir = scratch("params");
        let path = dir.join("key");
        Cipher::generate(&mut OsRng)
            .write_key_file(&path, Some("p"), &mut OsRng)
            .expect("writes");
        let text = fs::read_to_string(&path).expect("reads");
        assert!(text.starts_with(&format!(
            "{WRAPPED_PREFIX}{ARGON_MEMORY_KIB}:{ARGON_PASSES}:{ARGON_LANES}:"
        )));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn writing_a_key_file_never_overwrites_one() {
        // There is no undo for this. Everything sealed under the old key
        // becomes unreadable the instant it is replaced.
        let dir = scratch("nooverwrite");
        let path = dir.join("key");
        Cipher::generate(&mut OsRng)
            .write_key_file(&path, None, &mut OsRng)
            .expect("writes");
        let before = fs::read_to_string(&path).expect("reads");
        let error = Cipher::generate(&mut OsRng)
            .write_key_file(&path, None, &mut OsRng)
            .expect_err("refuses to clobber");
        assert!(matches!(error, AtRestError::Io { .. }));
        assert_eq!(fs::read_to_string(&path).expect("reads"), before);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_or_junk_key_file_is_named_precisely() {
        let dir = scratch("junk");
        let missing = dir.join("absent");
        assert_eq!(
            Cipher::read_key_file(&missing, None).expect_err("no file"),
            AtRestError::NoKeyFile {
                path: missing.clone()
            }
        );
        let junk = dir.join("junk");
        fs::write(&junk, "hello\n").expect("writes");
        assert!(matches!(
            Cipher::read_key_file(&junk, None).expect_err("not a key file"),
            AtRestError::MalformedKeyFile { .. }
        ));
        let short = dir.join("short");
        fs::write(&short, format!("{KEY_PREFIX}00\n")).expect("writes");
        assert!(matches!(
            Cipher::read_key_file(&short, None).expect_err("wrong length"),
            AtRestError::MalformedKeyFile { .. }
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_cipher_does_not_print_its_key() {
        let cipher = Cipher::from_bytes([0xcd; KEY_LEN]);
        let shown = format!("{cipher:?}");
        assert_eq!(shown, "Cipher(<redacted>)");
        assert!(!shown.contains("cd"));
    }

    #[test]
    fn hex_round_trips_and_rejects_junk() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x10]), "00ff10");
        assert_eq!(hex_decode("00ff10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(hex_decode("00FF10"), Some(vec![0x00, 0xff, 0x10]));
        assert_eq!(hex_decode("abc"), None, "odd length");
        assert_eq!(hex_decode("zz"), None);
        assert_eq!(hex_decode(""), Some(Vec::new()));
    }
}
