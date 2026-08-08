//! Content-addressed storage for pinned verifier code.
//!
//! # The problem this exists to fix
//!
//! An objective pins its checker by SHA-256 and *references* it by a filesystem
//! path relative to the bundle root. The hash makes substitution impossible;
//! the path makes availability somebody else's problem. A peer that receives an
//! objective over [`crate::p2p::sync`] but has never seen the bundle cannot run
//! the checker, so it answers `Unavailable` forever and cannot derive
//! settlement at all — which means the headline guarantee, *anyone can
//! independently re-derive every settled result from the log alone*, was true
//! only for whoever also had the operator's working directory.
//!
//! # The pin is already the content address
//!
//! So there is no second identity scheme here, and deliberately no new record
//! field. A blob's name **is** the hex SHA-256 the objective already declares in
//! `checker_sha256` / `evaluator_sha256` / `statistic.sha256`. Adding a locator
//! field to `Objective` was considered and rejected twice over: inside the
//! digest, a dead URL would fork the objective and orphan every claim against
//! it; outside the digest, it would be unpinned attacker-controlled text that
//! every verifying node fetches, which is an SSRF surface and a way for an
//! objective author to fingerprint everyone who checks their work. *Where* the
//! bytes come from is a network question, not a record field.
//!
//! # Rules
//!
//! **Verify before write.** [`BlobStore::put`] hashes the bytes in memory and
//! refuses a mismatch before anything reaches the filesystem, so the store
//! never contains a file that could be executed under a name it does not hash
//! to. The write is to a temporary name followed by a rename, so a crash
//! mid-write cannot leave a short file visible under a real address either.
//!
//! **A ceiling, checked before allocating.** [`MAX_BLOB_BYTES`] bounds a blob
//! everywhere it can arrive — from a peer, from a bundle file, out of the store
//! — and the check is against a *declared* length wherever one exists. Refusing
//! after allocating is not a defence against a peer whose plan is to make you
//! allocate.
//!
//! **An address is 64 lowercase hex characters, or it is not an address.**
//! [`is_address`] is load-bearing rather than cosmetic: the address is used as
//! a filename, and it arrives from an objective written by a stranger. Without
//! the check, `"sha256": "../../../../etc/passwd"` reaches
//! [`std::path::Path::join`].
//!
//! **Nothing here is executable.** Blobs are source files read by an
//! interpreter that is itself spawned inside the jail in
//! [`crate::verifiers::sandbox`]. The file mode carries no execute bit, and the
//! store directory is not on anybody's `PATH`.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::hex;
use sha2::{Digest as _, Sha256};

/// Where a store lives under a bundle root.
///
/// Beside the pinned code rather than beside the log, because the root is what
/// a pinned path is resolved against and a node may audit several logs against
/// one bundle.
pub const STORE_DIR: &str = ".proofwork/blobs";

/// Largest blob this implementation will store, serve, or accept.
///
/// A pinned checker is a source file. The shipped examples are two to six
/// kilobytes, so a mebibyte is three orders of magnitude of headroom for an
/// honest objective and a hard stop for a peer that has decided to send a
/// gigabyte. It is deliberately not configurable: a node that raised it would
/// accept blobs its peers refuse, and the resulting asymmetry is invisible
/// until an objective becomes unverifiable on half the network.
pub const MAX_BLOB_BYTES: usize = 1 << 20;

/// The content address of some bytes, in the spelling an objective's verifier
/// block already uses: bare lowercase hex, **no** `sha256:` prefix.
///
/// The prefixed spelling is [`crate::canonical`]'s, for record ids. Pins
/// predate this module and are bare, so this function has to match them; two
/// spellings for one hash would be two names for one blob and half the network
/// would fail to find the other half's copy.
pub fn address(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(&hasher.finalize())
}

/// Whether `text` is a well-formed content address.
///
/// Exactly 64 characters, each `0-9a-f`. Uppercase is refused rather than
/// folded: two spellings of one address would be two files, and the objective
/// that declared the uppercase form would be unverifiable on a node that had
/// stored the lowercase one.
pub fn is_address(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Why a blob operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobError {
    /// The address is not 64 lowercase hex characters. Refused before it is
    /// allowed anywhere near a path join.
    NotAnAddress { address: String },
    /// Over [`MAX_BLOB_BYTES`], or over a caller-supplied ceiling.
    TooLarge { limit: usize, got: usize },
    /// Bytes offered under an address they do not hash to. Never written.
    Mismatch { declared: String, actual: String },
    /// The store has no copy. Distinct from every other variant because it is
    /// the one that must become `Unavailable` rather than a refusal: a blob
    /// this node does not have says nothing about anybody's artifact.
    Absent { address: String },
    /// Filesystem trouble, as text — `io::Error` is neither `Clone` nor `Eq`,
    /// and no caller does anything with the kind that it would not do with the
    /// message.
    Io { detail: String },
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlobError::NotAnAddress { address } => write!(
                f,
                "{address:?} is not a content address (64 lowercase hex characters)"
            ),
            BlobError::TooLarge { limit, got } => {
                write!(f, "verifier code is {got} bytes, limit is {limit}")
            }
            BlobError::Mismatch { declared, actual } => write!(
                f,
                "verifier code hashes to {actual}, offered under {declared}"
            ),
            BlobError::Absent { address } => {
                write!(f, "no local copy of verifier code {address}")
            }
            BlobError::Io { detail } => write!(f, "blob store: {detail}"),
        }
    }
}

impl std::error::Error for BlobError {}

fn io_error(error: io::Error) -> BlobError {
    BlobError::Io {
        detail: error.to_string(),
    }
}

/// A directory of blobs, each filed under its own content address.
///
/// Flat rather than sharded by hash prefix. Sharding exists to keep directory
/// sizes down when there are millions of objects; a node holds one blob per
/// distinct pinned checker across every objective it has heard of, which is a
/// few hundred at Stage 0 scale, and a two-level tree would buy nothing but a
/// second place for the path arithmetic to go wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobStore {
    dir: PathBuf,
}

impl BlobStore {
    /// The store belonging to a bundle root.
    pub fn under(root: impl AsRef<Path>) -> BlobStore {
        BlobStore {
            dir: root.as_ref().join(STORE_DIR),
        }
    }

    /// A store at an explicit directory, for a node that keeps its cache
    /// somewhere other than inside the bundle it verifies against.
    pub fn at(dir: impl Into<PathBuf>) -> BlobStore {
        BlobStore { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Where a blob would live. `Err` for anything that is not an address, so
    /// no caller can turn a hostile pin into a path outside the store.
    pub fn path_of(&self, address: &str) -> Result<PathBuf, BlobError> {
        if !is_address(address) {
            return Err(BlobError::NotAnAddress {
                address: address.to_string(),
            });
        }
        Ok(self.dir.join(address))
    }

    /// Whether a copy is on disk. Existence only — cheap enough to call once
    /// per pin per sync round, which is what the wire protocol does.
    ///
    /// A file whose contents have rotted is reported as held here and caught by
    /// [`BlobStore::read`], which is the only place the bytes are actually used.
    pub fn holds(&self, address: &str) -> bool {
        match self.path_of(address) {
            Ok(path) => path.is_file(),
            Err(_) => false,
        }
    }

    /// Read a blob, verifying it against its own filename.
    ///
    /// The verification is not paranoia about our own writes: the store is an
    /// ordinary directory an operator can edit, a backup can restore badly, and
    /// a disk can corrupt. A file whose name is the hash of its contents and
    /// whose contents disagree is not a blob, so it is deleted rather than
    /// returned — otherwise it would shadow the real blob forever, since
    /// [`BlobStore::holds`] would go on reporting the address as held and the
    /// fetch that would replace it would never be attempted.
    pub fn read(&self, wanted: &str) -> Result<Vec<u8>, BlobError> {
        let path = self.path_of(wanted)?;
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(BlobError::Absent {
                    address: wanted.to_string(),
                })
            }
            Err(error) => return Err(io_error(error)),
        };
        // The declared length, before the allocation. A store entry is
        // untrusted input for the same reason a wire frame is.
        if metadata.len() > MAX_BLOB_BYTES as u64 {
            return Err(BlobError::TooLarge {
                limit: MAX_BLOB_BYTES,
                got: usize::try_from(metadata.len()).unwrap_or(usize::MAX),
            });
        }
        let bytes = fs::read(&path).map_err(io_error)?;
        let actual = address(&bytes);
        if actual != wanted {
            let _ = fs::remove_file(&path);
            return Err(BlobError::Mismatch {
                declared: wanted.to_string(),
                actual,
            });
        }
        Ok(bytes)
    }

    /// Store `bytes` under `declared`, **verifying first**.
    ///
    /// Every path into the store goes through here, which is what makes "a
    /// received blob is checked against the pin before it is written anywhere it
    /// could be run" a property of the type rather than of each call site. The
    /// order is: shape of the address, then the ceiling, then the hash, then the
    /// filesystem. Nothing hostile reaches disk.
    pub fn put(&self, declared: &str, bytes: &[u8]) -> Result<PathBuf, BlobError> {
        let path = self.path_of(declared)?;
        if bytes.len() > MAX_BLOB_BYTES {
            return Err(BlobError::TooLarge {
                limit: MAX_BLOB_BYTES,
                got: bytes.len(),
            });
        }
        let actual = address(bytes);
        if actual != declared {
            return Err(BlobError::Mismatch {
                declared: declared.to_string(),
                actual,
            });
        }
        if path.is_file() {
            return Ok(path);
        }
        create_dir(&self.dir)?;
        // Written under a temporary name and renamed, so a crash cannot leave a
        // truncated file visible under an address it does not hash to. The
        // temporary name carries the pid so two processes sharing a root do not
        // rename each other's partial writes into place.
        let staging = self
            .dir
            .join(format!(".{declared}.{}.partial", std::process::id()));
        write_private(&staging, bytes)?;
        match fs::rename(&staging, &path) {
            Ok(()) => Ok(path),
            Err(error) => {
                let _ = fs::remove_file(&staging);
                Err(io_error(error))
            }
        }
    }

    /// Publish a bundle file whose hash the objective declares.
    ///
    /// How code enters the network: the funder has the file on disk, and this
    /// makes their node able to serve it. `Ok(false)` means the file is absent
    /// or does not match the pin — not an error, because a node replaying
    /// somebody else's objectives has neither the bundle nor any obligation to.
    pub fn publish_file(&self, path: &Path, declared: &str) -> Result<bool, BlobError> {
        if !is_address(declared) {
            return Err(BlobError::NotAnAddress {
                address: declared.to_string(),
            });
        }
        let metadata = match fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(_) => return Ok(false),
        };
        if !metadata.is_file() || metadata.len() > MAX_BLOB_BYTES as u64 {
            return Ok(false);
        }
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(false),
        };
        if address(&bytes) != declared {
            return Ok(false);
        }
        self.put(declared, &bytes).map(|_| true)
    }

    /// Every address held, sorted. An empty or absent directory is empty, not
    /// an error: a node that has never fetched anything is a normal node.
    pub fn addresses(&self) -> Vec<String> {
        let mut out = Vec::new();
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return out;
        };
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if is_address(name) {
                    out.push(name.to_string());
                }
            }
        }
        out.sort();
        out
    }

    pub fn len(&self) -> usize {
        self.addresses().len()
    }

    pub fn is_empty(&self) -> bool {
        self.addresses().is_empty()
    }

    /// Drop every blob outside `keep`, returning how many went.
    ///
    /// Collection is explicit — a command an operator runs, never something a
    /// sync round does on its way past. A node cannot tell a blob nobody wants
    /// from a blob pinned by an objective it has not synced yet, and dropping
    /// the second kind on a timer would make a node stop being able to serve
    /// precisely the code its peers are about to ask it for. The caller decides
    /// what "reachable" means; [`crate::node::Node::pinned_code`] is the
    /// answer for a node holding a log.
    pub fn retain(&self, keep: &BTreeSet<String>) -> usize {
        let mut dropped = 0;
        for held in self.addresses() {
            if keep.contains(&held) {
                continue;
            }
            if let Ok(path) = self.path_of(&held) {
                if fs::remove_file(path).is_ok() {
                    dropped += 1;
                }
            }
        }
        dropped
    }
}

#[cfg(unix)]
fn create_dir(dir: &Path) -> Result<(), BlobError> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.is_dir() {
        return Ok(());
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(io_error)
}

#[cfg(not(unix))]
fn create_dir(dir: &Path) -> Result<(), BlobError> {
    if dir.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(dir).map_err(io_error)
}

/// Write with no execute bit and no group or world access.
///
/// The mode is the point. This file holds code a stranger sent; the only thing
/// that should ever open it is the interpreter the verifier spawns inside the
/// jail, and nothing should be able to `exec` it directly.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), BlobError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), BlobError> {
    fs::write(path, bytes).map_err(io_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory under `target/`, so a failed run leaves evidence.
    fn scratch(name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("blob-tests")
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    const CODE: &[u8] = b"def check(artifact):\n    return True\n";

    #[test]
    fn an_address_is_the_bare_hex_a_verifier_block_already_declares() {
        // Not the `sha256:` spelling records use. Two spellings for one hash
        // would be two names for one blob, and each half of the network would
        // fail to find the other half's copy.
        let a = address(CODE);
        assert_eq!(a.len(), 64);
        assert!(!a.starts_with("sha256:"));
        assert!(is_address(&a));
        assert_eq!(
            address(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn only_64_lowercase_hex_characters_are_an_address() {
        // Load-bearing: the address becomes a filename and arrives from an
        // objective a stranger wrote.
        assert!(is_address(&"ab".repeat(32)));
        for bad in [
            "",
            "ab",
            &"AB".repeat(32),
            &"ab".repeat(31),
            &"ab".repeat(33),
            "../../../../etc/passwd",
            &format!("sha256:{}", "ab".repeat(32)),
            &"g".repeat(64),
        ] {
            assert!(!is_address(bad), "{bad:?} was accepted as an address");
        }
    }

    #[test]
    fn a_hostile_pin_never_reaches_a_path_join() {
        // The whole reason `is_address` exists. Without it this store would
        // happily read and write anywhere the process can.
        let store = BlobStore::at(scratch("hostile"));
        for bad in ["../../../../etc/passwd", "..", "/etc/passwd", ""] {
            assert!(matches!(
                store.path_of(bad),
                Err(BlobError::NotAnAddress { .. })
            ));
            assert!(!store.holds(bad));
            assert!(matches!(
                store.read(bad),
                Err(BlobError::NotAnAddress { .. })
            ));
            assert!(matches!(
                store.put(bad, CODE),
                Err(BlobError::NotAnAddress { .. })
            ));
        }
    }

    #[test]
    fn a_blob_round_trips_under_its_own_address() {
        let store = BlobStore::at(scratch("round-trip"));
        assert!(store.is_empty());
        let a = address(CODE);
        store.put(&a, CODE).expect("put");
        assert!(store.holds(&a));
        assert_eq!(store.read(&a).expect("read"), CODE);
        assert_eq!(store.addresses(), vec![a.clone()]);
        assert_eq!(store.len(), 1);
        // Idempotent: storing the same bytes twice is one blob.
        store.put(&a, CODE).expect("re-put");
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn a_mismatch_is_refused_before_anything_reaches_the_filesystem() {
        // "Verify before execute" starts here: code that does not hash to the
        // pin never acquires a filename under which it could be run.
        let dir = scratch("mismatch");
        let store = BlobStore::at(dir.clone());
        let wrong = address(b"something else entirely");
        assert!(matches!(
            store.put(&wrong, CODE),
            Err(BlobError::Mismatch { .. })
        ));
        assert!(store.is_empty());
        assert!(
            fs::read_dir(&dir).expect("dir").next().is_none(),
            "a refused blob left a file behind"
        );
    }

    #[test]
    fn an_oversized_blob_is_refused_against_the_declared_length() {
        let store = BlobStore::at(scratch("oversized"));
        let huge = vec![b'x'; MAX_BLOB_BYTES + 1];
        let a = address(&huge);
        assert!(matches!(
            store.put(&a, &huge),
            Err(BlobError::TooLarge {
                limit: MAX_BLOB_BYTES,
                ..
            })
        ));
        assert!(store.is_empty());
    }

    #[test]
    fn an_absent_blob_is_absent_and_not_an_io_error() {
        // The caller turns exactly this variant into `Unavailable`. Folding it
        // into `Io` would make "I do not have the code" indistinguishable from
        // "the disk is broken", and one of those is a fact about the artifact's
        // verifiability that a peer can fix by sending it.
        let store = BlobStore::at(scratch("absent"));
        let a = address(CODE);
        assert!(matches!(store.read(&a), Err(BlobError::Absent { .. })));
    }

    #[test]
    fn a_rotted_entry_is_deleted_rather_than_served() {
        // Otherwise it shadows the real blob forever: `holds` reports the
        // address as held, so the fetch that would replace it never happens.
        let dir = scratch("rotted");
        let store = BlobStore::at(dir.clone());
        let a = address(CODE);
        store.put(&a, CODE).expect("put");
        fs::write(dir.join(&a), b"tampered").expect("tamper");
        assert!(matches!(store.read(&a), Err(BlobError::Mismatch { .. })));
        assert!(!store.holds(&a), "the rotted entry survived a read");
    }

    #[test]
    fn publishing_a_bundle_file_that_does_not_match_is_a_no_op_not_an_error() {
        // A node replaying somebody else's objectives has neither the bundle
        // nor any obligation to; refusing the post over it would make record
        // sync stop importing objectives.
        let dir = scratch("publish");
        let store = BlobStore::at(dir.join("store"));
        let bundle = dir.join("checker.py");
        fs::write(&bundle, CODE).expect("write bundle");

        let a = address(CODE);
        assert!(store.publish_file(&bundle, &a).expect("publish"));
        assert!(store.holds(&a));

        let other = address(b"different");
        assert!(!store.publish_file(&bundle, &other).expect("publish"));
        assert!(!store
            .publish_file(&dir.join("nope.py"), &a)
            .expect("absent"));
        assert!(matches!(
            store.publish_file(&bundle, "not-an-address"),
            Err(BlobError::NotAnAddress { .. })
        ));
    }

    #[test]
    fn collection_keeps_what_is_still_pinned_and_drops_the_rest() {
        let store = BlobStore::at(scratch("gc"));
        let keep = address(CODE);
        let drop = address(b"stale");
        store.put(&keep, CODE).expect("put");
        store.put(&drop, b"stale").expect("put");
        assert_eq!(store.len(), 2);

        let pinned: BTreeSet<String> = [keep.clone()].into_iter().collect();
        assert_eq!(store.retain(&pinned), 1);
        assert_eq!(store.addresses(), vec![keep]);
    }

    #[test]
    fn a_directory_full_of_junk_lists_no_addresses() {
        // The store is an ordinary directory. Anything whose name is not an
        // address is not a blob, whatever it contains.
        let dir = scratch("junk");
        let store = BlobStore::at(dir.clone());
        fs::create_dir_all(&dir).expect("dir");
        fs::write(dir.join("README"), b"hello").expect("write");
        fs::write(dir.join(".hidden.partial"), b"x").expect("write");
        assert!(store.addresses().is_empty());
    }
}
