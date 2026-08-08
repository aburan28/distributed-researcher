//! A confidential corpus: material the network stores and serves without being
//! able to read it.
//!
//! # What "the node cannot read it" actually means
//!
//! [`crate::store::atrest`] encrypts a node's own store, and is explicit that it
//! does not defend against live access to a running node -- the key has to be
//! readable for the node to work. That is the right property for a node's *own*
//! log and the wrong foundation for this, so none of it is reused here.
//!
//! The property this module provides is stronger and simpler: **a serving node
//! is never given a key at all.** A document is sealed by whoever contributes
//! it, addressed by the hash of its *ciphertext*, and served as opaque bytes. A
//! node holds it, proves it holds it, and hands it to whoever asks, having no
//! more idea what it is than a courier has of a sealed envelope.
//!
//! Three claims get conflated under "nodes must never view the material", and
//! only two of them are things cryptography can deliver:
//!
//! | claim | status |
//! |---|---|
//! | a serving node holds bytes it cannot read | **held.** It never receives a key |
//! | no single node can decrypt unilaterally | **held.** The key is split `threshold`-of-`n` ([`crate::crypto::envelope`]) |
//! | no operator can *ever* read the material | **not held, and not holdable.** Anyone who may read it may also run a node |
//!
//! The third is access control, not encryption, and pretending otherwise is the
//! oversold-confidentiality failure `crate::crypto` opens by warning about.
//!
//! # Release is policy, not cryptography
//!
//! [`Document::open`] refuses before the release epoch. That refusal binds
//! whoever calls this code and nobody else: `threshold` colluding committee
//! members can combine their shares whenever they like, and no check in this
//! file is in their way. The epoch is what an *honest* committee waits for.
//!
//! This is worth stating plainly because the alternative reading -- that the
//! release epoch is enforced -- would make the committee threshold look like a
//! convenience rather than the entire security argument. What actually holds
//! the line is the cost of collusion among `threshold` members, which
//! `proofwork incentives` reports on and `docs/threat-model.md` should carry a
//! row for.
//!
//! A time-lock puzzle (Rivest–Shamir–Wagner) would make early opening cost
//! sequential work rather than cost agreement, and would remove the committee's
//! liveness from the release path entirely. It is deliberately not here:
//! composing it as a second recovery path for the same key means confidentiality
//! becomes the *weaker* of the two branches, which is a real design decision and
//! not a free improvement.
//!
//! # Why the plaintext digest travels inside the seal
//!
//! The sealed payload is `sha256(content) ‖ content`, and the digest is
//! therefore confidential until release.
//!
//! Publishing it alongside the ciphertext would have been convenient and is a
//! confirmation-of-file attack: an adversary holding a candidate document could
//! test membership by hashing it, which for an embargoed preprint or a
//! restricted dataset is most of what they wanted to know. Content addressing
//! the *ciphertext* rather than the plaintext is the same decision -- it costs
//! deduplication across two independent contributions of one document, and
//! convergent encryption would buy that back at exactly the price just refused.
//!
//! After release the digest is what makes a citation checkable: a claim can name
//! `sha256(content)`, and once the committee has published, anyone can confirm
//! the document they fetched is the one that was cited.
//!
//! # What this does not change
//!
//! Availability sampling. [`Document::availability_root`] is a Merkle root over
//! ciphertext chunks, so a node proves possession without comprehension and the
//! existing challenge in [`crate::incentive`] needs no modification.
//!
//! There is a pleasant consequence. The verification game is hard because
//! canaries must be indistinguishable from real work; for storage they are
//! indistinguishable *by construction*, since a node cannot tell a canary
//! document from a real one when it can read neither.

use core::fmt;

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::canonical::{digest_bytes, merkle_root, CanonicalError, Value};
use crate::crypto::envelope::{CommitteeMember, EnvelopeError, SealedEnvelope};
use crate::crypto::shamir::Share;

/// Bytes of `sha256(content)` carried at the front of the sealed payload.
const DIGEST_LEN: usize = 32;

/// Chunk size for the availability Merkle tree.
///
/// A sampler asks for one chunk, so this is the unit of proof and the unit of
/// wasted transfer when a node is challenged. 64 KiB keeps a challenge cheap on
/// a slow link while keeping the tree shallow enough that a proof for a large
/// document is tens of hashes rather than thousands.
pub const CHUNK_LEN: usize = 64 * 1024;

/// The context string bound into the AEAD and every share's key derivation.
///
/// Carries the release epoch so a share cannot be lifted onto a document with an
/// earlier release: a committee member who published for epoch 100 has not
/// thereby opened a document that was meant to wait for epoch 200.
fn aad_for(release_epoch: u64) -> String {
    format!("proofwork-corpus-v1:release={release_epoch}")
}

/// Why a document could not be sealed, opened, or decoded.
#[derive(Debug)]
pub enum CorpusError {
    /// The committee could not seal or open this payload.
    Envelope(EnvelopeError),
    /// A stored document is not a well-formed record.
    Malformed { reason: String },
    /// A stored document is JSON this format cannot represent.
    Canonical(CanonicalError),
    /// [`Document::open`] was called before the release epoch.
    ///
    /// A refusal by this code, and not a fact about the world: see the module
    /// docs on why `threshold` colluding members are unaffected by it.
    NotYetReleased { release_epoch: u64, now: u64 },
    /// The payload opened but was shorter than its own digest header, so it was
    /// not produced by [`Document::seal`].
    TruncatedPayload { len: usize },
    /// The opened content does not hash to the digest sealed alongside it.
    ///
    /// The AEAD already refuses a tampered ciphertext, so reaching this means
    /// the *sealer* was inconsistent rather than that an attacker got here --
    /// which is why it is worth its own error instead of a generic decrypt
    /// failure an operator would go hunting for a network attack over.
    DigestMismatch { sealed: String, found: String },
}

impl fmt::Display for CorpusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CorpusError::Envelope(e) => write!(f, "{e}"),
            CorpusError::Malformed { reason } => write!(f, "corpus document: {reason}"),
            CorpusError::Canonical(e) => write!(f, "corpus document: {e}"),
            CorpusError::NotYetReleased { release_epoch, now } => write!(
                f,
                "this document releases in epoch {release_epoch} and it is epoch {now}. \
                 The committee has not published its shares; nothing here can open it \
                 earlier, and {release_epoch} is what an honest committee waits for"
            ),
            CorpusError::TruncatedPayload { len } => write!(
                f,
                "the sealed payload is {len} bytes, shorter than the {DIGEST_LEN}-byte \
                 digest header every document carries; this was not sealed by this version"
            ),
            CorpusError::DigestMismatch { sealed, found } => write!(
                f,
                "the content opened cleanly but hashes to {found}, not the {sealed} sealed \
                 with it -- the document was sealed inconsistently rather than tampered with, \
                 because a tampered ciphertext fails the AEAD before reaching here"
            ),
        }
    }
}

impl std::error::Error for CorpusError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CorpusError::Envelope(e) => Some(e),
            CorpusError::Canonical(e) => Some(e),
            _ => None,
        }
    }
}

impl From<EnvelopeError> for CorpusError {
    fn from(e: EnvelopeError) -> CorpusError {
        CorpusError::Envelope(e)
    }
}

impl From<CanonicalError> for CorpusError {
    fn from(e: CanonicalError) -> CorpusError {
        CorpusError::Canonical(e)
    }
}

/// One document in the confidential corpus.
///
/// Every field is public ciphertext or public metadata. `Debug` and `Clone` are
/// derived because there is nothing here to leak -- the content key was wiped
/// inside [`SealedEnvelope::seal`] and the plaintext digest is sealed away with
/// the content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    envelope: SealedEnvelope,
    release_epoch: u64,
}

impl Document {
    /// Seal `content` to `committee`, openable by any `threshold` of them from
    /// `release_epoch` onward.
    ///
    /// The content key is generated inside the envelope and wiped there. This
    /// constructor deliberately offers no way to keep it: a corpus document has
    /// no equivalent of the stalled-committee fallback in
    /// [`crate::sealed`], because there is no submitter waiting on a payout who
    /// might need to open their own submission. Retaining the key would only
    /// create something to seize.
    pub fn seal<R: RngCore + CryptoRng>(
        content: &[u8],
        release_epoch: u64,
        committee: &[CommitteeMember],
        threshold: u8,
        rng: &mut R,
    ) -> Result<Document, CorpusError> {
        // `Zeroizing` because this is the plaintext, assembled in full. The
        // caller's copy is theirs to manage; this one is ours.
        let mut payload = Zeroizing::new(Vec::with_capacity(DIGEST_LEN + content.len()));
        payload.extend_from_slice(&digest_raw(content));
        payload.extend_from_slice(content);

        let envelope =
            SealedEnvelope::seal(&payload, &aad_for(release_epoch), committee, threshold, rng)?;
        Ok(Document {
            envelope,
            release_epoch,
        })
    }

    /// The address a node stores and serves this under: `sha256` of the
    /// ciphertext.
    ///
    /// Deliberately not the plaintext's hash. A node that can name what it holds
    /// can be asked to stop holding it, and an address derived from the content
    /// would let anyone with a candidate file confirm the corpus has it -- see
    /// the module docs on confirmation-of-file.
    pub fn blind_address(&self) -> String {
        crate::blobs::address(self.envelope.ciphertext())
    }

    /// The epoch from which an honest committee will publish its shares.
    pub fn release_epoch(&self) -> u64 {
        self.release_epoch
    }

    /// The sealed bytes a node actually stores.
    pub fn ciphertext(&self) -> &[u8] {
        self.envelope.ciphertext()
    }

    /// The envelope, for a committee member that needs to open its own share.
    pub fn envelope(&self) -> &SealedEnvelope {
        &self.envelope
    }

    /// Merkle root over `CHUNK_LEN` chunks of the ciphertext, for availability
    /// sampling.
    ///
    /// Over ciphertext, so a challenge proves a node holds the bytes and proves
    /// nothing about what they say. Returns `None` only for an empty ciphertext,
    /// which [`SealedEnvelope`] does not produce -- an AEAD tag is always there.
    pub fn availability_root(&self) -> Option<String> {
        let leaves: Vec<String> = self
            .envelope
            .ciphertext()
            .chunks(CHUNK_LEN)
            .map(digest_bytes)
            .collect();
        merkle_root(&leaves)
    }

    /// Open the document with `shares`, refusing before `release_epoch`.
    ///
    /// `now` is the caller's epoch, and the refusal is exactly as trustworthy as
    /// the caller -- see the module docs. Pass the epoch derived from a record,
    /// never one read from a clock, for the reason `AGENTS.md` gives.
    pub fn open(&self, shares: &[Share], now: u64) -> Result<Vec<u8>, CorpusError> {
        if now < self.release_epoch {
            return Err(CorpusError::NotYetReleased {
                release_epoch: self.release_epoch,
                now,
            });
        }
        self.open_regardless(shares)
    }

    /// [`Document::open`] without the epoch check.
    ///
    /// Exists so that the check is visibly a *policy* in one place rather than
    /// something smeared through the decryption path, and so a committee auditing
    /// its own behaviour can demonstrate what early opening would produce. It is
    /// not a privilege escalation: anyone holding `threshold` shares can already
    /// do this, with or without this function.
    pub fn open_regardless(&self, shares: &[Share]) -> Result<Vec<u8>, CorpusError> {
        let payload = Zeroizing::new(self.envelope.open_with_shares(shares)?);
        if payload.len() < DIGEST_LEN {
            return Err(CorpusError::TruncatedPayload { len: payload.len() });
        }
        let (header, content) = payload.split_at(DIGEST_LEN);
        let found = digest_bytes(content);
        let sealed = format!("sha256:{}", hex_of(header));
        if found != sealed {
            return Err(CorpusError::DigestMismatch { sealed, found });
        }
        Ok(content.to_vec())
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("kind", Value::string("corpus-document")),
            ("release_epoch", Value::Int(i128::from(self.release_epoch))),
            ("envelope", self.envelope.to_value()),
        ])
    }

    pub fn from_value(value: &Value) -> Result<Document, CorpusError> {
        let object = value.as_object().ok_or(CorpusError::Malformed {
            reason: "not an object".into(),
        })?;
        let _ = object;
        let release_epoch = match value.get("release_epoch") {
            Some(Value::Int(n)) if *n >= 0 => {
                u64::try_from(*n).map_err(|_| CorpusError::Malformed {
                    reason: format!("release_epoch {n} does not fit in u64"),
                })?
            }
            Some(_) => {
                return Err(CorpusError::Malformed {
                    reason: "release_epoch must be a non-negative integer".into(),
                })
            }
            None => {
                return Err(CorpusError::Malformed {
                    reason: "release_epoch missing".into(),
                })
            }
        };
        let envelope = value.get("envelope").ok_or(CorpusError::Malformed {
            reason: "envelope missing".into(),
        })?;
        Ok(Document {
            envelope: SealedEnvelope::from_value(envelope)?,
            release_epoch,
        })
    }
}

/// `sha256(bytes)` as raw bytes, for the sealed header.
fn digest_raw(bytes: &[u8]) -> [u8; DIGEST_LEN] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::envelope::CommitteeKey;
    use rand_core::OsRng;

    /// A committee of `n`, and the keys to open their shares with.
    fn committee(n: u8) -> (Vec<CommitteeMember>, Vec<CommitteeKey>) {
        let mut members = Vec::new();
        let mut keys = Vec::new();
        for index in 1..=n {
            let key = CommitteeKey::generate(&mut OsRng);
            members.push(CommitteeMember {
                index,
                public_key: key.public(),
            });
            keys.push(key);
        }
        (members, keys)
    }

    fn shares_from(
        document: &Document,
        keys: &[CommitteeKey],
        members: &[CommitteeMember],
        take: usize,
    ) -> Vec<Share> {
        keys.iter()
            .zip(members)
            .take(take)
            .map(|(key, member)| {
                key.open_share(document.envelope(), member.index)
                    .expect("member opens its own share")
            })
            .collect()
    }

    #[test]
    fn a_serving_node_holds_bytes_that_do_not_contain_the_document() {
        let (members, _keys) = committee(5);
        let content = b"An embargoed preprint. Section 1: the result.";
        let document = Document::seal(content, 100, &members, 3, &mut OsRng).expect("seals");

        // Everything a node is given, in the form it is given it.
        let stored = document.ciphertext();
        let record = document.to_value().canonical_string();

        // The point of the whole module: neither the bytes on disk nor the
        // record describing them carries the content, and neither carries the
        // plaintext digest that would let a holder confirm a guess.
        assert!(
            !stored.windows(content.len()).any(|w| w == content),
            "the content appeared in the bytes a node stores"
        );
        assert!(
            !record.contains("preprint"),
            "the content appeared in the record"
        );
        let plaintext_digest = digest_bytes(content);
        assert!(
            !record.contains(&plaintext_digest),
            "the plaintext digest leaked into the record, which is a \
             confirmation-of-file oracle"
        );
    }

    #[test]
    fn the_address_a_node_stores_it_under_is_the_ciphertexts_not_the_contents() {
        let (members, _keys) = committee(5);
        let content = b"the same document, contributed twice";
        let first = Document::seal(content, 100, &members, 3, &mut OsRng).expect("seals");
        let second = Document::seal(content, 100, &members, 3, &mut OsRng).expect("seals");

        assert_ne!(
            first.blind_address(),
            second.blind_address(),
            "two seals of one document shared an address, which means the address \
             is a function of the content and anyone can test for it"
        );
        assert_ne!(first.blind_address(), digest_bytes(content));
    }

    #[test]
    fn a_threshold_opens_it_and_one_short_of_a_threshold_does_not() {
        let (members, keys) = committee(5);
        let content = b"Theorem 1. Every confidential corpus needs a release rule.";
        let document = Document::seal(content, 10, &members, 3, &mut OsRng).expect("seals");

        let two = shares_from(&document, &keys, &members, 2);
        assert!(
            document.open(&two, 10).is_err(),
            "two of a three-threshold opened the document"
        );

        let three = shares_from(&document, &keys, &members, 3);
        assert_eq!(document.open(&three, 10).expect("opens"), content);
    }

    #[test]
    fn it_refuses_before_the_release_epoch_and_says_that_this_is_policy() {
        let (members, keys) = committee(5);
        let document = Document::seal(b"embargoed", 100, &members, 3, &mut OsRng).expect("seals");
        let shares = shares_from(&document, &keys, &members, 3);

        match document.open(&shares, 99) {
            Err(CorpusError::NotYetReleased { release_epoch, now }) => {
                assert_eq!((release_epoch, now), (100, 99));
            }
            other => panic!("expected a refusal before release, got {other:?}"),
        }
        // And the honest part: the shares work regardless, which is why the
        // threshold rather than the epoch is the security argument.
        assert_eq!(
            document.open_regardless(&shares).expect("opens"),
            b"embargoed"
        );
        assert_eq!(document.open(&shares, 100).expect("opens"), b"embargoed");
    }

    #[test]
    fn a_share_does_not_carry_across_two_release_epochs() {
        // The release epoch is in the AAD, so a committee that published for an
        // early document has not thereby opened a later one. Without this, an
        // operator could re-point shares at whichever document they wanted.
        let (members, keys) = committee(5);
        let early = Document::seal(b"released first", 10, &members, 3, &mut OsRng).expect("seals");
        let late = Document::seal(b"released later", 200, &members, 3, &mut OsRng).expect("seals");

        let early_shares = shares_from(&early, &keys, &members, 3);
        assert!(
            late.open_regardless(&early_shares).is_err(),
            "shares published for an epoch-10 document opened an epoch-200 one"
        );
    }

    #[test]
    fn availability_sampling_works_over_the_ciphertext() {
        let (members, _keys) = committee(5);
        // Several chunks, so the root is a tree rather than a single leaf.
        let content = vec![7u8; CHUNK_LEN * 3 + 11];
        let document = Document::seal(&content, 10, &members, 3, &mut OsRng).expect("seals");

        let root = document.availability_root().expect("a root");
        assert!(root.starts_with("sha256:"));
        // Reproducible from the stored bytes alone: a sampler challenges a node
        // that holds only ciphertext, and the node can answer.
        let leaves: Vec<String> = document
            .ciphertext()
            .chunks(CHUNK_LEN)
            .map(digest_bytes)
            .collect();
        assert_eq!(merkle_root(&leaves), Some(root));
    }

    #[test]
    fn a_document_round_trips_through_its_record() {
        let (members, keys) = committee(4);
        let content = b"round trip";
        let document = Document::seal(content, 42, &members, 2, &mut OsRng).expect("seals");

        let decoded = Document::from_value(&document.to_value()).expect("decodes");
        assert_eq!(decoded, document);
        assert_eq!(decoded.release_epoch(), 42);
        assert_eq!(decoded.blind_address(), document.blind_address());

        let shares = shares_from(&document, &keys, &members, 2);
        assert_eq!(decoded.open(&shares, 42).expect("opens"), content);
    }

    #[test]
    fn an_empty_document_is_still_a_document() {
        let (members, keys) = committee(3);
        let document = Document::seal(b"", 0, &members, 2, &mut OsRng).expect("seals");
        let shares = shares_from(&document, &keys, &members, 2);
        assert_eq!(document.open(&shares, 0).expect("opens"), b"");
        assert!(document.availability_root().is_some());
    }
}
