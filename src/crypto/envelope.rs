//! Sealed submission envelopes: one AEAD over the artifact, with the content
//! key split across a threshold committee.
//!
//! # Why this exists
//!
//! Plain commit–reveal requires the submitter to act **twice** (`docs/censorship.md`
//! §1). An adversary who can neither forge nor steal your work can still take it
//! by stopping the second action: a targeted DoS, a network block, a detention, a
//! seized laptop, or a sequencer that drops your reveal until the deadline
//! passes. Your commitment sits on the log proving you had the answer first, and
//! you cannot collect.
//!
//! A sealed envelope removes the submitter from the reveal path entirely
//! (§2). The artifact is submitted encrypted at commit time; at the epoch
//! boundary `t` committee members publish their shares and *anyone* reconstructs
//! the content key. The submitter can be offline, jailed, or firewalled and still
//! be paid. Three properties fall out at once:
//!
//! - reveal-window censorship dies — nothing is required of the submitter after commit;
//! - in-flight front-running dies — nobody, sequencer included, sees the artifact
//!   while they could still act on it;
//! - selective censorship becomes visible — a sequencer that cannot see what it is
//!   dropping must include everything or censor indiscriminately, and
//!   indiscriminate censorship is detectable by everyone at once.
//!
//! # What binds what
//!
//! Confidentiality here is *not* what makes the scheme safe; **binding** is, and
//! binding is free. The commitment is already a hash of the plaintext artifact
//! ([`crate::records::commitment_hash`]), so a submitter who seals garbage is
//! caught the moment the committee opens it. This module therefore never needs to
//! prove the plaintext is "the right one" — it only has to guarantee that an
//! envelope cannot be *moved* between submissions. That is what `aad` is for:
//!
//! - it is the AEAD associated data of the payload ciphertext, so a ciphertext
//!   lifted into another submission fails its tag;
//! - it is absorbed into the key-derivation transcript of every sealed share, so
//!   a sealed share replayed into another envelope derives a different key and
//!   fails its tag.
//!
//! Callers pass the submission's commitment hash as `aad`. Storing it and not
//! feeding it to the cryptography would be theatre; both uses above are load
//! bearing and both are tested.
//!
//! # What this does not defend against
//!
//! - **`t` colluding committee members** read the artifact early and can
//!   front-run it. Rotation, diversity and a high threshold make that expensive;
//!   nothing here makes it impossible (§8).
//! - **A committee that refuses to publish shares** stalls the reveal. That is a
//!   liveness failure, not a confidentiality one, and it is why `n - t` must be
//!   large enough to absorb absentees. The fallback is submitter-initiated
//!   reveal: [`SealedEnvelope::seal_retaining_key`] plus
//!   [`SealedEnvelope::open_with_content_key`]. It reintroduces the requirement
//!   that the submitter be online, which is the whole problem — hence a
//!   fallback, not a path.
//! - **Traffic analysis.** [`SealedEnvelope::digest`] is public and the
//!   ciphertext length leaks the artifact length to within 16 bytes (§4).
//!   Padding to a size bucket is the caller's job; this module deliberately does
//!   not pad, because a padding policy chosen here would be invisible to the
//!   record layer that has to agree on it.
//! - **Structural tampering.** `threshold` and the sealed-share list travel
//!   outside every AEAD. Editing them can only make an envelope fail to open: a
//!   wrong or short share set reconstructs a wrong content key, and a wrong
//!   content key fails the payload tag. It can never produce a different
//!   plaintext.
//!
//! # Timing
//!
//! No secret-dependent branch or index is taken in this module. Everything that
//! touches a secret is either data-independent (`copy_from_slice`, the SHA-256
//! transcript) or delegated: `x25519-dalek` for the scalar multiplication,
//! `chacha20poly1305` for the constant-time Poly1305 tag comparison, and
//! [`super::shamir`] for the GF(2^8) arithmetic. The one data-dependent routine
//! here, `hex_encode`, is applied only to published bytes.

use core::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::shamir::{self, Share};
use crate::canonical::Value;

/// Wire type tag. Present so a record decoder cannot confuse an envelope with
/// some other object that happens to share field names.
const RECORD_TYPE: &str = "sealed_envelope";

/// Wire version. Bumped only for a change that alters how bytes are interpreted;
/// an unknown version is refused rather than guessed at.
const VERSION: i128 = 1;

/// Domain separator for the share key derivation.
///
/// A hash used for two purposes in one protocol is a hash used wrongly. This
/// string exists so that a share key can never collide with a digest computed
/// anywhere else in the crate, whatever the inputs.
const SHARE_KDF_DOMAIN: &[u8] = b"proofwork/censorship/envelope/share-key/v1";

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// Shamir indexes are `u8` x-coordinates, so at most 255 members can hold one
/// share each.
const MAX_COMMITTEE: usize = 255;

// -- secret material -------------------------------------------------------

/// A 32-byte secret that wipes itself on drop and never prints itself.
///
/// Used for the content key, for derived share keys, and as the return type of
/// [`CommitteeKey::to_bytes`]. Handing callers a bare `[u8; 32]` would silently
/// move the wiping obligation onto code that has no reason to remember it.
pub struct Secret32([u8; KEY_LEN]);

impl Secret32 {
    fn zeroed() -> Secret32 {
        Secret32([0u8; KEY_LEN])
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Secret32 {
        let mut bytes = [0u8; KEY_LEN];
        rng.fill_bytes(&mut bytes);
        Secret32(bytes)
    }

    /// Take ownership of key bytes the caller already has.
    ///
    /// Public because [`crate::store::atrest`] holds a key that came off disk
    /// rather than out of this module, and it should get the same zeroing and
    /// the same redacted `Debug` as every other secret here. Taking the array
    /// by value rather than by reference is the point: there is one owner, and
    /// the caller's copy is moved rather than left lying around.
    pub fn new(bytes: [u8; KEY_LEN]) -> Secret32 {
        Secret32(bytes)
    }

    /// Borrow the raw bytes. Named `expose` so that every call site reads as an
    /// admission rather than an accessor.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Zeroize for Secret32 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for Secret32 {}

/// Redacted: a debug-printed key ends up in logs, and a key in a log is a key
/// that leaked.
impl fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret32(<redacted>)")
    }
}

// -- errors ----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// A committee of zero members can seal nothing that anyone can reopen.
    EmptyCommittee,
    /// More members than there are Shamir x-coordinates.
    CommitteeTooLarge { size: usize },
    /// `threshold` must be at least 1 and at most the committee size.
    InvalidThreshold { threshold: u8, committee: usize },
    /// Two members share a routing index, so a share cannot be addressed.
    DuplicateMemberIndex { index: u8 },
    /// Two members share a public key. Not a decoding problem: it means one
    /// entity silently holds two shares and the effective threshold is lower
    /// than the stated one.
    DuplicateMemberKey { index: u8 },
    /// The X25519 exchange produced the identity point, which every observer can
    /// also compute. Almost always a low-order public key planted by a member
    /// who wants their own share to be readable by anyone.
    NonContributoryExchange { index: u8 },
    /// The share splitter returned a different number of shares than there are
    /// members, so shares and members cannot be paired.
    ShareCountMismatch { shares: usize, committee: usize },
    /// The secret sharing layer failed. Text is captured rather than typed so
    /// this module does not constrain the sibling's error enum.
    Shamir(String),
    /// AEAD encryption failed. Reachable only for absurd input lengths.
    Encrypt { context: &'static str },
    /// AEAD authentication failed.
    ///
    /// For the payload this is the *only* signal that the share set was wrong:
    /// see [`SealedEnvelope::open_with_shares`].
    Authentication { context: &'static str },
    /// No sealed share carries this routing index.
    UnknownShare { index: u8 },
    /// A decrypted sealed share was empty, so it carries no Shamir index byte.
    MalformedShare { index: u8 },
    /// The reconstructed secret is not a 32-byte content key.
    ContentKeyLength { actual: usize },
    /// `open_with_shares` was handed nothing to combine.
    NoShares,
    /// Decoding: the value is not an object.
    NotAnObject,
    /// Decoding: required field absent.
    MissingField { field: &'static str },
    /// Decoding: field present with the wrong shape.
    InvalidField {
        field: &'static str,
        expected: &'static str,
    },
    /// Decoding: field is not lowercase, even-length hex.
    InvalidHex { field: &'static str },
    /// Decoding: hex field decoded to the wrong number of bytes.
    WrongLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    /// Decoding: two sealed shares claim the same routing index.
    DuplicateShareIndex { index: u8 },
    /// Decoding: a version this build cannot interpret.
    UnsupportedVersion { version: i128 },
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnvelopeError::EmptyCommittee => f.write_str("committee must have at least one member"),
            EnvelopeError::CommitteeTooLarge { size } => write!(
                f,
                "committee of {size} exceeds the {MAX_COMMITTEE} addressable shares"
            ),
            EnvelopeError::InvalidThreshold {
                threshold,
                committee,
            } => write!(
                f,
                "threshold {threshold} must be in 1..={committee} for this committee"
            ),
            EnvelopeError::DuplicateMemberIndex { index } => {
                write!(f, "duplicate committee member index {index}")
            }
            EnvelopeError::DuplicateMemberKey { index } => write!(
                f,
                "committee member {index} reuses another member's public key; \
                 one entity would hold two shares"
            ),
            EnvelopeError::NonContributoryExchange { index } => write!(
                f,
                "key exchange with committee member {index} was non-contributory \
                 (low-order public key)"
            ),
            EnvelopeError::ShareCountMismatch { shares, committee } => write!(
                f,
                "share splitter returned {shares} shares for {committee} members"
            ),
            EnvelopeError::Shamir(why) => write!(f, "secret sharing failed: {why}"),
            EnvelopeError::Encrypt { context } => write!(f, "{context}: AEAD encryption failed"),
            EnvelopeError::Authentication { context } => {
                write!(f, "{context}: AEAD authentication failed")
            }
            EnvelopeError::UnknownShare { index } => {
                write!(f, "envelope carries no sealed share for index {index}")
            }
            EnvelopeError::MalformedShare { index } => {
                write!(f, "sealed share {index} decrypted to an empty plaintext")
            }
            EnvelopeError::ContentKeyLength { actual } => write!(
                f,
                "reconstructed secret is {actual} bytes, expected {KEY_LEN}"
            ),
            EnvelopeError::NoShares => f.write_str("no shares supplied"),
            EnvelopeError::NotAnObject => f.write_str("sealed envelope must be an object"),
            EnvelopeError::MissingField { field } => {
                write!(f, "missing required field {field:?}")
            }
            EnvelopeError::InvalidField { field, expected } => {
                write!(f, "field {field:?} must be {expected}")
            }
            EnvelopeError::InvalidHex { field } => {
                write!(f, "field {field:?} must be lowercase hex of even length")
            }
            EnvelopeError::WrongLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "field {field:?} must decode to {expected} bytes, got {actual}"
            ),
            EnvelopeError::DuplicateShareIndex { index } => {
                write!(f, "duplicate sealed share index {index}")
            }
            EnvelopeError::UnsupportedVersion { version } => {
                write!(f, "unsupported sealed envelope version {version}")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}

// -- committee -------------------------------------------------------------

/// A committee member's public identity: a routing index and an X25519 key.
///
/// `index` addresses the member within *this* envelope and has nothing to do
/// with the Shamir x-coordinate of the share they hold; the x-coordinate travels
/// sealed, inside the share ciphertext. Keeping them separate means this module
/// never has to assume how the sibling splitter numbers its shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitteeMember {
    pub index: u8,
    pub public_key: [u8; KEY_LEN],
}

/// A committee member's private key.
///
/// `StaticSecret` rather than `EphemeralSecret` because a committee member must
/// be reachable across an epoch's worth of submissions with one published key.
pub struct CommitteeKey {
    secret: StaticSecret,
}

/// Redacted. `StaticSecret` itself has no `Debug`; this impl exists so that
/// deriving `Debug` on a surrounding type cannot accidentally add one later.
impl fmt::Debug for CommitteeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CommitteeKey")
            .field("public", &hex_encode(self.public().as_slice()))
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl CommitteeKey {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> CommitteeKey {
        CommitteeKey {
            secret: StaticSecret::random_from_rng(&mut *rng),
        }
    }

    /// Load a stored key. Bytes are used as-is; X25519 clamps at use time, so
    /// every 32-byte string is a usable secret and there is nothing to reject.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> CommitteeKey {
        CommitteeKey {
            secret: StaticSecret::from(bytes),
        }
    }

    /// Export for persistence. The returned value wipes itself on drop; that is
    /// the whole reason it is not a plain `[u8; 32]`.
    pub fn to_bytes(&self) -> Secret32 {
        Secret32(self.secret.to_bytes())
    }

    pub fn public(&self) -> [u8; KEY_LEN] {
        PublicKey::from(&self.secret).to_bytes()
    }

    /// The public half of this key, addressed at `index`.
    pub fn member(&self, index: u8) -> CommitteeMember {
        CommitteeMember {
            index,
            public_key: self.public(),
        }
    }

    /// Recover this member's Shamir share at the epoch boundary.
    ///
    /// Failure modes are deliberately indistinguishable: a share sealed to
    /// somebody else, a share lifted from another envelope, and a tampered share
    /// all surface as [`EnvelopeError::Authentication`]. There is no way to tell
    /// them apart from the ciphertext, and pretending otherwise would invent a
    /// distinction the cryptography does not support.
    pub fn open_share(&self, envelope: &SealedEnvelope, index: u8) -> Result<Share, EnvelopeError> {
        let sealed = envelope
            .sealed_share(index)
            .ok_or(EnvelopeError::UnknownShare { index })?;

        let ephemeral = PublicKey::from(sealed.ephemeral_public);
        let shared = self.secret.diffie_hellman(&ephemeral);
        if !shared.was_contributory() {
            return Err(EnvelopeError::NonContributoryExchange { index });
        }

        let key = derive_share_key(
            &shared,
            &sealed.ephemeral_public,
            &self.public(),
            index,
            &envelope.aad,
        );
        let cipher = cipher_for(&key);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(&Nonce::from(sealed.nonce), sealed.ciphertext.as_slice())
                .map_err(|_| EnvelopeError::Authentication {
                    context: "sealed share",
                })?,
        );

        // Layout: one Shamir x-coordinate byte, then the share body. The
        // x-coordinate is inside the AEAD rather than beside it so that a
        // relabelled share is a tag failure, not a silently wrong reconstruction.
        let (x, body) = plaintext
            .split_first()
            .ok_or(EnvelopeError::MalformedShare { index })?;
        Ok(Share {
            index: *x,
            data: body.to_vec(),
        })
    }
}

// -- sealed share ----------------------------------------------------------

/// One committee member's share, sealed to their public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedShare {
    index: u8,
    ephemeral_public: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl SealedShare {
    pub fn index(&self) -> u8 {
        self.index
    }

    pub fn ephemeral_public(&self) -> &[u8; KEY_LEN] {
        &self.ephemeral_public
    }

    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("index", Value::Int(i128::from(self.index))),
            (
                "ephemeral_public",
                Value::string(hex_encode(&self.ephemeral_public)),
            ),
            ("nonce", Value::string(hex_encode(&self.nonce))),
            ("ciphertext", Value::string(hex_encode(&self.ciphertext))),
        ])
    }

    pub fn from_value(value: &Value) -> Result<SealedShare, EnvelopeError> {
        if value.as_object().is_none() {
            return Err(EnvelopeError::NotAnObject);
        }
        Ok(SealedShare {
            index: field_u8(value, "index")?,
            ephemeral_public: field_hex_fixed::<KEY_LEN>(value, "ephemeral_public")?,
            nonce: field_hex_fixed::<NONCE_LEN>(value, "nonce")?,
            ciphertext: field_hex(value, "ciphertext")?,
        })
    }
}

// -- envelope --------------------------------------------------------------

/// An artifact sealed to a threshold committee.
///
/// Every field is public ciphertext or public metadata, so `Debug`, `Clone` and
/// `PartialEq` leak nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEnvelope {
    threshold: u8,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
    sealed_shares: Vec<SealedShare>,
    aad: String,
}

impl SealedEnvelope {
    /// Seal `payload` to `committee`, openable by any `threshold` of them.
    ///
    /// `aad` is the context this envelope is bound to — the submission's
    /// commitment hash. It is fed to the payload AEAD *and* into every share's
    /// key derivation, so neither the payload ciphertext nor an individual
    /// sealed share can be lifted into a different submission.
    ///
    /// The 96-bit nonces are random rather than counters. That is safe only
    /// because both keys are fresh: the content key is 32 bytes drawn from `rng`
    /// for this envelope alone, and each share key comes from a fresh ephemeral
    /// exchange. Neither key ever encrypts a second message, so nonce reuse
    /// across messages under one key cannot arise.
    pub fn seal<R: RngCore + CryptoRng>(
        payload: &[u8],
        aad: &str,
        committee: &[CommitteeMember],
        threshold: u8,
        rng: &mut R,
    ) -> Result<SealedEnvelope, EnvelopeError> {
        // The content key is dropped here, and wiped on the way out. A submitter
        // who wants the §2 liveness fallback must ask for it explicitly.
        SealedEnvelope::seal_retaining_key(payload, aad, committee, threshold, rng)
            .map(|(envelope, _key)| envelope)
    }

    /// [`SealedEnvelope::seal`], but the content key is returned instead of
    /// wiped.
    ///
    /// Keeping it is what makes [`SealedEnvelope::open_with_content_key`] usable,
    /// and therefore what makes the stalled-committee fallback in
    /// `docs/censorship.md` §2 real rather than aspirational. It is a separate
    /// constructor because retaining the key is a decision with a cost: the key
    /// is now a thing that can be seized from the submitter, which is the exact
    /// leverage sealing was meant to remove.
    pub fn seal_retaining_key<R: RngCore + CryptoRng>(
        payload: &[u8],
        aad: &str,
        committee: &[CommitteeMember],
        threshold: u8,
        rng: &mut R,
    ) -> Result<(SealedEnvelope, Secret32), EnvelopeError> {
        if committee.is_empty() {
            return Err(EnvelopeError::EmptyCommittee);
        }
        if committee.len() > MAX_COMMITTEE {
            return Err(EnvelopeError::CommitteeTooLarge {
                size: committee.len(),
            });
        }
        if threshold == 0 || usize::from(threshold) > committee.len() {
            return Err(EnvelopeError::InvalidThreshold {
                threshold,
                committee: committee.len(),
            });
        }
        // A duplicate index makes a share unaddressable; a duplicate key means
        // one entity holds two shares, which quietly lowers the threshold the
        // rest of the system believes it has. Both are caller bugs worth
        // refusing loudly (docs/censorship.md §2 on collusion cost).
        for (i, member) in committee.iter().enumerate() {
            for other in committee.iter().skip(i + 1) {
                if member.index == other.index {
                    return Err(EnvelopeError::DuplicateMemberIndex {
                        index: member.index,
                    });
                }
                if member.public_key == other.public_key {
                    return Err(EnvelopeError::DuplicateMemberKey { index: other.index });
                }
            }
        }

        let content_key = Secret32::random(rng);
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        let ciphertext = cipher_for(&content_key)
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: payload,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| EnvelopeError::Encrypt { context: "payload" })?;

        // `committee.len() <= MAX_COMMITTEE == u8::MAX`, checked above.
        let count = committee.len() as u8;
        let mut shares = shamir::split(content_key.expose(), threshold, count, &mut *rng)
            .map_err(|e| EnvelopeError::Shamir(format!("{e:?}")))?;
        if shares.len() != committee.len() {
            wipe_shares(&mut shares);
            return Err(EnvelopeError::ShareCountMismatch {
                shares: shares.len(),
                committee: committee.len(),
            });
        }

        let mut sealed_shares = Vec::with_capacity(committee.len());
        let mut failure = None;
        for (member, share) in committee.iter().zip(shares.iter()) {
            match seal_share(member, share, aad, rng) {
                Ok(sealed) => sealed_shares.push(sealed),
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            }
        }
        // The splitter's `Share` is a plain data struct with no drop glue, so
        // wiping is this module's responsibility -- on the error path too, where
        // plaintext shares of a still-secret content key would otherwise be left
        // in freed memory.
        wipe_shares(&mut shares);
        if let Some(e) = failure {
            return Err(e);
        }

        Ok((
            SealedEnvelope {
                threshold,
                nonce,
                ciphertext,
                sealed_shares,
                aad: aad.to_string(),
            },
            content_key,
        ))
    }

    /// Reconstruct the content key from published shares and decrypt.
    ///
    /// **Shamir cannot tell you "too few shares".** Any set of points defines
    /// *some* polynomial, so combining `t-1` shares yields a perfectly
    /// well-formed 32-byte value that is simply the wrong key — this is the
    /// information-theoretic security property, not a defect. There is therefore
    /// no share count check here and there could not be a useful one: the AEAD
    /// tag is the only thing that can distinguish a correct reconstruction from
    /// a wrong one, which is why it is load-bearing rather than decorative.
    ///
    /// A failure means one of: too few shares, a corrupt or forged share, shares
    /// from a different envelope, or a tampered ciphertext. All of them are
    /// [`EnvelopeError::Authentication`] and none of them can be distinguished.
    pub fn open_with_shares(&self, shares: &[Share]) -> Result<Vec<u8>, EnvelopeError> {
        if shares.is_empty() {
            return Err(EnvelopeError::NoShares);
        }
        let combined = Zeroizing::new(
            shamir::combine(shares).map_err(|e| EnvelopeError::Shamir(format!("{e:?}")))?,
        );
        if combined.len() != KEY_LEN {
            return Err(EnvelopeError::ContentKeyLength {
                actual: combined.len(),
            });
        }
        let mut content_key = Secret32::zeroed();
        content_key.0.copy_from_slice(&combined); // length checked immediately above

        cipher_for(&content_key)
            .decrypt(
                &Nonce::from(self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: self.aad.as_bytes(),
                },
            )
            .map_err(|_| EnvelopeError::Authentication { context: "payload" })
    }

    /// Decrypt with a content key held directly.
    ///
    /// The submitter never lost the key, so this is the fallback for a committee
    /// that will not publish (`docs/censorship.md` §2: "a permanently stalled
    /// epoch must fall back to submitter-initiated reveal rather than losing the
    /// submission"). It restores the plain commit–reveal failure mode — the
    /// submitter must be online — which is exactly why it is the fallback and
    /// not the path.
    pub fn open_with_content_key(&self, content_key: &Secret32) -> Result<Vec<u8>, EnvelopeError> {
        cipher_for(content_key)
            .decrypt(
                &Nonce::from(self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: self.aad.as_bytes(),
                },
            )
            .map_err(|_| EnvelopeError::Authentication { context: "payload" })
    }

    pub fn threshold(&self) -> u8 {
        self.threshold
    }

    pub fn nonce(&self) -> &[u8; NONCE_LEN] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// The context this envelope is bound to, normally a commitment hash.
    pub fn aad(&self) -> &str {
        &self.aad
    }

    pub fn sealed_shares(&self) -> &[SealedShare] {
        &self.sealed_shares
    }

    pub fn sealed_share(&self, index: u8) -> Option<&SealedShare> {
        self.sealed_shares.iter().find(|s| s.index == index)
    }

    pub fn to_value(&self) -> Value {
        Value::object([
            ("type", Value::string(RECORD_TYPE)),
            ("version", Value::Int(VERSION)),
            ("threshold", Value::Int(i128::from(self.threshold))),
            ("nonce", Value::string(hex_encode(&self.nonce))),
            ("ciphertext", Value::string(hex_encode(&self.ciphertext))),
            ("aad", Value::string(self.aad.clone())),
            (
                "sealed_shares",
                Value::array(self.sealed_shares.iter().map(SealedShare::to_value)),
            ),
        ])
    }

    pub fn from_value(value: &Value) -> Result<SealedEnvelope, EnvelopeError> {
        if value.as_object().is_none() {
            return Err(EnvelopeError::NotAnObject);
        }
        match value.get("type") {
            None => return Err(EnvelopeError::MissingField { field: "type" }),
            Some(Value::String(t)) if t.as_str() == RECORD_TYPE => {}
            Some(_) => {
                return Err(EnvelopeError::InvalidField {
                    field: "type",
                    expected: "\"sealed_envelope\"",
                })
            }
        }
        let version = value
            .get("version")
            .ok_or(EnvelopeError::MissingField { field: "version" })?
            .as_i128()
            .ok_or(EnvelopeError::InvalidField {
                field: "version",
                expected: "an integer",
            })?;
        if version != VERSION {
            return Err(EnvelopeError::UnsupportedVersion { version });
        }

        let threshold = field_u8(value, "threshold")?;
        let nonce = field_hex_fixed::<NONCE_LEN>(value, "nonce")?;
        let ciphertext = field_hex(value, "ciphertext")?;
        let aad = field_str(value, "aad")?.to_string();

        let raw = value
            .get("sealed_shares")
            .ok_or(EnvelopeError::MissingField {
                field: "sealed_shares",
            })?
            .as_array()
            .ok_or(EnvelopeError::InvalidField {
                field: "sealed_shares",
                expected: "an array",
            })?;
        let mut sealed_shares = Vec::with_capacity(raw.len());
        for item in raw {
            let share = SealedShare::from_value(item)?;
            if sealed_shares
                .iter()
                .any(|s: &SealedShare| s.index == share.index)
            {
                return Err(EnvelopeError::DuplicateShareIndex { index: share.index });
            }
            sealed_shares.push(share);
        }

        // These are the same invariants `seal` enforces. A decoder that accepted
        // an envelope `seal` could not have produced would hand the rest of the
        // system a shape it never has to handle.
        if sealed_shares.is_empty() {
            return Err(EnvelopeError::EmptyCommittee);
        }
        if threshold == 0 || usize::from(threshold) > sealed_shares.len() {
            return Err(EnvelopeError::InvalidThreshold {
                threshold,
                committee: sealed_shares.len(),
            });
        }

        Ok(SealedEnvelope {
            threshold,
            nonce,
            ciphertext,
            sealed_shares,
            aad,
        })
    }

    /// Content address of the envelope as it appears on the wire.
    ///
    /// Over the canonical encoding, so it covers the sealed shares and their
    /// order. Two nodes that hold the same envelope agree on this digest; a node
    /// that reorders the share list produces a different digest for an envelope
    /// that still opens, so the digest identifies the *encoding*, not the
    /// plaintext. The commitment hash is what identifies the plaintext.
    pub fn digest(&self) -> String {
        self.to_value().digest()
    }
}

// -- internals -------------------------------------------------------------

/// Seal one Shamir share to one member.
fn seal_share<R: RngCore + CryptoRng>(
    member: &CommitteeMember,
    share: &Share,
    aad: &str,
    rng: &mut R,
) -> Result<SealedShare, EnvelopeError> {
    // Ephemeral, not static: a per-share keypair means a compromised sender key
    // cannot retroactively open past envelopes, and `EphemeralSecret` is
    // consumed by the exchange so it cannot be reused by mistake.
    let ephemeral = EphemeralSecret::random_from_rng(&mut *rng);
    let ephemeral_public = PublicKey::from(&ephemeral).to_bytes();
    let recipient = PublicKey::from(member.public_key);
    let shared = ephemeral.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        // The identity point means the shared secret is a constant every
        // observer can compute, so this member's share would be world-readable
        // and the effective threshold would be one lower than advertised.
        return Err(EnvelopeError::NonContributoryExchange {
            index: member.index,
        });
    }

    let key = derive_share_key(
        &shared,
        &ephemeral_public,
        &member.public_key,
        member.index,
        aad,
    );

    let mut plaintext = Zeroizing::new(Vec::with_capacity(share.data.len().saturating_add(1)));
    plaintext.push(share.index);
    plaintext.extend_from_slice(&share.data);

    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    // No associated data here: `aad` is already committed to by the derived key,
    // so an envelope-mismatched share fails at the tag either way, and binding it
    // twice would only invite the two bindings to drift apart.
    let ciphertext = cipher_for(&key)
        .encrypt(&Nonce::from(nonce), plaintext.as_slice())
        .map_err(|_| EnvelopeError::Encrypt {
            context: "sealed share",
        })?;

    Ok(SealedShare {
        index: member.index,
        ephemeral_public,
        nonce,
        ciphertext,
    })
}

/// Derive a share-sealing key from a completed X25519 exchange.
///
/// Every value that decides *which* envelope and *which* recipient this share
/// belongs to is absorbed, so a sealed share is cryptographically welded to its
/// position: replay it into another envelope (different `aad`), re-address it to
/// another member (different recipient key or index), or pair it with a
/// different ephemeral key, and the derived key changes and the tag fails.
///
/// Fields are length-prefixed so the transcript is injective — without prefixes,
/// a recipient key ending in some bytes and an `aad` starting with them could
/// concatenate to the same string as a different pair.
fn derive_share_key(
    shared: &SharedSecret,
    ephemeral_public: &[u8; KEY_LEN],
    recipient_public: &[u8; KEY_LEN],
    member_index: u8,
    aad: &str,
) -> Secret32 {
    let mut hasher = Sha256::new();
    absorb(&mut hasher, SHARE_KDF_DOMAIN);
    absorb(&mut hasher, shared.as_bytes());
    absorb(&mut hasher, ephemeral_public);
    absorb(&mut hasher, recipient_public);
    absorb(&mut hasher, &[member_index]);
    absorb(&mut hasher, aad.as_bytes());

    let mut out = hasher.finalize();
    let mut key = Secret32::zeroed();
    // SHA-256's output is 32 bytes by construction, so this cannot mismatch.
    key.0.copy_from_slice(&out[..]);
    Zeroize::zeroize(&mut out[..]);
    key
}

fn absorb(hasher: &mut Sha256, field: &[u8]) {
    hasher.update((field.len() as u64).to_be_bytes());
    hasher.update(field);
}

/// Build an AEAD instance, wiping the copy of the key made on the way in.
///
/// `ChaCha20Poly1305` zeroizes its own key on drop; the `GenericArray` used to
/// hand it over is the one copy nobody else wipes.
fn cipher_for(key: &Secret32) -> ChaCha20Poly1305 {
    let mut material = Key::from(*key.expose());
    let cipher = ChaCha20Poly1305::new(&material);
    Zeroize::zeroize(&mut material[..]);
    cipher
}

fn wipe_shares(shares: &mut [Share]) {
    for share in shares.iter_mut() {
        share.data.zeroize();
    }
}

// -- hex and field decoding ------------------------------------------------

/// Lowercase hex. Binary on the wire is hex because the canonical encoder has no
/// byte-string type and base64 has too many spellings of one value.
///
/// **Not constant time**: it branches per nibble. That is fine for what it is
/// used on -- nonces, ciphertexts, ephemeral and committee public keys, all of
/// which are published -- and it is why [`Secret32`] has no hex or `Display`
/// impl. Do not reach for this to print key material.
fn hex_encode(bytes: &[u8]) -> String {
    // One encoder for the whole crate, in `crate::hex`. A second copy here is a
    // second thing that could disagree about how a published byte is spelled.
    crate::hex::encode(bytes)
}

/// Strict decoder: lowercase only.
///
/// Accepting `AB` as well as `ab` would give one envelope two spellings and
/// therefore two digests, which is the disagreement `canonical.rs` exists to
/// prevent.
fn hex_decode(text: &str, field: &'static str) -> Result<Vec<u8>, EnvelopeError> {
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut high: Option<u8> = None;
    for byte in text.bytes() {
        let value = hex_value(byte).ok_or(EnvelopeError::InvalidHex { field })?;
        match high.take() {
            None => high = Some(value),
            Some(h) => out.push((h << 4) | value),
        }
    }
    if high.is_some() {
        return Err(EnvelopeError::InvalidHex { field });
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn field_str<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, EnvelopeError> {
    value
        .get(field)
        .ok_or(EnvelopeError::MissingField { field })?
        .as_str()
        .ok_or(EnvelopeError::InvalidField {
            field,
            expected: "a string",
        })
}

fn field_hex(value: &Value, field: &'static str) -> Result<Vec<u8>, EnvelopeError> {
    hex_decode(field_str(value, field)?, field)
}

fn field_hex_fixed<const N: usize>(
    value: &Value,
    field: &'static str,
) -> Result<[u8; N], EnvelopeError> {
    let bytes = field_hex(value, field)?;
    if bytes.len() != N {
        return Err(EnvelopeError::WrongLength {
            field,
            expected: N,
            actual: bytes.len(),
        });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes); // length checked immediately above
    Ok(out)
}

fn field_u8(value: &Value, field: &'static str) -> Result<u8, EnvelopeError> {
    let raw = value
        .get(field)
        .ok_or(EnvelopeError::MissingField { field })?
        .as_i128()
        .ok_or(EnvelopeError::InvalidField {
            field,
            expected: "an integer",
        })?;
    u8::try_from(raw).map_err(|_| EnvelopeError::InvalidField {
        field,
        expected: "an integer in 0..=255",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    const AAD: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const OTHER_AAD: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn committee(n: u8) -> (Vec<CommitteeKey>, Vec<CommitteeMember>) {
        let mut keys = Vec::new();
        let mut members = Vec::new();
        for index in 1..=n {
            let key = CommitteeKey::generate(&mut OsRng);
            members.push(key.member(index));
            keys.push(key);
        }
        (keys, members)
    }

    fn clone_share(share: &Share) -> Share {
        Share {
            index: share.index,
            data: share.data.clone(),
        }
    }

    /// Open every member's share. Mirrors the epoch boundary, where each member
    /// publishes independently.
    fn open_all(keys: &[CommitteeKey], envelope: &SealedEnvelope) -> Vec<Share> {
        keys.iter()
            .enumerate()
            .map(|(i, key)| {
                let index = u8::try_from(i + 1).expect("test committee fits in u8");
                key.open_share(envelope, index)
                    .expect("member opens their own share")
            })
            .collect()
    }

    #[test]
    fn round_trip_with_exactly_threshold_shares() {
        let (keys, members) = committee(5);
        let payload = b"artifact: the answer is 42";
        let envelope =
            SealedEnvelope::seal(payload, AAD, &members, 3, &mut OsRng).expect("seal succeeds");

        let shares = open_all(&keys, &envelope);
        let exactly_three: Vec<Share> = shares.iter().take(3).map(clone_share).collect();
        let opened = envelope
            .open_with_shares(&exactly_three)
            .expect("t shares reconstruct");
        assert_eq!(opened, payload);
    }

    #[test]
    fn round_trip_with_more_than_threshold_shares() {
        let (keys, members) = committee(5);
        let payload = b"artifact with every share published";
        let envelope =
            SealedEnvelope::seal(payload, AAD, &members, 3, &mut OsRng).expect("seal succeeds");

        let shares = open_all(&keys, &envelope);
        assert_eq!(shares.len(), 5);
        let opened = envelope
            .open_with_shares(&shares)
            .expect("n shares reconstruct");
        assert_eq!(opened, payload);

        // Order is not part of the reconstruction.
        let mut reversed: Vec<Share> = shares.iter().rev().map(clone_share).collect();
        reversed.truncate(4);
        assert_eq!(
            envelope
                .open_with_shares(&reversed)
                .expect("order does not matter"),
            payload
        );
    }

    /// The central adversarial case: `t-1` shares must not open the envelope,
    /// must not panic, and must not return anything the caller could mistake for
    /// a plaintext. Shamir cannot report "too few"; only the tag can.
    #[test]
    fn one_share_short_fails_authentication() {
        let (keys, members) = committee(5);
        let envelope = SealedEnvelope::seal(b"secret artifact", AAD, &members, 3, &mut OsRng)
            .expect("seal succeeds");

        let shares = open_all(&keys, &envelope);
        let two: Vec<Share> = shares.iter().take(2).map(clone_share).collect();
        match envelope.open_with_shares(&two) {
            Err(EnvelopeError::Authentication { .. }) => {}
            Err(other) => panic!("expected authentication failure, got {other:?}"),
            Ok(plaintext) => panic!("t-1 shares returned {} bytes", plaintext.len()),
        }
    }

    #[test]
    fn single_share_of_a_three_of_five_fails() {
        let (keys, members) = committee(5);
        let envelope =
            SealedEnvelope::seal(b"x", AAD, &members, 3, &mut OsRng).expect("seal succeeds");
        let shares = open_all(&keys, &envelope);
        let one: Vec<Share> = shares.iter().take(1).map(clone_share).collect();
        assert!(matches!(
            envelope.open_with_shares(&one),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    #[test]
    fn empty_share_set_is_rejected_without_panicking() {
        let (_keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"x", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        assert_eq!(envelope.open_with_shares(&[]), Err(EnvelopeError::NoShares));
    }

    /// An envelope re-labelled with a different commitment must not open, even
    /// with a full share set: the payload AEAD binds `aad`.
    #[test]
    fn rewritten_aad_fails() {
        let (keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"bound to one commitment", AAD, &members, 2, &mut OsRng)
                .expect("seal succeeds");
        let shares = open_all(&keys, &envelope);

        let mut moved = envelope.clone();
        moved.aad = OTHER_AAD.to_string();
        assert!(matches!(
            moved.open_with_shares(&shares),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    /// And the share layer binds it too, independently: a member asked to open
    /// their share out of a re-labelled envelope derives a different key.
    #[test]
    fn rewritten_aad_also_breaks_share_opening() {
        let (keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        let mut moved = envelope.clone();
        moved.aad = OTHER_AAD.to_string();

        let member = keys.first().expect("committee is non-empty");
        assert!(matches!(
            member.open_share(&moved, 1),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    #[test]
    fn tampered_payload_ciphertext_fails() {
        let (keys, members) = committee(3);
        let envelope = SealedEnvelope::seal(b"do not edit me", AAD, &members, 2, &mut OsRng)
            .expect("seal succeeds");
        let shares = open_all(&keys, &envelope);

        let mut tampered = envelope.clone();
        if let Some(byte) = tampered.ciphertext.first_mut() {
            *byte ^= 0x01;
        }
        assert!(matches!(
            tampered.open_with_shares(&shares),
            Err(EnvelopeError::Authentication { .. })
        ));

        // Truncation is tampering too.
        let mut truncated = envelope.clone();
        truncated.ciphertext.pop();
        assert!(matches!(
            truncated.open_with_shares(&shares),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    #[test]
    fn tampered_share_ciphertext_fails() {
        let (keys, members) = committee(3);
        let mut envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        if let Some(sealed) = envelope.sealed_shares.first_mut() {
            if let Some(byte) = sealed.ciphertext.first_mut() {
                *byte ^= 0xff;
            }
        }
        let member = keys.first().expect("committee is non-empty");
        assert!(matches!(
            member.open_share(&envelope, 1),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    /// A sealed share lifted out of submission A and dropped into submission B
    /// must not open. This is the replay the KDF transcript exists to stop.
    #[test]
    fn sealed_share_does_not_transplant_between_envelopes() {
        let (keys, members) = committee(3);
        let a = SealedEnvelope::seal(b"artifact A", AAD, &members, 2, &mut OsRng)
            .expect("seal A succeeds");
        let mut b = SealedEnvelope::seal(b"artifact B", OTHER_AAD, &members, 2, &mut OsRng)
            .expect("seal B succeeds");

        let lifted = a
            .sealed_share(1)
            .expect("envelope A has a share for member 1")
            .clone();
        if let Some(slot) = b.sealed_shares.first_mut() {
            *slot = lifted;
        }

        let member = keys.first().expect("committee is non-empty");
        assert!(matches!(
            member.open_share(&b, 1),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    /// Honest statement of the limit: with an *identical* `aad`, two envelopes
    /// share a share-KDF transcript, so a transplanted share does decrypt. It
    /// yields a share of the wrong content key, and the payload tag catches it.
    /// Since `aad` is the commitment hash, two distinct submissions never
    /// collide here in practice.
    #[test]
    fn transplant_under_identical_aad_is_caught_by_the_payload_tag() {
        let (keys, members) = committee(3);
        let a = SealedEnvelope::seal(b"artifact A", AAD, &members, 2, &mut OsRng)
            .expect("seal A succeeds");
        let mut b =
            SealedEnvelope::seal(b"artifact B", AAD, &members, 2, &mut OsRng).expect("seal B");

        let lifted = a.sealed_share(1).expect("share exists").clone();
        if let Some(slot) = b.sealed_shares.first_mut() {
            *slot = lifted;
        }

        let mut shares = Vec::new();
        for (i, key) in keys.iter().enumerate().take(2) {
            let index = u8::try_from(i + 1).expect("fits");
            shares.push(key.open_share(&b, index).expect("share decrypts"));
        }
        assert!(matches!(
            b.open_with_shares(&shares),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    #[test]
    fn a_member_cannot_open_another_members_share() {
        let (keys, members) = committee(4);
        let envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");

        let second = keys.get(1).expect("committee has four members");
        assert!(second.open_share(&envelope, 2).is_ok());
        for index in [1u8, 3, 4] {
            assert!(
                matches!(
                    second.open_share(&envelope, index),
                    Err(EnvelopeError::Authentication { .. })
                ),
                "member 2 must not open share {index}"
            );
        }
    }

    #[test]
    fn an_outsider_cannot_open_any_share() {
        let (_keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        let outsider = CommitteeKey::generate(&mut OsRng);
        for index in 1u8..=3 {
            assert!(matches!(
                outsider.open_share(&envelope, index),
                Err(EnvelopeError::Authentication { .. })
            ));
        }
    }

    #[test]
    fn unknown_share_index_is_reported_not_panicked() {
        let (keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        let member = keys.first().expect("committee is non-empty");
        assert_eq!(
            member.open_share(&envelope, 99),
            Err(EnvelopeError::UnknownShare { index: 99 })
        );
    }

    /// Re-addressing a sealed share to a different routing index must fail: the
    /// index is inside the KDF transcript.
    #[test]
    fn relabelled_share_index_fails() {
        let (keys, members) = committee(3);
        let mut envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        if let Some(sealed) = envelope.sealed_shares.first_mut() {
            sealed.index = 2;
        }
        let second = keys.get(1).expect("committee has three members");
        assert!(matches!(
            second.open_share(&envelope, 2),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    /// The §2 liveness fallback: a committee that never publishes its shares
    /// must not be able to destroy a submission.
    #[test]
    fn submitter_can_reveal_without_the_committee() {
        let (_keys, members) = committee(5);
        let payload = b"artifact the committee refuses to unseal";
        let (envelope, key) =
            SealedEnvelope::seal_retaining_key(payload, AAD, &members, 4, &mut OsRng)
                .expect("seal succeeds");

        assert_eq!(
            envelope
                .open_with_content_key(&key)
                .expect("submitter opens"),
            payload.to_vec()
        );

        let wrong = Secret32::random(&mut OsRng);
        assert!(matches!(
            envelope.open_with_content_key(&wrong),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    /// The retained key is still bound to the commitment: it cannot be used to
    /// open the same artifact re-labelled as somebody else's submission.
    #[test]
    fn retained_key_does_not_unbind_the_envelope() {
        let (_keys, members) = committee(3);
        let (envelope, key) =
            SealedEnvelope::seal_retaining_key(b"artifact", AAD, &members, 2, &mut OsRng)
                .expect("seal succeeds");
        let mut moved = envelope.clone();
        moved.aad = OTHER_AAD.to_string();
        assert!(matches!(
            moved.open_with_content_key(&key),
            Err(EnvelopeError::Authentication { .. })
        ));
    }

    /// Both reveal paths must agree; otherwise the fallback would settle a
    /// different artifact than the committee-driven reveal.
    #[test]
    fn both_reveal_paths_yield_the_same_plaintext() {
        let (keys, members) = committee(4);
        let payload = b"one artifact, two ways in";
        let (envelope, key) =
            SealedEnvelope::seal_retaining_key(payload, AAD, &members, 2, &mut OsRng)
                .expect("seal succeeds");
        let shares = open_all(&keys, &envelope);
        assert_eq!(
            envelope.open_with_shares(&shares).expect("committee opens"),
            envelope
                .open_with_content_key(&key)
                .expect("submitter opens")
        );
    }

    #[test]
    fn seal_rejects_bad_committees() {
        let (_keys, members) = committee(3);
        assert_eq!(
            SealedEnvelope::seal(b"x", AAD, &[], 1, &mut OsRng),
            Err(EnvelopeError::EmptyCommittee)
        );
        assert_eq!(
            SealedEnvelope::seal(b"x", AAD, &members, 0, &mut OsRng),
            Err(EnvelopeError::InvalidThreshold {
                threshold: 0,
                committee: 3
            })
        );
        assert_eq!(
            SealedEnvelope::seal(b"x", AAD, &members, 4, &mut OsRng),
            Err(EnvelopeError::InvalidThreshold {
                threshold: 4,
                committee: 3
            })
        );

        let mut duplicate_index = members.clone();
        if let Some(m) = duplicate_index.get_mut(1) {
            m.index = 1;
        }
        assert_eq!(
            SealedEnvelope::seal(b"x", AAD, &duplicate_index, 2, &mut OsRng),
            Err(EnvelopeError::DuplicateMemberIndex { index: 1 })
        );

        let mut duplicate_key = members.clone();
        let first_key = members.first().expect("non-empty").public_key;
        if let Some(m) = duplicate_key.get_mut(2) {
            m.public_key = first_key;
        }
        assert_eq!(
            SealedEnvelope::seal(b"x", AAD, &duplicate_key, 2, &mut OsRng),
            Err(EnvelopeError::DuplicateMemberKey { index: 3 })
        );
    }

    /// A planted low-order public key would give one member a share that every
    /// observer can decrypt, silently lowering the threshold.
    #[test]
    fn low_order_member_key_is_rejected() {
        let (_keys, mut members) = committee(3);
        if let Some(m) = members.get_mut(1) {
            m.public_key = [0u8; 32];
        }
        assert_eq!(
            SealedEnvelope::seal(b"x", AAD, &members, 2, &mut OsRng),
            Err(EnvelopeError::NonContributoryExchange { index: 2 })
        );
    }

    #[test]
    fn value_round_trip_is_exact() {
        let (_keys, members) = committee(4);
        let envelope = SealedEnvelope::seal(b"round trip me", AAD, &members, 3, &mut OsRng)
            .expect("seal succeeds");
        let value = envelope.to_value();
        let decoded = SealedEnvelope::from_value(&value).expect("decodes");
        assert_eq!(decoded, envelope);
        assert_eq!(decoded.to_value(), value);
        assert_eq!(decoded.digest(), envelope.digest());
    }

    #[test]
    fn round_trip_survives_json_text() {
        let (keys, members) = committee(3);
        let payload = b"artifact carried as JSON";
        let envelope =
            SealedEnvelope::seal(payload, AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        let text = envelope.to_value().canonical_string();
        let parsed = Value::from_json(&text).expect("canonical output re-parses");
        let decoded = SealedEnvelope::from_value(&parsed).expect("decodes");

        let shares = open_all(&keys, &decoded);
        assert_eq!(
            decoded.open_with_shares(&shares).expect("opens"),
            payload.to_vec()
        );
    }

    #[test]
    fn digest_changes_with_any_field() {
        let (_keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        let baseline = envelope.digest();

        let mut moved = envelope.clone();
        moved.aad = OTHER_AAD.to_string();
        assert_ne!(moved.digest(), baseline);

        let mut retimed = envelope.clone();
        retimed.threshold = 3;
        assert_ne!(retimed.digest(), baseline);
    }

    #[test]
    fn decoder_rejects_malformed_values() {
        let (_keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"payload", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        let good = envelope.to_value();

        assert_eq!(
            SealedEnvelope::from_value(&Value::Int(1)),
            Err(EnvelopeError::NotAnObject)
        );

        let rebuild = |mutate: &dyn Fn(&mut std::collections::BTreeMap<String, Value>)| {
            let mut map = good
                .as_object()
                .expect("envelope encodes to an object")
                .clone();
            mutate(&mut map);
            SealedEnvelope::from_value(&Value::Object(map))
        };

        assert_eq!(
            rebuild(&|m| {
                m.remove("nonce");
            }),
            Err(EnvelopeError::MissingField { field: "nonce" })
        );
        assert_eq!(
            rebuild(&|m| {
                m.insert("version".into(), Value::Int(2));
            }),
            Err(EnvelopeError::UnsupportedVersion { version: 2 })
        );
        assert_eq!(
            rebuild(&|m| {
                m.insert("type".into(), Value::string("commitment"));
            }),
            Err(EnvelopeError::InvalidField {
                field: "type",
                expected: "\"sealed_envelope\""
            })
        );
        assert_eq!(
            rebuild(&|m| {
                m.insert("nonce".into(), Value::string("00112233"));
            }),
            Err(EnvelopeError::WrongLength {
                field: "nonce",
                expected: NONCE_LEN,
                actual: 4
            })
        );
        assert_eq!(
            rebuild(&|m| {
                m.insert("threshold".into(), Value::Int(9));
            }),
            Err(EnvelopeError::InvalidThreshold {
                threshold: 9,
                committee: 3
            })
        );
        assert_eq!(
            rebuild(&|m| {
                m.insert("threshold".into(), Value::Int(300));
            }),
            Err(EnvelopeError::InvalidField {
                field: "threshold",
                expected: "an integer in 0..=255"
            })
        );
        assert_eq!(
            rebuild(&|m| {
                m.insert("sealed_shares".into(), Value::array([]));
            }),
            Err(EnvelopeError::EmptyCommittee)
        );

        // Duplicate routing indexes would make `sealed_share` ambiguous.
        let duplicated = {
            let mut map = good
                .as_object()
                .expect("envelope encodes to an object")
                .clone();
            let first = envelope
                .sealed_shares
                .first()
                .expect("non-empty")
                .to_value();
            map.insert("sealed_shares".into(), Value::array([first.clone(), first]));
            SealedEnvelope::from_value(&Value::Object(map))
        };
        assert_eq!(
            duplicated,
            Err(EnvelopeError::DuplicateShareIndex { index: 1 })
        );
    }

    #[test]
    fn hex_is_strict_and_lowercase() {
        assert_eq!(hex_encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(
            hex_decode("000fa5ff", "x").expect("decodes"),
            vec![0x00, 0x0f, 0xa5, 0xff]
        );
        // Uppercase would give one envelope two spellings and two digests.
        assert_eq!(
            hex_decode("00FF", "x"),
            Err(EnvelopeError::InvalidHex { field: "x" })
        );
        assert_eq!(
            hex_decode("abc", "x"),
            Err(EnvelopeError::InvalidHex { field: "x" })
        );
        assert_eq!(
            hex_decode("zz", "x"),
            Err(EnvelopeError::InvalidHex { field: "x" })
        );
        assert_eq!(
            hex_decode("", "x").expect("empty is empty"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn debug_never_prints_secret_material() {
        let key = CommitteeKey::generate(&mut OsRng);
        let exported = key.to_bytes();
        let secret_hex = hex_encode(exported.expose());

        let rendered = format!("{key:?}");
        assert!(!rendered.contains(&secret_hex), "CommitteeKey Debug leaked");
        assert!(rendered.contains("<redacted>"));

        let rendered = format!("{exported:?}");
        assert!(!rendered.contains(&secret_hex), "Secret32 Debug leaked");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn stored_key_round_trips() {
        let key = CommitteeKey::generate(&mut OsRng);
        let restored = CommitteeKey::from_bytes(*key.to_bytes().expose());
        assert_eq!(restored.public(), key.public());
    }

    #[test]
    fn empty_payload_seals_and_opens() {
        let (keys, members) = committee(3);
        let envelope =
            SealedEnvelope::seal(b"", AAD, &members, 2, &mut OsRng).expect("seal succeeds");
        let shares = open_all(&keys, &envelope);
        assert_eq!(
            envelope.open_with_shares(&shares).expect("opens"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn one_of_one_committee_works() {
        let (keys, members) = committee(1);
        let envelope = SealedEnvelope::seal(b"single custodian", AAD, &members, 1, &mut OsRng)
            .expect("seal succeeds");
        let shares = open_all(&keys, &envelope);
        assert_eq!(
            envelope.open_with_shares(&shares).expect("opens"),
            b"single custodian".to_vec()
        );
    }

    #[test]
    fn two_seals_of_one_payload_differ() {
        // Envelopes are randomized, so an observer cannot tell two submissions
        // carry the same artifact by comparing ciphertexts.
        let (_keys, members) = committee(3);
        let a = SealedEnvelope::seal(b"same artifact", AAD, &members, 2, &mut OsRng)
            .expect("seal succeeds");
        let b = SealedEnvelope::seal(b"same artifact", AAD, &members, 2, &mut OsRng)
            .expect("seal succeeds");
        assert_ne!(a.ciphertext(), b.ciphertext());
        assert_ne!(a.digest(), b.digest());
    }
}
