//! Pseudonymous submitter identity: per-objective signing keys derived from one
//! seed, and detached signatures over canonical record bytes.
//!
//! # Why this exists
//!
//! Encryption hides *what* was submitted. Against an adversary who wants to know
//! **who is working on X**, hiding *who* is the property that matters, and it is
//! the harder one (`docs/censorship.md` §3). The cheapest layer that actually
//! defeats routine analysis is a **fresh signing key per objective**, so activity
//! on one objective cannot be linked to activity on another. That is what
//! [`MasterSeed::pseudonym`] produces.
//!
//! Deriving those keys rather than generating them independently is what makes
//! the scheme usable. A submitter who loses a per-objective key loses the ability
//! to speak for that pseudonym — to answer a challenge, to claim a payout, to
//! sign a follow-up claim. Derivation means the key is never stored, only
//! recomputed: one backed-up seed recovers every objective the holder has ever
//! worked on, including ones they have forgotten.
//!
//! # The tradeoff this module does not paper over
//!
//! **This gives per-objective unlinkability. It does not give anonymity.** The
//! difference is not academic, and `docs/censorship.md` §3 states the reason it
//! cannot be engineered away:
//!
//! > **Citation flow requires linkage.** If your claim cites mine and value flows
//! > to me, the graph connecting us is public *by construction* — that graph is
//! > the attribution mechanism.
//!
//! Concretely, after every layer in this module is applied, an observer still
//! sees:
//!
//! - **the pseudonym graph** — which pseudonym cited which, and therefore which
//!   pseudonyms are paying which. Hiding it would mean deleting attribution,
//!   which is what the network is for;
//! - **timing and volume** — which objectives received submissions, how many,
//!   when, and roughly how large (§4). Fixed-size envelopes and batch-boundary
//!   publication narrow this; only cover traffic defeats a global observer, and
//!   nobody wants to pay for cover traffic;
//! - **repeat submissions to one objective**, which share a pseudonym by
//!   construction: derivation is deterministic, so two submissions to the same
//!   `objective_id` from the same seed are trivially linked *to each other*. They
//!   are just not linked to that seed's activity elsewhere.
//!
//! So the honest statement of what a participant gets is: *an observer without
//! your seed cannot tell that the pseudonym on objective A and the pseudonym on
//! objective B are the same person; an observer can still see everything either
//! pseudonym did, and can still follow the money between pseudonyms.*
//!
//! A participant who wants **maximal anonymity** must go further: a throwaway
//! [`Identity::generate`] per submission, never cited, with a fresh payout
//! address. That forfeits citation income, because being paid for being built
//! upon requires a stable identity to be built upon. The system should let people
//! choose that explicitly rather than discover it after the fact, which is why
//! both constructors exist here and why this paragraph is in the docs rather than
//! in a footnote.
//!
//! # Seed compromise is retroactive, total, and deliberate
//!
//! One seed derives every pseudonym. Someone who obtains it can (a) link the
//! holder's entire history across every objective, retroactively, and (b) forge
//! signatures for all of those pseudonyms, including future ones. Independent
//! random keys would not have property (a).
//!
//! That is a real cost, accepted for a reason: the alternative is a key store
//! that must be backed up as it grows, and the failure mode of *that* design —
//! losing the key for work already committed — is the same censorship outcome
//! this whole subsystem exists to prevent (§1: work done, verified in principle,
//! unpaid). A seizure is a targeted attack; key loss is an accident, and
//! accidents happen more often. Holders who disagree with that tradeoff for a
//! particular objective should use [`Identity::generate`] and store the result
//! themselves.
//!
//! Because derivation is deterministic and objective ids are public, a *guessed*
//! seed is verifiable: an adversary who can enumerate candidate seeds can confirm
//! a hit by re-deriving a published public key. The seed must therefore come from
//! a CSPRNG ([`MasterSeed::generate`]) and never from a passphrase.
//!
//! # Why signatures are over canonical bytes
//!
//! A signature is a statement about *bytes*. Two parties who serialize the same
//! record differently sign different statements, and the network then disagrees
//! about who said what — the same class of failure `canonical.rs` exists to
//! prevent for content addressing. [`Identity::sign_value`] therefore signs
//! [`Value::canonical_bytes`] and nothing else, and a verifier re-canonicalizes
//! rather than trusting the byte string it was handed.
//!
//! **Cross-protocol hazard.** By construction `sign_value(v)` is exactly
//! `sign_bytes(v.canonical_bytes())`. There is no domain separator between the
//! two, because adding one would mean this crate's signatures could not be
//! checked by an implementation that follows the plain "sign the canonical bytes"
//! rule. The consequence is that [`Identity::sign_bytes`] must never be exposed
//! as a blind signing oracle: bytes that happen to be a canonical record are a
//! signature on that record. Callers who need a general-purpose signing service
//! should prefix their own domain string into the message.
//!
//! # Verification is strict, on purpose
//!
//! Verification uses `verify_strict`, which rejects small-order public keys and
//! non-canonical signature components. Plain ed25519 verification accepts
//! signatures that different implementations judge differently; in a system where
//! a signature decides whether a settlement is legitimate, two honest nodes
//! reaching opposite verdicts on the same bytes is a consensus fault. Strictness
//! costs a little compatibility with sloppy signers and buys agreement.
//!
//! # What this module does not do
//!
//! - It does not prove *authorization*. [`SignedRecord::verify`] proves that the
//!   holder of a key signed some bytes; whether that key is allowed to say that
//!   is a question for the record layer. See the note on
//!   [`SignedRecord::verify_signed_by`].
//! - It does not provide zero-knowledge submission (§3, layer 3), which is what
//!   would hide *which* commitment a submitter is claiming.
//! - It does nothing about coercion of a participant whose name is already known
//!   (§7), and nothing about the network layer (§5).
//!
//! # Timing
//!
//! Secret-dependent work is either delegated to `ed25519-dalek` (constant-time
//! scalar arithmetic, constant-time secret comparison) or data-independent (the
//! SHA-256 compression in the private `hmac_sha256` helper runs over fixed-size
//! blocks and takes no secret-dependent branch). The hex and equality helpers are
//! **not** constant time and are applied only to public values — public keys,
//! signatures, digests. No secret is ever hex-encoded, which is why [`MasterSeed`]
//! and [`Identity`] expose their bytes only through self-wiping wrappers and
//! never through `Display`.

use core::fmt;

use ed25519_dalek::{Signature as DalekSignature, Signer as _, SigningKey, VerifyingKey};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::canonical::Value;

/// Wire type tag, so a decoder cannot confuse a signed record with another
/// object that happens to share field names.
const RECORD_TYPE: &str = "signed_record";

/// Wire version. An unknown version is refused rather than guessed at.
const VERSION: i128 = 1;

const KEY_LEN: usize = 32;
const SEED_LEN: usize = 32;
const SIG_LEN: usize = 64;

/// Domain separator for pseudonym derivation.
///
/// A hash used for two purposes in one protocol is a hash used wrongly. The
/// string is a fixed-length constant, so `DOMAIN || objective_id` is injective in
/// `objective_id` and no length prefix is needed to stop two different objective
/// ids deriving one key. If this constant ever becomes caller-controlled, that
/// argument dies and a length prefix becomes mandatory.
const PSEUDONYM_DOMAIN: &[u8] = b"proofwork/censorship/identity/pseudonym/v1";

// -- errors ----------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// A record that should have been an object was not one.
    NotAnObject,
    MissingField {
        field: &'static str,
    },
    InvalidField {
        field: &'static str,
        expected: &'static str,
    },
    /// Hex that is not strict lowercase hex, or has an odd length.
    InvalidHex {
        field: &'static str,
    },
    WrongLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    UnsupportedVersion {
        version: i128,
    },
    /// The 32 bytes are not a usable ed25519 public key: they do not decompress
    /// to a curve point, or the point has small order and verifies against
    /// signatures nobody had to know a secret to produce.
    InvalidPublicKey,
    /// The signature does not verify. Deliberately one variant: a forged
    /// signature, a tampered record and a mismatched key are indistinguishable
    /// from the outside and reporting them separately would invent a distinction
    /// the cryptography does not support.
    BadSignature,
    /// The signature is valid but was made by a different key than the caller
    /// required. Distinct from [`IdentityError::BadSignature`] because the
    /// remedy is different: this one means "authentic, but not from who you
    /// wanted", which is an authorization failure, not a forgery.
    WrongSigner {
        expected: String,
        actual: String,
    },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::NotAnObject => write!(f, "expected a JSON object"),
            IdentityError::MissingField { field } => write!(f, "missing field `{field}`"),
            IdentityError::InvalidField { field, expected } => {
                write!(f, "field `{field}` must be {expected}")
            }
            IdentityError::InvalidHex { field } => {
                write!(f, "field `{field}` must be lowercase hex of even length")
            }
            IdentityError::WrongLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "field `{field}` must decode to {expected} bytes, got {actual}"
            ),
            IdentityError::UnsupportedVersion { version } => {
                write!(f, "unsupported signed-record version {version}")
            }
            IdentityError::InvalidPublicKey => {
                write!(f, "not a usable ed25519 public key")
            }
            IdentityError::BadSignature => write!(f, "signature does not verify"),
            IdentityError::WrongSigner { expected, actual } => {
                write!(f, "signed by {actual}, but {expected} was required")
            }
        }
    }
}

impl std::error::Error for IdentityError {}

// -- master seed -----------------------------------------------------------

/// The root secret from which every pseudonym is derived.
///
/// Deliberately not `Clone`: duplicating the one secret that links a
/// participant's entire history should be an explicit act, spelled
/// `MasterSeed::from_bytes(*seed.to_bytes())`, not an incidental `.clone()` in a
/// data structure.
///
/// Deliberately no `to_value`/`from_value` either. Every other type here has one
/// because it goes on the wire; this one has none because it must not, and the
/// absence of a serializer is the cheapest way to say so.
pub struct MasterSeed([u8; SEED_LEN]);

impl MasterSeed {
    /// Draw a seed from a cryptographic RNG.
    ///
    /// The only supported way to create a *new* seed. Derivation is deterministic
    /// and objective ids are public, so a low-entropy seed (a passphrase, a
    /// counter) can be confirmed by re-deriving a published public key — the
    /// pseudonyms would be linkable to anyone willing to guess.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> MasterSeed {
        let mut bytes = [0u8; SEED_LEN];
        rng.fill_bytes(&mut bytes);
        let seed = MasterSeed(bytes);
        bytes.zeroize();
        seed
    }

    /// Restore a seed from backup. Every 32-byte string is a valid seed, so there
    /// is nothing to reject; entropy is the caller's responsibility and
    /// [`MasterSeed::generate`] is the way to discharge it.
    pub fn from_bytes(bytes: [u8; SEED_LEN]) -> MasterSeed {
        MasterSeed(bytes)
    }

    /// Export for backup. The wrapper wipes itself on drop, which is the whole
    /// reason this does not return a bare `[u8; 32]`: handing out raw bytes
    /// silently moves the wiping obligation onto code with no reason to remember
    /// it.
    pub fn to_bytes(&self) -> Zeroizing<[u8; SEED_LEN]> {
        Zeroizing::new(self.0)
    }

    /// Deterministically derive the unlinkable signing identity for one objective.
    ///
    /// `HMAC-SHA256(seed, DOMAIN || objective_id)`, interpreted as an ed25519
    /// secret key. HMAC rather than a bare hash because the seed is the key here:
    /// with a plain `H(seed || id)` an attacker who learns any derived key learns
    /// nothing extra, but length-extension of the *seed* becomes a property of
    /// the construction rather than an assumption, and there is no reason to take
    /// that on.
    ///
    /// Deterministic in both directions: the holder can always recompute a key
    /// they never stored, and anyone *without* the seed sees 32 bytes
    /// indistinguishable from random and cannot tell two pseudonyms belong to one
    /// person. Two calls with the same `objective_id` return the same key by
    /// design — repeat submissions to one objective are linkable to each other
    /// (see the module docs), just not to that seed's activity elsewhere.
    ///
    /// Every 32-byte string is a valid ed25519 secret key — it is hashed and
    /// clamped before use — so this cannot fail and does not return `Result`.
    pub fn pseudonym(&self, objective_id: &str) -> Identity {
        let mut message =
            Vec::with_capacity(PSEUDONYM_DOMAIN.len().saturating_add(objective_id.len()));
        message.extend_from_slice(PSEUDONYM_DOMAIN);
        message.extend_from_slice(objective_id.as_bytes());
        // `message` is public: a fixed domain string and an objective id that is
        // on the log. Only the HMAC key and its output are secret.
        let secret = hmac_sha256(&self.0, &message);
        Identity {
            signing: SigningKey::from_bytes(&secret),
        }
    }
}

impl Zeroize for MasterSeed {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for MasterSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl ZeroizeOnDrop for MasterSeed {}

/// Redacted, with no fingerprint.
///
/// Printing even a hash of the seed would publish a stable identifier for the
/// one object that links every pseudonym a participant owns, which is precisely
/// the linkage this module exists to withhold.
impl fmt::Debug for MasterSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterSeed(<redacted>)")
    }
}

// -- public key ------------------------------------------------------------

/// An ed25519 public key as bytes: a pseudonym's public name.
///
/// A newtype rather than a bare `[u8; 32]` so that a public key cannot be passed
/// where a seed, a share, or a content key is expected. All of them are 32 bytes
/// and only one of them is safe to print.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifyingKeyBytes([u8; KEY_LEN]);

impl VerifyingKeyBytes {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> VerifyingKeyBytes {
        VerifyingKeyBytes(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; KEY_LEN] {
        self.0
    }

    /// Lowercase hex. This is the submitter id used in records.
    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    pub fn from_hex(text: &str) -> Result<VerifyingKeyBytes, IdentityError> {
        Ok(VerifyingKeyBytes(hex_fixed::<KEY_LEN>(text, "public_key")?))
    }

    /// Whether these bytes are a public key that can meaningfully verify anything.
    ///
    /// False for bytes that do not decompress to a curve point and for
    /// small-order points, which verify signatures that anyone can produce
    /// without knowing a secret. Checking at parse time turns a would-be
    /// authentication bypass into a decoding error.
    pub fn is_usable(&self) -> bool {
        match VerifyingKey::from_bytes(&self.0) {
            Ok(key) => !key.is_weak(),
            Err(_) => false,
        }
    }

    pub fn to_value(&self) -> Value {
        Value::string(self.to_hex())
    }

    pub fn from_value(value: &Value) -> Result<VerifyingKeyBytes, IdentityError> {
        let text = value.as_str().ok_or(IdentityError::InvalidField {
            field: "public_key",
            expected: "a hex string",
        })?;
        VerifyingKeyBytes::from_hex(text)
    }
}

/// Public data, printed in full: a pseudonym's public key is exactly what an
/// operator needs to see in a log line to match it against a record.
impl fmt::Debug for VerifyingKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifyingKeyBytes({})", self.to_hex())
    }
}

impl fmt::Display for VerifyingKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl From<[u8; KEY_LEN]> for VerifyingKeyBytes {
    fn from(bytes: [u8; KEY_LEN]) -> VerifyingKeyBytes {
        VerifyingKeyBytes(bytes)
    }
}

// -- identity --------------------------------------------------------------

/// One pseudonym: an ed25519 signing key and the public name derived from it.
///
/// Secret material is wiped on drop — `SigningKey` zeroizes itself — so an
/// `Identity` that goes out of scope leaves no key in the stack frame. Like
/// [`MasterSeed`] it has no wire form; what travels is its
/// [`VerifyingKeyBytes`].
#[derive(Clone)]
pub struct Identity {
    signing: SigningKey,
}

/// Sound because the only field wipes itself on drop; declared so the guarantee
/// is visible in the type system rather than inherited silently from a
/// dependency's feature flag.
impl ZeroizeOnDrop for Identity {}

impl Identity {
    /// A standalone identity with no derivation path.
    ///
    /// This is the "maximal anonymity" constructor: nothing links it to a seed or
    /// to any other identity, and nothing recovers it if the caller loses the
    /// bytes. Use it for a throwaway pseudonym that will never be cited — and see
    /// the module docs on what that costs, because a pseudonym nobody can
    /// attribute work to is a pseudonym nobody can pay.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Identity {
        Identity {
            signing: SigningKey::generate(rng),
        }
    }

    /// Reload a stored identity. Every 32-byte string is a valid ed25519 secret
    /// key, so there is nothing to reject.
    pub fn from_secret_bytes(bytes: [u8; KEY_LEN]) -> Identity {
        Identity {
            signing: SigningKey::from_bytes(&bytes),
        }
    }

    /// Export for storage. Self-wiping, for the same reason as
    /// [`MasterSeed::to_bytes`]. Identities from [`MasterSeed::pseudonym`] never
    /// need this: they are recomputed from the seed.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    pub fn public(&self) -> VerifyingKeyBytes {
        VerifyingKeyBytes(self.signing.verifying_key().to_bytes())
    }

    /// The submitter id as it appears in records: lowercase hex of the public key.
    ///
    /// This string is what [`crate::records::commitment_hash`] binds a commitment
    /// to, which is what stops an observer replaying someone else's commitment
    /// under their own name. Identity and commitment are therefore the same fact,
    /// and the pseudonym is the unit of attribution.
    pub fn submitter_id(&self) -> String {
        self.public().to_hex()
    }

    /// Sign a record. The signed message is the record's canonical encoding, so
    /// any two implementations sign the same bytes for the same record.
    pub fn sign_value(&self, value: &Value) -> Signature {
        self.sign_bytes(&value.canonical_bytes())
    }

    /// Sign arbitrary bytes.
    ///
    /// See the cross-protocol note in the module docs: this is deliberately *not*
    /// domain-separated from [`Identity::sign_value`], so never offer it as a
    /// signing oracle over attacker-chosen input.
    pub fn sign_bytes(&self, message: &[u8]) -> Signature {
        match self.signing.try_sign(message) {
            Ok(signature) => Signature(signature.to_bytes()),
            // `SigningKey::try_sign` returns `Ok(..)` unconditionally in
            // ed25519-dalek 2.x; there is no failure path today. The arm is
            // handled rather than `.expect()`-ed because a library that panics on
            // an impossible case panics in production the day a dependency adds
            // one. An all-zero signature has a small-order `R`, which
            // `verify_strict` rejects under every key, so a signature that could
            // not be produced fails loudly at the first verification instead of
            // being mistaken for a valid one.
            Err(_) => Signature([0u8; SIG_LEN]),
        }
    }
}

/// Redacted. The public key is printed because it is public and is the only part
/// worth logging; the secret half is never formatted anywhere in this crate.
impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("public", &self.public().to_hex())
            .field("secret", &"<redacted>")
            .finish()
    }
}

// -- signature -------------------------------------------------------------

/// A detached ed25519 signature.
///
/// Comparison is a plain byte comparison and is not constant time. Signatures are
/// public, so there is no secret for a timing difference to leak.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; SIG_LEN]);

impl Signature {
    pub fn from_bytes(bytes: [u8; SIG_LEN]) -> Signature {
        Signature(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SIG_LEN] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; SIG_LEN] {
        self.0
    }

    pub fn to_hex(&self) -> String {
        hex_encode(&self.0)
    }

    pub fn from_hex(text: &str) -> Result<Signature, IdentityError> {
        Ok(Signature(hex_fixed::<SIG_LEN>(text, "signature")?))
    }

    pub fn to_value(&self) -> Value {
        Value::string(self.to_hex())
    }

    pub fn from_value(value: &Value) -> Result<Signature, IdentityError> {
        let text = value.as_str().ok_or(IdentityError::InvalidField {
            field: "signature",
            expected: "a hex string",
        })?;
        Signature::from_hex(text)
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({})", self.to_hex())
    }
}

// -- verification ----------------------------------------------------------

/// Verify a signature over a record's canonical encoding.
///
/// The record is re-canonicalized here rather than trusted as bytes, so a peer
/// cannot get a signature accepted over one byte string while the rest of the
/// network stores a different one.
pub fn verify_value(
    public: &[u8; KEY_LEN],
    value: &Value,
    signature: &Signature,
) -> Result<(), IdentityError> {
    verify_bytes(public, &value.canonical_bytes(), signature)
}

/// Verify a signature over raw bytes.
///
/// Uses `verify_strict`: small-order public keys and non-canonical signature
/// components are rejected, so two honest verifiers cannot reach opposite
/// verdicts on the same input (see the module docs).
pub fn verify_bytes(
    public: &[u8; KEY_LEN],
    message: &[u8],
    signature: &Signature,
) -> Result<(), IdentityError> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| IdentityError::InvalidPublicKey)?;
    if key.is_weak() {
        // A small-order key verifies signatures that require no secret. Treating
        // that as a valid signature would be an authentication bypass, so it is a
        // key error rather than a signature error.
        return Err(IdentityError::InvalidPublicKey);
    }
    let parsed = DalekSignature::from_bytes(&signature.0);
    key.verify_strict(message, &parsed)
        .map_err(|_| IdentityError::BadSignature)
}

// -- signed record ---------------------------------------------------------

/// A record with the pseudonym that signed it.
///
/// Every field is public data, so `Debug` prints all of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRecord {
    pub record: Value,
    pub public_key: [u8; KEY_LEN],
    pub signature: Signature,
}

impl SignedRecord {
    pub fn sign(identity: &Identity, record: Value) -> SignedRecord {
        let signature = identity.sign_value(&record);
        SignedRecord {
            record,
            public_key: identity.public().to_bytes(),
            signature,
        }
    }

    /// Check that `public_key` signed `record`.
    ///
    /// This is **authentication, not authorization**. It answers "did the holder
    /// of this key sign these bytes", and says nothing about whether that key was
    /// entitled to. A record whose own `submitter` field names someone else still
    /// passes here, because a validator co-signing another party's record is a
    /// legitimate shape and this type cannot tell the two apart. Callers binding a
    /// record to its author must compare [`SignedRecord::submitter_id`] against
    /// the record's own field, or use [`SignedRecord::verify_signed_by`].
    pub fn verify(&self) -> Result<(), IdentityError> {
        verify_value(&self.public_key, &self.record, &self.signature)
    }

    /// Verify, and require a specific signer.
    ///
    /// The one-call safe path when the caller already knows which pseudonym must
    /// have signed. The key is checked first so that a valid signature from the
    /// wrong key reports [`IdentityError::WrongSigner`] rather than a misleading
    /// `BadSignature`.
    pub fn verify_signed_by(&self, expected: &[u8; KEY_LEN]) -> Result<(), IdentityError> {
        if &self.public_key != expected {
            return Err(IdentityError::WrongSigner {
                expected: hex_encode(expected),
                actual: hex_encode(&self.public_key),
            });
        }
        self.verify()
    }

    pub fn public(&self) -> VerifyingKeyBytes {
        VerifyingKeyBytes(self.public_key)
    }

    /// The signer's submitter id, in the same form records use.
    pub fn submitter_id(&self) -> String {
        hex_encode(&self.public_key)
    }

    /// Wire form.
    ///
    /// Only `record` is inside the signature. `type` and `version` travel outside
    /// it, which is safe in the same way structural fields are elsewhere in this
    /// layer: editing them can only make the wrapper fail to decode or fail to
    /// verify, never produce a different authenticated record.
    pub fn to_value(&self) -> Value {
        Value::object([
            ("type", Value::string(RECORD_TYPE)),
            ("version", Value::Int(VERSION)),
            ("record", self.record.clone()),
            ("public_key", Value::string(hex_encode(&self.public_key))),
            ("signature", self.signature.to_value()),
        ])
    }

    pub fn from_value(value: &Value) -> Result<SignedRecord, IdentityError> {
        if value.as_object().is_none() {
            return Err(IdentityError::NotAnObject);
        }
        match value.get("type") {
            None => return Err(IdentityError::MissingField { field: "type" }),
            Some(Value::String(tag)) if tag.as_str() == RECORD_TYPE => {}
            Some(_) => {
                return Err(IdentityError::InvalidField {
                    field: "type",
                    expected: "\"signed_record\"",
                })
            }
        }
        let version = value
            .get("version")
            .ok_or(IdentityError::MissingField { field: "version" })?
            .as_i128()
            .ok_or(IdentityError::InvalidField {
                field: "version",
                expected: "an integer",
            })?;
        if version != VERSION {
            return Err(IdentityError::UnsupportedVersion { version });
        }

        // Any `Value` can be signed, including a bare string or null, so the
        // record is taken as-is. Its shape is the record layer's business; all
        // this type guarantees is that the signature covers exactly what round
        // trips back out.
        let record = value
            .get("record")
            .ok_or(IdentityError::MissingField { field: "record" })?
            .clone();

        let public_key = hex_fixed::<KEY_LEN>(field_str(value, "public_key")?, "public_key")?;
        let signature = Signature(hex_fixed::<SIG_LEN>(
            field_str(value, "signature")?,
            "signature",
        )?);

        Ok(SignedRecord {
            record,
            public_key,
            signature,
        })
    }
}

// -- HMAC ------------------------------------------------------------------

/// HMAC-SHA256, RFC 2104.
///
/// Implemented here rather than through the `hmac` crate for one reason: that
/// crate's constructor returns `Result`, and this crate forbids panics in library
/// code. `MasterSeed::pseudonym` is infallible by design — a fallible key
/// derivation would force every caller to handle an error that cannot happen —
/// so the alternatives were `.expect()` (a panic in production the day the
/// dependency changes) or an invented fallback (a *silently different* key, which
/// is worse than a crash). Keying a hash is small enough to own outright.
///
/// Correctness is pinned two ways in the tests below: the RFC 4231 vectors, and a
/// differential check against the `hmac` crate, which is a normal dependency and
/// perfectly usable where panics are allowed.
///
/// No branch depends on the key's *value*; the only data-dependent path is the
/// key-length case, and key length is not secret.
fn hmac_sha256(key: &[u8], message: &[u8]) -> Zeroizing<[u8; 32]> {
    const BLOCK: usize = 64;
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    let mut block = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        // A key longer than the block is replaced by its digest. SHA-256's
        // 32-byte output always fits, and `zip` truncates rather than panicking
        // if that ever stops being true.
        let mut digest = Sha256::digest(key);
        for (dst, src) in block.iter_mut().zip(digest.iter()) {
            *dst = *src;
        }
        Zeroize::zeroize(&mut digest[..]);
    } else {
        for (dst, src) in block.iter_mut().zip(key.iter()) {
            *dst = *src;
        }
    }

    let mut inner_pad = Zeroizing::new(*block);
    let mut outer_pad = Zeroizing::new(*block);
    for byte in inner_pad.iter_mut() {
        *byte ^= IPAD;
    }
    for byte in outer_pad.iter_mut() {
        *byte ^= OPAD;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad.as_slice());
    inner.update(message);
    let mut inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad.as_slice());
    outer.update(inner_digest.as_slice());
    let mut outer_digest = outer.finalize();

    let mut out = Zeroizing::new([0u8; 32]);
    for (dst, src) in out.iter_mut().zip(outer_digest.iter()) {
        *dst = *src;
    }

    // The pads wipe themselves; the digest buffers are the copies nobody else
    // owns.
    Zeroize::zeroize(&mut inner_digest[..]);
    Zeroize::zeroize(&mut outer_digest[..]);
    out
}

// -- hex and field decoding ------------------------------------------------

/// Lowercase hex.
///
/// One encoder, in [`crate::hex`]: a second copy here would be a second thing
/// that could disagree with the spelling of a published key. Kept as a local
/// alias because every call site in this module reads as `hex_encode(..)` and
/// the indirection is free.
///
/// **Not constant time**: it branches per nibble. Every value it is applied to —
/// public keys, signatures — is published, and no secret in this module has a hex
/// or `Display` form precisely so that this function cannot be pointed at one.
fn hex_encode(bytes: &[u8]) -> String {
    crate::hex::encode(bytes)
}

/// Strict decoder: lowercase only, exact length.
///
/// Uppercase is refused rather than normalized. Accepting both spellings would
/// give one signed record two encodings and therefore two digests, which is the
/// disagreement `canonical.rs` exists to prevent.
fn hex_fixed<const N: usize>(text: &str, field: &'static str) -> Result<[u8; N], IdentityError> {
    if text.len() != N.saturating_mul(2) {
        return Err(IdentityError::WrongLength {
            field,
            expected: N,
            // Report decoded length where the input is well formed, so the
            // message is about bytes rather than characters.
            actual: text.len() / 2,
        });
    }
    let mut out = [0u8; N];
    let mut high: Option<u8> = None;
    let mut written = 0usize;
    for byte in text.bytes() {
        let nibble = hex_value(byte).ok_or(IdentityError::InvalidHex { field })?;
        match high.take() {
            None => high = Some(nibble),
            Some(h) => {
                match out.get_mut(written) {
                    Some(slot) => *slot = (h << 4) | nibble,
                    // Unreachable: the length was checked above. Bounds-checked
                    // anyway so the function has no indexing panic at all.
                    None => return Err(IdentityError::InvalidHex { field }),
                }
                written = written.saturating_add(1);
            }
        }
    }
    if high.is_some() || written != N {
        return Err(IdentityError::InvalidHex { field });
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

fn field_str<'a>(value: &'a Value, field: &'static str) -> Result<&'a str, IdentityError> {
    value
        .get(field)
        .ok_or(IdentityError::MissingField { field })?
        .as_str()
        .ok_or(IdentityError::InvalidField {
            field,
            expected: "a string",
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use rand_core::OsRng;

    const OBJECTIVE_A: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const OBJECTIVE_B: &str =
        "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn seed(fill: u8) -> MasterSeed {
        MasterSeed::from_bytes([fill; SEED_LEN])
    }

    fn record() -> Value {
        crate::obj! {
            "type" => Value::string("claim"),
            "objective_id" => Value::string(OBJECTIVE_A),
            "artifact" => crate::obj!{ "answer" => Value::Int(42) },
            "cites" => Value::array([Value::string("sha256:abcd")]),
        }
    }

    // -- derivation --------------------------------------------------------

    #[test]
    fn pseudonyms_differ_across_objectives() {
        let master = seed(7);
        let a = master.pseudonym(OBJECTIVE_A);
        let b = master.pseudonym(OBJECTIVE_B);
        assert_ne!(a.public(), b.public());
        // The whole point of §3 layer 1: nothing about A's key reveals B's.
        assert_ne!(a.submitter_id(), b.submitter_id());
    }

    #[test]
    fn pseudonym_is_stable_for_one_objective() {
        let master = seed(7);
        assert_eq!(
            master.pseudonym(OBJECTIVE_A).public(),
            master.pseudonym(OBJECTIVE_A).public()
        );
        // ... and across process restarts, modelled by rebuilding the seed.
        let restored = MasterSeed::from_bytes([7u8; SEED_LEN]);
        assert_eq!(
            master.pseudonym(OBJECTIVE_A).public(),
            restored.pseudonym(OBJECTIVE_A).public()
        );
    }

    #[test]
    fn different_seeds_give_different_pseudonyms() {
        assert_ne!(
            seed(7).pseudonym(OBJECTIVE_A).public(),
            seed(8).pseudonym(OBJECTIVE_A).public()
        );
    }

    #[test]
    fn a_one_bit_seed_change_changes_the_pseudonym() {
        let mut bytes = [0u8; SEED_LEN];
        let first = MasterSeed::from_bytes(bytes)
            .pseudonym(OBJECTIVE_A)
            .public();
        bytes[SEED_LEN - 1] = 1;
        let second = MasterSeed::from_bytes(bytes)
            .pseudonym(OBJECTIVE_A)
            .public();
        assert_ne!(first, second);
    }

    #[test]
    fn objective_ids_are_not_confusable_by_concatenation() {
        // A derivation that hashed `domain || id` with a *variable* domain could
        // collide these. With a fixed-length domain it cannot; the test pins that
        // property so a future refactor of PSEUDONYM_DOMAIN cannot quietly break
        // it.
        let master = seed(3);
        assert_ne!(
            master.pseudonym("ab").public(),
            master.pseudonym("a").public()
        );
        assert_ne!(
            master.pseudonym("").public(),
            master.pseudonym(" ").public()
        );
    }

    #[test]
    fn derived_keys_survive_a_seed_round_trip() {
        let master = MasterSeed::generate(&mut OsRng);
        let backup = master.to_bytes();
        let restored = MasterSeed::from_bytes(*backup);
        assert_eq!(
            master.pseudonym(OBJECTIVE_A).public(),
            restored.pseudonym(OBJECTIVE_A).public()
        );
    }

    #[test]
    fn generated_seeds_differ() {
        assert_ne!(
            MasterSeed::generate(&mut OsRng)
                .pseudonym(OBJECTIVE_A)
                .public(),
            MasterSeed::generate(&mut OsRng)
                .pseudonym(OBJECTIVE_A)
                .public()
        );
    }

    // -- signing and verification -----------------------------------------

    #[test]
    fn sign_and_verify_round_trip() {
        let id = seed(1).pseudonym(OBJECTIVE_A);
        let value = record();
        let signature = id.sign_value(&value);
        assert!(verify_value(id.public().as_bytes(), &value, &signature).is_ok());
    }

    #[test]
    fn sign_bytes_round_trip() {
        let id = Identity::generate(&mut OsRng);
        let signature = id.sign_bytes(b"epoch 12 attestation");
        assert!(verify_bytes(id.public().as_bytes(), b"epoch 12 attestation", &signature).is_ok());
        assert_eq!(
            verify_bytes(id.public().as_bytes(), b"epoch 13 attestation", &signature),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn signing_a_value_is_signing_its_canonical_bytes() {
        // Documented equivalence, and the reason sign_bytes must never be a blind
        // oracle. If this ever stops holding, the cross-protocol warning in the
        // module docs is wrong and must be updated.
        let id = seed(2).pseudonym(OBJECTIVE_A);
        let value = record();
        assert_eq!(
            id.sign_value(&value),
            id.sign_bytes(&value.canonical_bytes())
        );
    }

    #[test]
    fn key_order_does_not_change_the_signature() {
        // Two peers writing the same record with different key order must produce
        // one signature, or the network disagrees about who said what.
        let id = seed(2).pseudonym(OBJECTIVE_A);
        let first = Value::from_json(r#"{"a":1,"b":2,"z":{"y":1,"x":2}}"#).expect("valid json");
        let second = Value::from_json(r#"{"z":{"x":2,"y":1},"b":2,"a":1}"#).expect("valid json");
        assert_eq!(first.canonical_bytes(), second.canonical_bytes());
        let signature = id.sign_value(&first);
        assert!(verify_value(id.public().as_bytes(), &second, &signature).is_ok());
    }

    #[test]
    fn tampered_record_fails_verification() {
        let id = seed(1).pseudonym(OBJECTIVE_A);
        let value = record();
        let signature = id.sign_value(&value);

        let tampered = crate::obj! {
            "type" => Value::string("claim"),
            "objective_id" => Value::string(OBJECTIVE_A),
            "artifact" => crate::obj!{ "answer" => Value::Int(43) },
            "cites" => Value::array([Value::string("sha256:abcd")]),
        };
        assert_eq!(
            verify_value(id.public().as_bytes(), &tampered, &signature),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn added_field_fails_verification() {
        // Adding a field is the cheap attack: the original fields still match, so
        // a naive "check the fields I care about" verifier would accept it.
        let id = seed(1).pseudonym(OBJECTIVE_A);
        let value = record();
        let signature = id.sign_value(&value);

        let mut extended = match value.clone() {
            Value::Object(map) => map,
            _ => unreachable!("record() builds an object"),
        };
        extended.insert("payout_to".to_string(), Value::string("attacker"));
        assert_eq!(
            verify_value(id.public().as_bytes(), &Value::Object(extended), &signature),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn signature_from_one_key_fails_against_another() {
        let mine = seed(1).pseudonym(OBJECTIVE_A);
        let theirs = seed(9).pseudonym(OBJECTIVE_A);
        let value = record();
        let signature = mine.sign_value(&value);
        assert_eq!(
            verify_value(theirs.public().as_bytes(), &value, &signature),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn a_pseudonym_cannot_verify_its_own_other_objective() {
        // Unlinkability in the direction that matters operationally: the key for
        // objective A is simply not the key for objective B.
        let master = seed(4);
        let a = master.pseudonym(OBJECTIVE_A);
        let b = master.pseudonym(OBJECTIVE_B);
        let value = record();
        let signature = a.sign_value(&value);
        assert_eq!(
            verify_value(b.public().as_bytes(), &value, &signature),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn flipped_signature_bits_fail() {
        let id = seed(1).pseudonym(OBJECTIVE_A);
        let value = record();
        let mut bytes = id.sign_value(&value).to_bytes();
        bytes[0] ^= 0x01;
        assert_eq!(
            verify_value(
                id.public().as_bytes(),
                &value,
                &Signature::from_bytes(bytes)
            ),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn all_zero_signature_never_verifies() {
        // The sentinel returned by the unreachable arm of `sign_bytes`. Its `R` is
        // small order, which `verify_strict` rejects, so the impossible case fails
        // loudly instead of forging anything.
        let id = seed(1).pseudonym(OBJECTIVE_A);
        assert_eq!(
            verify_value(
                id.public().as_bytes(),
                &record(),
                &Signature::from_bytes([0u8; SIG_LEN])
            ),
            Err(IdentityError::BadSignature)
        );
    }

    #[test]
    fn small_order_public_key_is_rejected_not_accepted() {
        // The identity point. Under non-strict verification a small-order key
        // accepts signatures nobody needed a secret to make; here it is a key
        // error, which is the difference between "authentication bypass" and
        // "decoding failure".
        let mut identity_point = [0u8; KEY_LEN];
        identity_point[0] = 1;
        assert!(!VerifyingKeyBytes::from_bytes(identity_point).is_usable());
        assert_eq!(
            verify_bytes(
                &identity_point,
                b"anything",
                &Signature::from_bytes([0u8; SIG_LEN])
            ),
            Err(IdentityError::InvalidPublicKey)
        );
    }

    #[test]
    fn non_curve_public_key_is_rejected() {
        // `y = 2`: (y^2 - 1) / (d*y^2 + 1) is a quadratic non-residue, so no `x`
        // exists and these 32 bytes are not a point at all. The value is pinned
        // deliberately -- roughly half of all `y` values *are* valid, so a
        // "random-looking" string like `[0xff; 32]` decompresses fine and would
        // test nothing.
        let mut bogus = [0u8; KEY_LEN];
        bogus[0] = 2;
        assert!(!VerifyingKeyBytes::from_bytes(bogus).is_usable());
        assert_eq!(
            verify_bytes(&bogus, b"anything", &Signature::from_bytes([0u8; SIG_LEN])),
            Err(IdentityError::InvalidPublicKey)
        );
    }

    #[test]
    fn real_public_keys_are_usable() {
        let id = Identity::generate(&mut OsRng);
        assert!(id.public().is_usable());
    }

    // -- signed record -----------------------------------------------------

    #[test]
    fn signed_record_round_trips_and_still_verifies() {
        let id = seed(5).pseudonym(OBJECTIVE_A);
        let signed = SignedRecord::sign(&id, record());
        assert!(signed.verify().is_ok());

        let encoded = signed.to_value();
        let decoded = SignedRecord::from_value(&encoded).expect("round trip decodes");
        assert_eq!(decoded, signed);
        assert!(decoded.verify().is_ok());
        assert_eq!(
            decoded.to_value().canonical_bytes(),
            encoded.canonical_bytes()
        );
    }

    #[test]
    fn signed_record_survives_json_transport() {
        let id = seed(5).pseudonym(OBJECTIVE_A);
        let signed = SignedRecord::sign(&id, record());
        let text = signed.to_value().canonical_string();
        let reparsed = Value::from_json(&text).expect("canonical output is valid json");
        let decoded = SignedRecord::from_value(&reparsed).expect("decodes");
        assert!(decoded.verify().is_ok());
        assert_eq!(decoded, signed);
    }

    #[test]
    fn signed_record_detects_a_tampered_body() {
        let id = seed(5).pseudonym(OBJECTIVE_A);
        let mut signed = SignedRecord::sign(&id, record());
        signed.record = crate::obj! { "type" => Value::string("claim") };
        assert_eq!(signed.verify(), Err(IdentityError::BadSignature));
    }

    #[test]
    fn signed_record_detects_a_swapped_public_key() {
        // The attack this blocks: republish someone's record under your own key to
        // collect the payout. The signature is over the body only, so the swapped
        // key simply fails.
        let mine = seed(5).pseudonym(OBJECTIVE_A);
        let attacker = seed(6).pseudonym(OBJECTIVE_A);
        let mut signed = SignedRecord::sign(&mine, record());
        signed.public_key = attacker.public().to_bytes();
        assert_eq!(signed.verify(), Err(IdentityError::BadSignature));
    }

    #[test]
    fn verify_signed_by_separates_authentication_from_authorization() {
        let mine = seed(5).pseudonym(OBJECTIVE_A);
        let other = seed(6).pseudonym(OBJECTIVE_A);
        let signed = SignedRecord::sign(&other, record());

        // Authentic: `other` really did sign it.
        assert!(signed.verify().is_ok());
        // But not from who we required.
        match signed.verify_signed_by(mine.public().as_bytes()) {
            Err(IdentityError::WrongSigner { expected, actual }) => {
                assert_eq!(expected, mine.submitter_id());
                assert_eq!(actual, other.submitter_id());
            }
            unexpected => panic!("expected WrongSigner, got {unexpected:?}"),
        }
        assert!(signed.verify_signed_by(other.public().as_bytes()).is_ok());
    }

    #[test]
    fn verify_does_not_check_the_records_own_submitter_field() {
        // Documenting the trap rather than pretending it does not exist: a record
        // can name any submitter it likes and still be authentically signed by
        // someone else. Binding the two is the record layer's job.
        let signer = seed(5).pseudonym(OBJECTIVE_A);
        let victim = seed(6).pseudonym(OBJECTIVE_A);
        let signed = SignedRecord::sign(
            &signer,
            crate::obj! { "submitter" => Value::string(victim.submitter_id()) },
        );
        assert!(signed.verify().is_ok());
        assert_ne!(signed.submitter_id(), victim.submitter_id());
        assert_eq!(signed.submitter_id(), signer.submitter_id());
    }

    #[test]
    fn signed_record_rejects_a_foreign_type_tag() {
        let id = seed(5).pseudonym(OBJECTIVE_A);
        let signed = SignedRecord::sign(&id, record());
        let mut encoded = match signed.to_value() {
            Value::Object(map) => map,
            _ => unreachable!("to_value builds an object"),
        };
        encoded.insert("type".to_string(), Value::string("sealed_envelope"));
        assert_eq!(
            SignedRecord::from_value(&Value::Object(encoded)),
            Err(IdentityError::InvalidField {
                field: "type",
                expected: "\"signed_record\"",
            })
        );
    }

    #[test]
    fn signed_record_rejects_an_unknown_version() {
        let id = seed(5).pseudonym(OBJECTIVE_A);
        let signed = SignedRecord::sign(&id, record());
        let mut encoded = match signed.to_value() {
            Value::Object(map) => map,
            _ => unreachable!("to_value builds an object"),
        };
        encoded.insert("version".to_string(), Value::Int(2));
        assert_eq!(
            SignedRecord::from_value(&Value::Object(encoded)),
            Err(IdentityError::UnsupportedVersion { version: 2 })
        );
    }

    #[test]
    fn signed_record_rejects_missing_fields_and_non_objects() {
        assert_eq!(
            SignedRecord::from_value(&Value::string("not a record")),
            Err(IdentityError::NotAnObject)
        );
        assert_eq!(
            SignedRecord::from_value(&crate::obj! { "version" => Value::Int(1) }),
            Err(IdentityError::MissingField { field: "type" })
        );
        assert_eq!(
            SignedRecord::from_value(&crate::obj! {
                "type" => Value::string(RECORD_TYPE),
                "version" => Value::Int(1),
            }),
            Err(IdentityError::MissingField { field: "record" })
        );
    }

    #[test]
    fn a_null_record_round_trips() {
        // Any Value is signable, so any Value must survive the wire form.
        let id = seed(5).pseudonym(OBJECTIVE_A);
        let signed = SignedRecord::sign(&id, Value::Null);
        let decoded = SignedRecord::from_value(&signed.to_value()).expect("decodes");
        assert_eq!(decoded, signed);
        assert!(decoded.verify().is_ok());
    }

    // -- hex strictness ----------------------------------------------------

    #[test]
    fn hex_fields_are_strict_and_lowercase() {
        let id = seed(5).pseudonym(OBJECTIVE_A);
        let signature = id.sign_value(&record());
        let hex = signature.to_hex();
        assert_eq!(hex.len(), SIG_LEN * 2);
        assert!(hex
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));

        assert_eq!(
            Signature::from_hex(&hex.to_uppercase()),
            Err(IdentityError::InvalidHex { field: "signature" })
        );
        assert_eq!(
            Signature::from_hex(""),
            Err(IdentityError::WrongLength {
                field: "signature",
                expected: SIG_LEN,
                actual: 0,
            })
        );
        assert!(matches!(
            Signature::from_hex(&hex[..SIG_LEN * 2 - 1]),
            Err(IdentityError::WrongLength { .. })
        ));
        assert_eq!(Signature::from_hex(&hex), Ok(signature));
    }

    #[test]
    fn public_key_and_signature_values_round_trip_exactly() {
        let id = Identity::generate(&mut OsRng);
        let public = id.public();
        assert_eq!(
            VerifyingKeyBytes::from_value(&public.to_value()),
            Ok(public)
        );

        let signature = id.sign_bytes(b"x");
        assert_eq!(Signature::from_value(&signature.to_value()), Ok(signature));

        assert_eq!(
            Signature::from_value(&Value::Int(1)),
            Err(IdentityError::InvalidField {
                field: "signature",
                expected: "a hex string",
            })
        );
    }

    #[test]
    fn submitter_id_is_the_public_key_in_hex() {
        let id = seed(5).pseudonym(OBJECTIVE_A);
        assert_eq!(id.submitter_id(), id.public().to_hex());
        assert_eq!(id.submitter_id().len(), KEY_LEN * 2);
        assert_eq!(
            VerifyingKeyBytes::from_hex(&id.submitter_id()),
            Ok(id.public())
        );
    }

    #[test]
    fn identity_secret_bytes_round_trip() {
        let id = Identity::generate(&mut OsRng);
        let restored = Identity::from_secret_bytes(*id.to_secret_bytes());
        assert_eq!(restored.public(), id.public());
        let signature = restored.sign_value(&record());
        assert!(verify_value(id.public().as_bytes(), &record(), &signature).is_ok());
    }

    // -- redaction ---------------------------------------------------------

    #[test]
    fn debug_never_prints_secret_material() {
        let seed_bytes = [0xabu8; SEED_LEN];
        let master = MasterSeed::from_bytes(seed_bytes);
        let seed_hex = hex_encode(&seed_bytes);

        let printed = format!("{master:?}");
        assert!(!printed.contains(&seed_hex), "seed leaked: {printed}");
        assert!(!printed.contains("ab"), "seed nibbles leaked: {printed}");
        assert!(printed.contains("redacted"));

        let id = master.pseudonym(OBJECTIVE_A);
        let secret_hex = hex_encode(&*id.to_secret_bytes());
        let printed = format!("{id:?}");
        assert!(
            !printed.contains(&secret_hex),
            "secret key leaked: {printed}"
        );
        assert!(printed.contains("redacted"));
        // The public half is fine to print, and useful.
        assert!(printed.contains(&id.public().to_hex()));

        // A struct that merely *contains* an identity must not leak either: the
        // redaction has to live on `Identity`'s own `Debug`, not on discipline at
        // every call site.
        #[derive(Debug)]
        struct Holder {
            id: Identity,
        }
        let public = id.public();
        let holder = Holder { id };
        let printed = format!("{holder:?}");
        assert!(
            !printed.contains(&secret_hex),
            "secret key leaked: {printed}"
        );
        assert_eq!(holder.id.public(), public);
    }

    // -- HMAC correctness --------------------------------------------------

    #[test]
    fn hmac_matches_rfc_4231_vectors() {
        let cases: [(&[u8], &[u8], &str); 4] = [
            (
                &[0x0b; 20],
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe",
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                &[0xaa; 20],
                &[0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                // Longer than the 64-byte block, so the key is hashed first.
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
        ];
        for (key, message, expected) in cases {
            assert_eq!(hex_encode(&*hmac_sha256(key, message)), expected);
        }
    }

    #[test]
    fn hmac_agrees_with_the_hmac_crate() {
        // Differential check against the vetted implementation. The library code
        // cannot use it -- its constructor is fallible and this crate forbids
        // panics -- but a test may, and this is what keeps the hand-rolled version
        // honest.
        for len in [0usize, 1, 31, 32, 63, 64, 65, 200] {
            let key: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let message: Vec<u8> = (0..len * 3 + 1).map(|i| (i % 97) as u8).collect();
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&key).expect("hmac accepts any key length");
            mac.update(&message);
            let expected = mac.finalize().into_bytes();
            assert_eq!(
                hmac_sha256(&key, &message).as_slice(),
                expected.as_slice(),
                "mismatch at key length {len}"
            );
        }
    }

    #[test]
    fn hmac_is_keyed_not_just_hashed() {
        // A construction that ignored the key, or that concatenated it in a
        // length-extendable way, would fail this.
        assert_ne!(
            *hmac_sha256(b"key-one", b"message"),
            *hmac_sha256(b"key-two", b"message")
        );
        assert_ne!(
            *hmac_sha256(b"key", b"message-one"),
            *hmac_sha256(b"key", b"message-two")
        );
    }
}
