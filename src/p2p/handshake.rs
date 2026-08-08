//! Post-quantum peer handshake: Classic McEliece KEM to a long-term key.
//!
//! # Why the key sizes decide the protocol
//!
//! Measured on this machine, `mceliece348864`:
//!
//! | operation | cost | size |
//! |---|---|---|
//! | keygen | 243 ms | public key **261,120 bytes** |
//! | encapsulate | 22 µs | ciphertext **96 bytes** |
//! | decapsulate | 12 ms | shared secret 32 bytes |
//!
//! A 255 KB public key cannot travel in every handshake, and a 243 ms keygen
//! cannot happen per connection. So the public key is a peer's **long-term
//! identity**: published once, fetched once, cached by id thereafter. After
//! that a handshake costs 96 bytes on the wire — smaller than an X25519
//! exchange plus a certificate, which is a genuinely good trade for gossip.
//!
//! # What this does and does not give you
//!
//! * **Confidentiality against a quantum adversary.** Classic McEliece is the
//!   most conservative KEM available: the underlying problem has resisted
//!   attack since 1978, which is the reason to accept the key size.
//! * **Responder authentication, implicitly.** Only the holder of the secret
//!   key can decapsulate, so a session that decrypts proves you are talking to
//!   the owner of that public key.
//! * **No initiator authentication.** The KEM says nothing about who
//!   encapsulated. Peers that must prove who they are sign the transcript with
//!   the ed25519 identity in [`crate::crypto::identity`] — that layer already
//!   exists and this one deliberately does not duplicate it.
//! * **No forward secrecy.** This is the real cost of a static key, and it is
//!   stated rather than buried: if a peer's McEliece secret leaks, every past
//!   session it accepted becomes decryptable to whoever recorded the traffic.
//!   Ephemeral keypairs would fix it and cost 243 ms plus 255 KB per
//!   connection, which no gossip protocol can pay. The mitigation available
//!   here is key rotation, and a peer's id changes when it rotates.
//!
//! # The amplification a deployment must handle
//!
//! Encapsulation costs 22 µs; decapsulation costs 12 ms. A 96-byte message
//! therefore buys about **125,000× its cost in CPU** from the responder. That
//! is a denial-of-service asymmetry, not a cryptographic weakness, and it is
//! the responder's problem to price: rate-limit per source, or require
//! something cheap-to-verify and expensive-to-produce before decapsulating.
//! Nothing in this module does that for you.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use classic_mceliece_rust::{
    decapsulate_boxed, encapsulate_boxed, keypair_boxed, Ciphertext, PublicKey, SecretKey,
    CRYPTO_CIPHERTEXTBYTES, CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::fmt;

/// A peer's identity: the SHA-256 of its public key.
///
/// 32 bytes rather than 255 KB, so peer references stay small everywhere. It
/// commits to the key, so citing an id and fetching the key later is safe.
pub type PeerId = [u8; 32];

/// Domain separation. Changing any of these changes every derived key.
const KDF_DOMAIN: &str = "proofwork/p2p/mceliece/v1";
const LABEL_I2R: &str = "initiator-to-responder";
const LABEL_R2I: &str = "responder-to-initiator";

/// Errors from the handshake or the channel it produces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// A public key blob was not exactly `CRYPTO_PUBLICKEYBYTES` long.
    BadPublicKeyLength { got: usize },
    /// A secret key blob was not exactly `CRYPTO_SECRETKEYBYTES` long.
    BadSecretKeyLength { got: usize },
    /// A ciphertext was not exactly `CRYPTO_CIPHERTEXTBYTES` long.
    BadCiphertextLength { got: usize },
    /// The frame did not authenticate: wrong key, wrong transcript, or
    /// tampering. Deliberately one variant — telling an attacker *which* is
    /// free help.
    NotAuthentic,
    /// A frame arrived with a counter at or below one already accepted.
    Replay { counter: u64, expected_above: u64 },
    /// The send counter is exhausted. Rekey rather than wrap.
    CounterExhausted,
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeError::BadPublicKeyLength { got } => write!(
                f,
                "public key must be {CRYPTO_PUBLICKEYBYTES} bytes, got {got}"
            ),
            HandshakeError::BadSecretKeyLength { got } => write!(
                f,
                "secret key must be {CRYPTO_SECRETKEYBYTES} bytes, got {got}"
            ),
            HandshakeError::BadCiphertextLength { got } => write!(
                f,
                "ciphertext must be {CRYPTO_CIPHERTEXTBYTES} bytes, got {got}"
            ),
            HandshakeError::NotAuthentic => f.write_str("frame did not authenticate"),
            HandshakeError::Replay {
                counter,
                expected_above,
            } => write!(
                f,
                "replayed or reordered frame: counter {counter}, expected above {expected_above}"
            ),
            HandshakeError::CounterExhausted => {
                f.write_str("send counter exhausted; rekey rather than reuse a nonce")
            }
        }
    }
}

impl std::error::Error for HandshakeError {}

/// A peer's long-term keypair.
///
/// Generating one costs ~243 ms, so generate it once and persist it. Not
/// `Clone`: two copies of a secret key are two things to lose.
pub struct PeerIdentity {
    secret: SecretKey<'static>,
    public: Box<[u8; CRYPTO_PUBLICKEYBYTES]>,
    id: PeerId,
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the secret, and never the 255 KB public key.
        write!(f, "PeerIdentity({})", short(&self.id))
    }
}

impl PeerIdentity {
    /// Generate a fresh long-term identity. ~243 ms.
    pub fn generate() -> PeerIdentity {
        let (public, secret) = keypair_boxed(&mut OsRng);
        let public: Box<[u8; CRYPTO_PUBLICKEYBYTES]> = Box::new(*public.as_array());
        let id = peer_id_of(public.as_ref());
        PeerIdentity { secret, public, id }
    }

    /// Restore an identity from persisted key material.
    pub fn from_bytes(public: &[u8], secret: &[u8]) -> Result<PeerIdentity, HandshakeError> {
        let public: Box<[u8; CRYPTO_PUBLICKEYBYTES]> =
            boxed_array(public).ok_or(HandshakeError::BadPublicKeyLength { got: public.len() })?;
        let secret_arr: Box<[u8; CRYPTO_SECRETKEYBYTES]> =
            boxed_array(secret).ok_or(HandshakeError::BadSecretKeyLength { got: secret.len() })?;
        let id = peer_id_of(public.as_ref());
        Ok(PeerIdentity {
            secret: SecretKey::from(secret_arr),
            public,
            id,
        })
    }

    pub fn id(&self) -> PeerId {
        self.id
    }

    /// The 255 KB public key. Publish once; peers cache it by id.
    pub fn public_key(&self) -> &[u8; CRYPTO_PUBLICKEYBYTES] {
        &self.public
    }

    /// Secret key material for an explicitly persisted node identity.
    /// Callers must protect the returned bytes like any other private key.
    pub fn secret_key(&self) -> &[u8; CRYPTO_SECRETKEYBYTES] {
        self.secret.as_array()
    }

    /// What other peers hold about this one.
    pub fn to_public(&self) -> PeerPublic {
        PeerPublic {
            public: self.public.clone(),
            id: self.id,
        }
    }

    /// Accept an incoming handshake.
    ///
    /// Costs ~12 ms. See the module docs on amplification before exposing this
    /// to unauthenticated traffic.
    pub fn accept(&self, initiator: PeerId, ciphertext: &[u8]) -> Result<Channel, HandshakeError> {
        let ct: [u8; CRYPTO_CIPHERTEXTBYTES] =
            ciphertext
                .try_into()
                .map_err(|_| HandshakeError::BadCiphertextLength {
                    got: ciphertext.len(),
                })?;
        let shared = decapsulate_boxed(&Ciphertext::from(ct), &self.secret);
        // Classic McEliece is IND-CCA2: a malformed ciphertext yields a
        // pseudorandom shared secret rather than an error, so there is nothing
        // to check here. The mismatch surfaces at the first frame that fails to
        // authenticate, which is exactly where it should.
        Ok(Channel::new(
            derive(shared.as_array(), initiator, self.id, &ct),
            Role::Responder,
        ))
    }
}

/// What a peer caches about another peer.
#[derive(Clone)]
pub struct PeerPublic {
    public: Box<[u8; CRYPTO_PUBLICKEYBYTES]>,
    id: PeerId,
}

impl fmt::Debug for PeerPublic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerPublic({})", short(&self.id))
    }
}

impl PeerPublic {
    /// Adopt a public key blob, deriving its id.
    ///
    /// The id is computed here rather than taken on trust, so a peer cannot
    /// hand you a key under someone else's name.
    pub fn from_bytes(public: &[u8]) -> Result<PeerPublic, HandshakeError> {
        let public: Box<[u8; CRYPTO_PUBLICKEYBYTES]> =
            boxed_array(public).ok_or(HandshakeError::BadPublicKeyLength { got: public.len() })?;
        let id = peer_id_of(public.as_ref());
        Ok(PeerPublic { public, id })
    }

    pub fn id(&self) -> PeerId {
        self.id
    }

    pub fn as_bytes(&self) -> &[u8; CRYPTO_PUBLICKEYBYTES] {
        &self.public
    }

    /// Open a session to this peer. ~22 µs, 96 bytes on the wire.
    pub fn initiate(&self, initiator: PeerId) -> ([u8; CRYPTO_CIPHERTEXTBYTES], Channel) {
        let mut key_bytes = self.public.clone();
        let pk = PublicKey::from(key_bytes.as_mut());
        let (ct, shared) = encapsulate_boxed(&pk, &mut OsRng);
        let ct_bytes = *ct.as_array();
        let channel = Channel::new(
            derive(shared.as_array(), initiator, self.id, &ct_bytes),
            Role::Initiator,
        );
        (ct_bytes, channel)
    }
}

/// Which end of the handshake this side is. Decides which derived key sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

/// The two directional keys a handshake produces.
struct SessionKeys {
    i2r: [u8; 32],
    r2i: [u8; 32],
}

/// Derive directional keys, binding the whole transcript.
///
/// Both peer ids and the ciphertext go into the KDF, so a shared secret is
/// useless outside the exact handshake that produced it: a ciphertext replayed
/// against a different claimed initiator derives different keys and every frame
/// fails to authenticate.
///
/// Separate keys per direction because the nonce is a counter starting at zero
/// on both sides. One key would mean both peers using nonce 0 under the same
/// key, which is the catastrophic failure mode for ChaCha20-Poly1305.
fn derive(
    shared: &[u8; 32],
    initiator: PeerId,
    responder: PeerId,
    ciphertext: &[u8; CRYPTO_CIPHERTEXTBYTES],
) -> SessionKeys {
    let leg = |label: &str| -> [u8; 32] {
        let mut h = Sha256::new();
        h.update((KDF_DOMAIN.len() as u64).to_be_bytes());
        h.update(KDF_DOMAIN.as_bytes());
        h.update((label.len() as u64).to_be_bytes());
        h.update(label.as_bytes());
        h.update(shared);
        h.update(initiator);
        h.update(responder);
        h.update(ciphertext);
        h.finalize().into()
    };
    SessionKeys {
        i2r: leg(LABEL_I2R),
        r2i: leg(LABEL_R2I),
    }
}

/// An authenticated, encrypted session.
///
/// Nonces are the frame counter, never random: a counter cannot repeat by
/// accident, and repetition is the one thing this construction cannot survive.
pub struct Channel {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_counter: u64,
    /// Highest counter accepted so far. Frames must strictly increase, which
    /// rejects both replays and reordering.
    recv_high: Option<u64>,
}

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel")
            .field("sent", &self.send_counter)
            .field("recv_high", &self.recv_high)
            .finish()
    }
}

/// Seal one frame under `key` at `counter`.
///
/// A free function rather than a method so both [`Channel`] and [`Sealer`] can
/// reach it **without copying the key to get there**. The first version of the
/// split built a temporary `Channel` per call, which meant a fresh copy of the
/// session key on the stack for every frame instead of one for the session --
/// the same objection [`crate::store::atrest::Cipher`] makes about deriving
/// `Clone`, and it applies to a session key at least as much.
fn seal_frame(
    key: &[u8; 32],
    counter: u64,
    plaintext: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    if counter == u64::MAX {
        return Err(HandshakeError::CounterExhausted);
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            &nonce_for(counter),
            Payload {
                msg: plaintext,
                aad: &aad(counter, context),
            },
        )
        .map_err(|_| HandshakeError::NotAuthentic)
}

/// Open one frame under `key` at `counter`. Replay is the caller's business:
/// this is the cryptography, and the window lives with whoever owns it.
fn open_frame(
    key: &[u8; 32],
    counter: u64,
    ciphertext: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, HandshakeError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            &nonce_for(counter),
            Payload {
                msg: ciphertext,
                aad: &aad(counter, context),
            },
        )
        .map_err(|_| HandshakeError::NotAuthentic)
}

impl Channel {
    fn new(keys: SessionKeys, role: Role) -> Channel {
        let (send_key, recv_key) = match role {
            Role::Initiator => (keys.i2r, keys.r2i),
            Role::Responder => (keys.r2i, keys.i2r),
        };
        Channel {
            send_key,
            recv_key,
            send_counter: 0,
            recv_high: None,
        }
    }

    /// Encrypt a frame. Returns its counter and ciphertext.
    ///
    /// `context` is authenticated but not transmitted — bind whatever the
    /// caller must agree on out of band.
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        context: &[u8],
    ) -> Result<(u64, Vec<u8>), HandshakeError> {
        let counter = self.send_counter;
        let ciphertext = seal_frame(&self.send_key, counter, plaintext, context)?;
        self.send_counter += 1;
        Ok((counter, ciphertext))
    }

    /// Decrypt a frame, refusing replays and reordering.
    pub fn open(
        &mut self,
        counter: u64,
        ciphertext: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, HandshakeError> {
        if let Some(high) = self.recv_high {
            if counter <= high {
                return Err(HandshakeError::Replay {
                    counter,
                    expected_above: high,
                });
            }
        }
        let plaintext = open_frame(&self.recv_key, counter, ciphertext, context)?;
        // Only advance on success, so a forged frame cannot burn counter space
        // and lock out the honest peer.
        self.recv_high = Some(counter);
        Ok(plaintext)
    }

    /// Frames sent so far. Rekey well before this approaches `u64::MAX`.
    pub fn frames_sent(&self) -> u64 {
        self.send_counter
    }

    /// Split into the two halves, so sending and receiving can happen on
    /// different threads.
    ///
    /// Safe because the two directions share nothing. A session derives *four*
    /// values — a key and a counter each way — and [`Channel::seal`] touches
    /// only the send pair while [`Channel::open`] touches only the receive pair.
    /// There is no state to race over, so the split needs no lock, and a lock
    /// would be actively wrong: a reader blocked in `recv` holding it would
    /// starve the writer forever.
    ///
    /// That is not a general property of AEAD sessions and is worth stating.
    /// A construction with one counter for both directions, or one key, could
    /// not do this — the halves would have to agree on every increment. The
    /// separation is what `SessionKeys`'s two labels buy.
    pub fn split(self) -> (Sealer, Opener) {
        (
            Sealer {
                key: self.send_key,
                counter: self.send_counter,
            },
            Opener {
                key: self.recv_key,
                high: self.recv_high,
            },
        )
    }
}

/// The sending half of a split [`Channel`].
pub struct Sealer {
    key: [u8; 32],
    counter: u64,
}

impl fmt::Debug for Sealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealer")
            .field("sent", &self.counter)
            .finish()
    }
}

impl Sealer {
    /// As [`Channel::seal`].
    pub fn seal(
        &mut self,
        plaintext: &[u8],
        context: &[u8],
    ) -> Result<(u64, Vec<u8>), HandshakeError> {
        let counter = self.counter;
        let ciphertext = seal_frame(&self.key, counter, plaintext, context)?;
        self.counter += 1;
        Ok((counter, ciphertext))
    }

    pub fn frames_sent(&self) -> u64 {
        self.counter
    }
}

/// The receiving half of a split [`Channel`].
pub struct Opener {
    key: [u8; 32],
    high: Option<u64>,
}

impl fmt::Debug for Opener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opener")
            .field("recv_high", &self.high)
            .finish()
    }
}

impl Opener {
    /// As [`Channel::open`], including the replay and reordering refusal.
    pub fn open(
        &mut self,
        counter: u64,
        ciphertext: &[u8],
        context: &[u8],
    ) -> Result<Vec<u8>, HandshakeError> {
        if let Some(high) = self.high {
            if counter <= high {
                return Err(HandshakeError::Replay {
                    counter,
                    expected_above: high,
                });
            }
        }
        let plaintext = open_frame(&self.key, counter, ciphertext, context)?;
        // As `Channel::open`: only advance on success, so a forged frame cannot
        // burn counter space and lock out the honest peer.
        self.high = Some(counter);
        Ok(plaintext)
    }
}

/// The counter as a 12-byte little-endian nonce, zero-padded.
fn nonce_for(counter: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[..8].copy_from_slice(&counter.to_le_bytes());
    bytes.into()
}

/// The counter is authenticated as well as used as the nonce, so a frame
/// cannot be renumbered without breaking the tag.
fn aad(counter: u64, context: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + context.len());
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(context);
    out
}

fn peer_id_of(public: &[u8; CRYPTO_PUBLICKEYBYTES]) -> PeerId {
    let mut h = Sha256::new();
    h.update(b"proofwork/p2p/peer-id/v1");
    h.update(public);
    h.finalize().into()
}

fn boxed_array<const N: usize>(bytes: &[u8]) -> Option<Box<[u8; N]>> {
    if bytes.len() != N {
        return None;
    }
    let mut out = Box::new([0u8; N]);
    out.copy_from_slice(bytes);
    Some(out)
}

fn short(id: &PeerId) -> String {
    id.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// Lowercase hex of a peer id, for logs and config.
pub fn peer_id_hex(id: &PeerId) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

/// Identity is by id, not by key blob: deriving `PartialEq` on the public key
/// would compare 255 KB every time, and the id already commits to it.
impl PartialEq for PeerPublic {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for PeerPublic {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generating a McEliece keypair costs ~243 ms, so the suite shares two.
    fn pair() -> &'static (PeerIdentity, PeerIdentity) {
        use std::sync::OnceLock;
        static PAIR: OnceLock<(PeerIdentity, PeerIdentity)> = OnceLock::new();
        PAIR.get_or_init(|| (PeerIdentity::generate(), PeerIdentity::generate()))
    }

    fn session() -> (Channel, Channel) {
        let (alice, bob) = pair();
        let (ct, a_chan) = bob.to_public().initiate(alice.id());
        let b_chan = bob.accept(alice.id(), &ct).expect("accept");
        (a_chan, b_chan)
    }

    #[test]
    fn a_session_round_trips_in_both_directions() {
        let (mut a, mut b) = session();
        let (n, ct) = a.seal(b"objectives 1..9", b"sync").unwrap();
        assert_eq!(b.open(n, &ct, b"sync").unwrap(), b"objectives 1..9");

        let (n, ct) = b.seal(b"want 3,7", b"sync").unwrap();
        assert_eq!(a.open(n, &ct, b"sync").unwrap(), b"want 3,7");
    }

    #[test]
    fn the_wire_cost_is_a_ciphertext_not_a_key() {
        // The whole reason the public key is a cached long-term identity.
        let (alice, bob) = pair();
        let (ct, _) = bob.to_public().initiate(alice.id());
        assert_eq!(ct.len(), 96);
        assert_eq!(bob.public_key().len(), 261_120);
    }

    #[test]
    fn peer_ids_commit_to_the_key_and_are_derived_not_trusted() {
        let (alice, bob) = pair();
        assert_ne!(alice.id(), bob.id());
        // Adopting a key recomputes the id, so a peer cannot present someone
        // else's key under its own name.
        let adopted = PeerPublic::from_bytes(bob.public_key()).unwrap();
        assert_eq!(adopted.id(), bob.id());
        assert_eq!(peer_id_hex(&adopted.id()).len(), 64);
    }

    #[test]
    fn only_the_holder_of_the_secret_can_open_the_session() {
        let (alice, bob) = pair();
        let (ct, mut a_chan) = bob.to_public().initiate(alice.id());
        // Alice is not the intended responder, so her decapsulation yields a
        // different secret -- IND-CCA2 means no error, just useless keys.
        let mut wrong = alice
            .accept(alice.id(), &ct)
            .expect("decapsulation never errors");
        let (n, frame) = a_chan.seal(b"secret", b"ctx").unwrap();
        assert_eq!(
            wrong.open(n, &frame, b"ctx"),
            Err(HandshakeError::NotAuthentic)
        );
    }

    #[test]
    fn the_transcript_is_bound_into_the_keys() {
        // A ciphertext replayed under a different claimed initiator must not
        // produce a working session.
        let (alice, bob) = pair();
        let (ct, mut a_chan) = bob.to_public().initiate(alice.id());
        let mut mallory = bob.accept([0xAA; 32], &ct).unwrap();
        let (n, frame) = a_chan.seal(b"hello", b"ctx").unwrap();
        assert_eq!(
            mallory.open(n, &frame, b"ctx"),
            Err(HandshakeError::NotAuthentic)
        );
    }

    #[test]
    fn directions_use_different_keys() {
        // Otherwise both peers would send counter 0 under one key, which is the
        // failure ChaCha20-Poly1305 cannot survive. Reflecting a frame back at
        // its sender must not decrypt.
        let (mut a, _b) = session();
        let (n, frame) = a.seal(b"mine", b"ctx").unwrap();
        assert_eq!(a.open(n, &frame, b"ctx"), Err(HandshakeError::NotAuthentic));
    }

    #[test]
    fn replayed_and_reordered_frames_are_refused() {
        let (mut a, mut b) = session();
        let (n1, f1) = a.seal(b"one", b"ctx").unwrap();
        let (n2, f2) = a.seal(b"two", b"ctx").unwrap();
        assert_eq!(b.open(n2, &f2, b"ctx").unwrap(), b"two");
        // n1 < n2: arrives late, or is replayed. Either way, refused.
        assert_eq!(
            b.open(n1, &f1, b"ctx"),
            Err(HandshakeError::Replay {
                counter: n1,
                expected_above: n2
            })
        );
    }

    #[test]
    fn a_forged_frame_does_not_advance_the_window() {
        // Otherwise an attacker sends garbage at a high counter and locks the
        // honest peer out of every counter below it.
        let (mut a, mut b) = session();
        assert!(b.open(9_000, b"garbage", b"ctx").is_err());
        let (n, f) = a.seal(b"still fine", b"ctx").unwrap();
        assert_eq!(b.open(n, &f, b"ctx").unwrap(), b"still fine");
    }

    #[test]
    fn nonces_never_repeat_within_a_session() {
        let (mut a, _) = session();
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..256 {
            let (n, _) = a.seal(b"x", b"ctx").unwrap();
            assert!(seen.insert(n), "counter {n} reused");
        }
        assert_eq!(a.frames_sent(), 256);
    }

    #[test]
    fn tampering_with_ciphertext_counter_or_context_is_detected() {
        let (mut a, mut b) = session();
        let (n, f) = a.seal(b"payload", b"sync").unwrap();

        let mut bad = f.clone();
        bad[0] ^= 0xff;
        assert_eq!(b.open(n, &bad, b"sync"), Err(HandshakeError::NotAuthentic));
        // Renumbering: the counter is authenticated, not just used as a nonce.
        assert_eq!(
            b.open(n + 1, &f, b"sync"),
            Err(HandshakeError::NotAuthentic)
        );
        // Context is bound even though it never travels.
        assert_eq!(b.open(n, &f, b"other"), Err(HandshakeError::NotAuthentic));
        // ... and the good frame still opens, so none of the above consumed it.
        assert_eq!(b.open(n, &f, b"sync").unwrap(), b"payload");
    }

    #[test]
    fn two_handshakes_to_one_peer_get_independent_sessions() {
        // Encapsulation is randomised, so a static responder key still gives a
        // fresh session per connection.
        let (alice, bob) = pair();
        let (ct1, mut a1) = bob.to_public().initiate(alice.id());
        let (ct2, _a2) = bob.to_public().initiate(alice.id());
        assert_ne!(ct1, ct2);
        let mut b2 = bob.accept(alice.id(), &ct2).unwrap();
        let (n, f) = a1.seal(b"session one", b"ctx").unwrap();
        assert_eq!(b2.open(n, &f, b"ctx"), Err(HandshakeError::NotAuthentic));
    }

    #[test]
    fn identities_persist_and_restore() {
        let (alice, _) = pair();
        let restored =
            PeerIdentity::from_bytes(alice.public_key(), alice.secret.as_array()).unwrap();
        assert_eq!(restored.id(), alice.id());
        // And a restored identity can still accept.
        let (ct, mut chan) = restored.to_public().initiate([1u8; 32]);
        let mut theirs = restored.accept([1u8; 32], &ct).unwrap();
        let (n, f) = chan.seal(b"ok", b"c").unwrap();
        assert_eq!(theirs.open(n, &f, b"c").unwrap(), b"ok");
    }

    #[test]
    fn malformed_blobs_are_refused_by_length() {
        assert_eq!(
            PeerPublic::from_bytes(&[0u8; 10]),
            Err(HandshakeError::BadPublicKeyLength { got: 10 })
        );
        let (_, bob) = pair();
        assert_eq!(
            bob.accept([0u8; 32], &[0u8; 10]).err(),
            Some(HandshakeError::BadCiphertextLength { got: 10 })
        );
    }

    #[test]
    fn debug_output_never_leaks_key_material() {
        let (alice, _) = pair();
        let rendered = format!("{:?} {:?}", alice, alice.to_public());
        assert!(rendered.len() < 100, "debug is far too large: {rendered}");
        assert!(!rendered.contains("["), "looks like raw bytes: {rendered}");
    }

    // -- splitting a channel ----------------------------------------------

    fn paired() -> (Channel, Channel) {
        let responder = PeerIdentity::generate();
        let initiator = PeerIdentity::generate();
        let (ciphertext, initiator_channel) = responder.to_public().initiate(initiator.id());
        let responder_channel = responder
            .accept(initiator.id(), &ciphertext)
            .expect("the responder decapsulates");
        (initiator_channel, responder_channel)
    }

    #[test]
    fn a_split_channel_still_talks_to_an_unsplit_one() {
        // The split must be invisible on the wire, or a node that splits could
        // not talk to a node that does not.
        let (initiator, mut responder) = paired();
        let (mut sealer, _opener) = initiator.split();
        let (counter, ciphertext) = sealer.seal(b"hello", b"ctx").expect("seals");
        assert_eq!(
            responder.open(counter, &ciphertext, b"ctx").expect("opens"),
            b"hello"
        );
    }

    #[test]
    fn both_halves_of_a_split_work_in_both_directions() {
        let (initiator, responder) = paired();
        let (mut i_send, mut i_recv) = initiator.split();
        let (mut r_send, mut r_recv) = responder.split();

        let (counter, ct) = i_send.seal(b"ping", b"ctx").expect("seals");
        assert_eq!(r_recv.open(counter, &ct, b"ctx").expect("opens"), b"ping");
        let (counter, ct) = r_send.seal(b"pong", b"ctx").expect("seals");
        assert_eq!(i_recv.open(counter, &ct, b"ctx").expect("opens"), b"pong");
    }

    #[test]
    fn a_split_opener_still_refuses_replays_and_reordering() {
        // The property that makes the counter worth having. Losing it in the
        // split would be a silent downgrade -- everything would still work,
        // and a recorded frame would replay.
        let (initiator, responder) = paired();
        let (mut sealer, _) = initiator.split();
        let (_, mut opener) = responder.split();

        let (c0, f0) = sealer.seal(b"first", b"ctx").expect("seals");
        let (c1, f1) = sealer.seal(b"second", b"ctx").expect("seals");
        assert_eq!(opener.open(c1, &f1, b"ctx").expect("opens"), b"second");
        // The earlier frame is now in the past: refused, not accepted late.
        assert!(
            matches!(
                opener.open(c0, &f0, b"ctx"),
                Err(HandshakeError::Replay { .. })
            ),
            "a split opener accepted a reordered frame"
        );
        // And the one it did accept cannot be replayed either.
        assert!(matches!(
            opener.open(c1, &f1, b"ctx"),
            Err(HandshakeError::Replay { .. })
        ));
    }

    #[test]
    fn a_split_sealer_does_not_reuse_a_counter() {
        // Nonce reuse is the one thing this construction cannot survive, and
        // the counter is the nonce. A split that reset it would be fatal.
        let (initiator, _) = paired();
        let sent_before = initiator.frames_sent();
        let (mut sealer, _) = initiator.split();
        assert_eq!(sealer.frames_sent(), sent_before);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..16 {
            let (counter, _) = sealer.seal(b"x", b"ctx").expect("seals");
            assert!(seen.insert(counter), "counter {counter} was reused");
        }
    }

    #[test]
    fn a_split_preserves_a_counter_already_advanced() {
        // Splitting mid-session must not rewind either side. A sealer that
        // restarted at zero would reuse nonces against a peer that had already
        // seen them, and an opener that forgot its high-water mark would accept
        // every frame it had already accepted.
        let (mut initiator, mut responder) = paired();
        let (c, f) = initiator.seal(b"before", b"ctx").expect("seals");
        assert_eq!(responder.open(c, &f, b"ctx").expect("opens"), b"before");
        let (r_c, r_f) = responder.seal(b"reply", b"ctx").expect("seals");
        assert_eq!(initiator.open(r_c, &r_f, b"ctx").expect("opens"), b"reply");

        let (mut sealer, mut opener) = initiator.split();
        let (next, _) = sealer.seal(b"after", b"ctx").expect("seals");
        assert!(next > c, "the split rewound the send counter");
        assert!(
            matches!(
                opener.open(r_c, &r_f, b"ctx"),
                Err(HandshakeError::Replay { .. })
            ),
            "the split forgot what it had already received"
        );
    }

    #[test]
    fn a_split_half_still_binds_its_context() {
        // Frames sealed for one subsystem must not open as another's; that is
        // what the context string is for and the split must not lose it.
        let (initiator, responder) = paired();
        let (mut sealer, _) = initiator.split();
        let (_, mut opener) = responder.split();
        let (counter, frame) = sealer.seal(b"payload", b"proofwork/a").expect("seals");
        assert!(matches!(
            opener.open(counter, &frame, b"proofwork/b"),
            Err(HandshakeError::NotAuthentic)
        ));
    }

    #[test]
    fn a_split_sealer_refuses_to_wrap_its_counter() {
        // The counter is the nonce, and nonce reuse is the one failure
        // ChaCha20-Poly1305 does not survive -- it exposes the XOR of two
        // messages and permits forgery. `Channel::seal` has always refused to
        // wrap; the split half has to refuse too, and would not if it reached
        // the cipher by a path that skipped the check.
        let (initiator, _) = paired();
        let (mut sealer, _) = initiator.split();
        sealer.counter = u64::MAX;
        assert_eq!(
            sealer.seal(b"one frame too many", b"ctx"),
            Err(HandshakeError::CounterExhausted)
        );
        // And it did not advance past the end while failing.
        assert_eq!(sealer.frames_sent(), u64::MAX);
    }
}
