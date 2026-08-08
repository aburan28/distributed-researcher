//! proofwork -- a research network where verified results are the unit of account.
//!
//! Stage 0: one operator, no token, no consensus. What it does provide is the
//! property that actually matters -- **anyone can independently re-derive every
//! result the network has settled**, from nothing but a copy of the log and this
//! crate.
//!
//! The design notes live in `docs/`. Three rules are load-bearing enough to
//! restate here, because the type system is used to enforce them:
//!
//! 1. **A verifier that cannot run returns [`Status::Unavailable`], never
//!    `Reject`.** A missing toolchain or a crash is an infrastructure fact, not
//!    a fact about the artifact, and [`Verdict::settles`](crate::verifiers::Verdict::settles) is the only path by
//!    which a verdict can move value.
//! 2. **Floats are unrepresentable**, not merely rejected: [`canonical::Value`]
//!    has no float variant, so an object whose identity could differ between
//!    two honest nodes cannot be constructed.
//! 3. **Money arithmetic is checked.** Overflow returns an error rather than
//!    wrapping, in debug and release alike.

pub mod attribution;
pub mod blobs;
pub mod canonical;
pub mod checkpoint;
pub mod crypto;
pub mod dht;
pub mod frontier;
pub mod gossip;
pub mod hex;
pub mod incentive;
pub mod ledger;
pub mod logging;
pub mod node;
pub mod p2p;
pub mod partition;
pub mod records;
pub mod scaffold;
pub mod schema;
pub mod sealed;
pub mod serve;
pub mod store;
pub mod swarm;
pub mod time;
pub mod verifiers;

pub use attribution::{flow, FlowParams};
pub use blobs::{BlobError, BlobStore};
pub use canonical::{digest_bytes, merkle_proof, merkle_root, CanonicalError, Inclusion, Value};
pub use frontier::{FrontierEntry, Ratchet, RatchetError};
pub use gossip::{ingest, Candidate, Population};
pub use incentive::{design::Report as IncentiveReport, NodeParams};
pub use ledger::{Entry, Ledger, LedgerError};
pub use node::{Node, Outcome, RuleViolation};
pub use partition::{assign, assignment_for, beacon, Assignment};
pub use records::{commitment_hash, Claim, Commitment, Objective, RecordError};
pub use schema::{validate_claim, validate_objective, SchemaError};
pub use verifiers::{Status, Verdict, VerifierRegistry};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
