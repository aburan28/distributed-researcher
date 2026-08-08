//! `proofwork` -- the command line.
//!
//! ```text
//! proofwork [--log PATH] [--root PATH] <command>
//!   post      examples/collatz/objective.json
//!   commit    <objective-id> --submitter alice --artifact a.json --nonce n1
//!   reveal    <objective-id> --submitter alice --artifact a.json --nonce n1
//!   settle
//!   audit
//!   verify    --from checkpoint.json [--root-key HEX|FILE] [--audit]
//!   prove     <seq> [--height N] [--out FILE]
//!   check     proof.json --from checkpoint.json [--root-key HEX|FILE]
//!   attribute
//!   log
//! ```
//!
//! Everything this binary prints is re-derivable by anyone holding a copy of the
//! log. That is the whole Stage 0 proposition -- one operator, no consensus, no
//! trust required -- so the commands are deliberately thin: they read files,
//! hand records to [`proofwork::node`], and format what comes back.
//!
//! # Why the argument parser is hand-rolled
//!
//! There is no `clap` in this crate's dependency set, and adding one to parse a
//! handful of subcommands would be a poor trade: the grammar below reads top to
//! bottom, and every failure in it is a typed error rather than a process abort.
//! `clap` calls `exit()` from inside the parser; this one returns, which is what
//! lets every command below be tested by calling it rather than by spawning it.
//!
//! # No panics, including the ones a CLI usually gets away with
//!
//! Three panics that ship in most Rust command-line tools are handled here
//! explicitly, because the no-panic rule in this crate is not decoration:
//!
//! 1. [`std::env::args`] panics on an argument that is not valid UTF-8. This
//!    binary reads [`std::env::args_os`] and reports the bad argument instead.
//! 2. `println!` panics when stdout is gone -- `proofwork log | head -1` is the
//!    everyday way to trigger it, and `scripts/demo.sh` does exactly that. Every
//!    line goes through [`say`], where a closed pipe simply ends the output.
//! 3. Slicing a string by byte offset panics on a multi-byte boundary. The log
//!    summaries truncate by *character*, matching Python's `str` slicing, which
//!    is the same reason they cannot panic.
//!
//! # Exit codes
//!
//! | code | meaning |
//! |------|---------|
//! | 0    | success |
//! | 1    | `audit` found problems, or `verify`/`check` found a mismatch |
//! | 2    | the network refused the submission, or the input was bad |
//! | 3    | `reveal` produced a verdict that settles nothing |
//!
//! Code 3 is the one worth explaining. A *rejected* claim exits 0: rejection is
//! a real answer, reached by a verifier that ran. `unavailable` and
//! `invalid_spec` exit 3, because nothing was learned about the artifact and a
//! caller scripting against this binary must be able to tell "we checked and it
//! is wrong" from "we could not check". Collapsing those two is precisely the
//! confusion the verdict taxonomy exists to prevent.

use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read as _, Write};
use std::path::{Path, PathBuf};
use std::process;

use proofwork::attribution::{payouts_over, FlowError, FlowParams};
use proofwork::canonical::{short, CanonicalError, Value};
use proofwork::checkpoint::{RootKey, SignedCheckpoint};
use proofwork::crypto::identity::Identity;
use proofwork::incentive::design::Report as IncentiveReport;
use proofwork::incentive::{sweep, NodeParams, ParamError, Rat};
use proofwork::ledger::{Codec, Ledger, LedgerError, Proof};
use proofwork::node::Node;
use proofwork::records::{
    commitment_hash, Availability, AvailabilityPool, Claim, Commitment, Objective, PeerRecord,
    RecordError, Undertaking,
};
use proofwork::scaffold;
use proofwork::schema::{validate_claim, validate_objective, SchemaError};
use proofwork::serve::Spool;
use proofwork::store::atrest::{AtRestError, Cipher};
use proofwork::store::{exposure, mirror, quota, Store, StoreError};
use proofwork::time::timestamp;

/// Where the log lives when `--log` and `$PROOFWORK_LOG` are both silent.
const DEFAULT_LOG: &str = "proofwork.jsonl";

/// Bytes of entropy in a generated nonce -- `secrets.token_hex(16)`.
const NONCE_BYTES: usize = 16;

/// Characters of an objective statement shown by `log`.
const STATEMENT_WIDTH: usize = 60;

/// Characters of a verdict detail shown by `log`.
const DETAIL_WIDTH: usize = 40;

// ---------------------------------------------------------------------------
// Adapter for `src/node.rs`
//
// Every call into the rules engine goes through this block, so nothing below
// names a `node` type and a change to that module's signatures lands in one
// place. The surface used is:
//
//     Node::new(ledger, root) -> Node
//     Node::ledger(&self) -> &Ledger
//     Node::post_objective(&mut self, &Objective, ts: &str) -> Result<String, RuleViolation>
//     Node::commit(&mut self, &Commitment, ts: &str)        -> Result<String, RuleViolation>
//     Node::reveal(&mut self, &Claim, ts: &str)             -> Result<Outcome, RuleViolation>
//     Node::audit(&self, rerun: bool) -> Vec<String>
//
// `ts` is required rather than defaulted, unlike the reference implementation's
// `ts: str | None = None`. That is the better contract -- the log's timestamps
// come from one clock reading per command instead of one per append -- and it
// is why [`timestamp`] lives here.
// ---------------------------------------------------------------------------

/// Open the log for reading and wrap it in a node rooted at `--root`.
///
/// No lock: reading a log another process is appending to is safe, because an
/// append never rewrites a line that is already there.
fn open_node(options: &Options) -> Result<Node, CliError> {
    let codec = resolve_codec(options)?;
    let ledger = Ledger::open_with(options.log.as_str(), codec).map_err(CliError::Ledger)?;
    Ok(Node::new(ledger, options.root.as_str()))
}

/// Open the log for writing, taking the single-writer lock.
///
/// Every command that appends goes through here. Two writers over one log
/// each compute `prev` from their own view of the tail and fork it; `audit`
/// notices afterwards, which is too late for the entries already written.
fn open_node_for_writing(options: &Options) -> Result<Node, CliError> {
    let codec = resolve_codec(options)?;
    let ledger =
        Ledger::open_exclusive_with(options.log.as_str(), codec).map_err(CliError::Ledger)?;
    Ok(Node::new(ledger, options.root.as_str()))
}

/// Read-only view of the node's log, for `log` and `attribute`.
fn ledger_of(node: &Node) -> &Ledger {
    node.ledger()
}

fn post_objective(node: &mut Node, objective: &Objective, ts: &str) -> Result<String, CliError> {
    node.post_objective(objective, ts)
        .map_err(|violation| CliError::Refused(violation.to_string()))
}

fn post_peer_record(node: &mut Node, record: &PeerRecord, ts: &str) -> Result<String, CliError> {
    node.post_peer(record, ts)
        .map_err(|violation| CliError::Refused(violation.to_string()))
}

fn refused<T>(result: Result<T, proofwork::node::RuleViolation>) -> Result<T, CliError> {
    result.map_err(|violation| CliError::Refused(violation.to_string()))
}

fn post_commitment(node: &mut Node, commitment: &Commitment, ts: &str) -> Result<(), CliError> {
    node.commit(commitment, ts)
        .map(|_id| ())
        .map_err(|violation| CliError::Refused(violation.to_string()))
}

/// Reveal a claim and flatten the outcome, so no `node` type escapes this block.
fn reveal_claim(node: &mut Node, claim: &Claim, ts: &str) -> Result<RevealReport, CliError> {
    let outcome = node
        .reveal(claim, ts)
        .map_err(|violation| CliError::Refused(violation.to_string()))?;
    Ok(RevealReport {
        claim_id: outcome.claim_id.clone(),
        status: outcome.verdict.status.as_str().to_string(),
        detail: outcome.verdict.detail.clone(),
        settles: outcome.verdict.settles(),
        settled: outcome.settled,
        pending_epoch: outcome.pending_epoch,
        reward: outcome.reward,
        note: outcome.note.clone(),
    })
}

/// Drain every settlement batch whose epoch has closed.
fn settle_now(node: &mut Node, ts: &str) -> Result<Vec<(String, bool, u64, String)>, CliError> {
    let outcomes = node
        .settle_at(ts)
        .map_err(|violation| CliError::Refused(violation.to_string()))?;
    Ok(outcomes
        .into_iter()
        .map(|outcome| {
            (
                outcome.claim_id,
                outcome.settled,
                outcome.reward,
                outcome.note,
            )
        })
        .collect())
}

fn audit_log(node: &Node, rerun: bool) -> Vec<String> {
    node.audit(rerun)
}

/// What `reveal` tells the user, decoupled from `node::Outcome`.
///
/// `settled` and `settles` are separate on purpose and are not redundant: a
/// verdict can settle -- a genuine `reject`, or an `accept` of an artifact
/// already in the log -- while moving no value at all. Printing only one of them
/// would hide either "we reached a real answer" or "you were paid".
#[derive(Debug, Clone, PartialEq, Eq)]
struct RevealReport {
    claim_id: String,
    status: String,
    detail: String,
    /// The verdict is a real answer about the artifact (`accept` or `reject`).
    settles: bool,
    /// Value actually moved.
    settled: bool,
    /// Accepted, but its reveal epoch has not closed, so nothing has been paid
    /// yet and `settled == false` does not mean "earned nothing".
    pending_epoch: Option<u64>,
    reward: u64,
    note: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything this binary can fail with, and nothing it can panic with.
#[derive(Debug)]
enum CliError {
    /// The command line does not parse.
    Usage(String),
    /// The network refused the submission. Carries the rule violation's message
    /// rather than the violation itself, so this type stays independent of
    /// `node`.
    Refused(String),
    Io {
        context: String,
        source: io::Error,
    },
    /// A file the user pointed at is not canonically representable JSON -- a
    /// float, most likely. Worth its own variant because the fix is specific:
    /// carry a scaled integer or a decimal string instead.
    Json {
        path: String,
        source: CanonicalError,
    },
    /// A checkpoint file could not be read as one. Carries the message rather
    /// than the error, so this type stays independent of `checkpoint`.
    Checkpoint(String),
    Record(RecordError),
    /// The body does not match the published schema in `spec/`.
    ///
    /// Separate from [`CliError::Record`] because it fires earlier and says
    /// something different: the record is not the shape third parties implement
    /// against, so it is refused before any constructor gets to interpret it.
    Schema(SchemaError),
    Ledger(LedgerError),
    Flow(FlowError),
    /// A payload already in the log cannot be read back. Distinct from
    /// [`CliError::Record`], which is about a file the user just supplied: this
    /// one means the log itself is malformed, and the entry number is the only
    /// way to find it.
    LogPayload {
        seq: u64,
        reason: String,
    },
    /// A total exceeded the range this build can represent. Python's integers
    /// are unbounded and the reference implementation therefore has no such
    /// failure; here it is reported, never wrapped.
    Overflow(String),
    /// No operating-system entropy for a nonce.
    Entropy(String),
    /// A set of incentive parameters that is not a network.
    Params(ParamError),
    /// The local store could not be read, sized, or copied.
    Store(StoreError),
    /// The at-rest key could not be created, found, or used.
    AtRest(AtRestError),
    /// An argument is not valid UTF-8. `std::env::args` would panic on this.
    NotUnicode(usize),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::Usage(message) => f.write_str(message),
            CliError::Params(error) => write!(f, "{error}"),
            CliError::Store(error) => write!(f, "{error}"),
            CliError::AtRest(error) => write!(f, "{error}"),
            CliError::Refused(message) => f.write_str(message),
            CliError::Io { context, source } => write!(f, "{context}: {source}"),
            CliError::Json { path, source } => write!(f, "{path}: {source}"),
            CliError::Checkpoint(message) => f.write_str(message),
            CliError::Record(source) => write!(f, "{source}"),
            CliError::Schema(source) => write!(f, "{source}"),
            CliError::Ledger(source) => write!(f, "{source}"),
            CliError::Flow(source) => write!(f, "{source}"),
            CliError::LogPayload { seq, reason } => write!(f, "log entry {seq}: {reason}"),
            CliError::Overflow(what) => {
                write!(f, "{what} exceeds the range this build can represent")
            }
            CliError::Entropy(why) => f.write_str(why),
            CliError::NotUnicode(position) => write!(f, "argument {position} is not valid UTF-8"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CliError::Io { source, .. } => Some(source),
            CliError::Json { source, .. } => Some(source),
            CliError::Record(source) => Some(source),
            CliError::Schema(source) => Some(source),
            CliError::Ledger(source) => Some(source),
            CliError::Flow(source) => Some(source),
            _ => None,
        }
    }
}

impl CliError {
    /// The stderr line. `refused:` is reserved for rule violations, matching the
    /// reference implementation, so a script can tell a rejected submission from
    /// a mistyped path without parsing prose.
    fn report(&self) -> String {
        match self {
            CliError::Usage(message) => format!("usage: {message}\ntry `proofwork help`"),
            // A schema violation *is* a refusal: the network declined to record
            // the body, and a script watching for `refused:` needs to see it as
            // one rather than as a local file-handling error.
            CliError::Refused(message) => format!("refused: {message}"),
            CliError::Schema(source) => format!("refused: {source}"),
            other => format!("error: {other}"),
        }
    }

    /// Every error here exits 2. Codes 1 and 3 are outcomes, not errors -- the
    /// log audited and found problems, or a verifier reached no real verdict --
    /// and both are returned from their commands as ordinary success values.
    fn code(&self) -> i32 {
        2
    }
}

// ---------------------------------------------------------------------------
// Command line grammar
// ---------------------------------------------------------------------------

/// Options that apply to every command. Accepted before the command name, where
/// `argparse` puts them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    log: String,
    root: String,
    /// The data directory, when one was chosen. `None` keeps the pre-existing
    /// behaviour exactly: a bare `proofwork.jsonl` wherever you are standing.
    data: Option<String>,
    /// Explicit key file, overriding `$PROOFWORK_KEY` and the default.
    key_file: Option<String>,
    /// File holding the passphrase for a wrapped key.
    passphrase_file: Option<String>,
    /// Size cap on the data directory, in bytes.
    max_size: Option<u64>,
}

impl Options {
    fn from_env() -> Options {
        let data = env::var(proofwork::store::DATA_ENV)
            .ok()
            .filter(|value| !value.is_empty());
        // `--log` and `$PROOFWORK_LOG` still win, and the default when neither
        // is set still depends on whether a data directory was chosen. An
        // operator upgrading into this release must find their log exactly
        // where they left it.
        let log = env::var("PROOFWORK_LOG").ok().filter(|v| !v.is_empty());
        Options {
            log: match (log, &data) {
                (Some(explicit), _) => explicit,
                (None, Some(data)) => Store::new(data).log_path().display().to_string(),
                (None, None) => DEFAULT_LOG.to_string(),
            },
            root: String::from("."),
            data,
            key_file: None,
            passphrase_file: None,
            max_size: None,
        }
    }

    /// The store this invocation is working in.
    ///
    /// Falls back to the log file's own directory when no data directory was
    /// chosen, so `store status` and `sync` mean something even for an operator
    /// who never adopted the layout.
    fn store(&self) -> Store {
        let root = match &self.data {
            Some(data) => PathBuf::from(data),
            None => PathBuf::from(&self.log)
                .parent()
                .map(Path::to_path_buf)
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| PathBuf::from(".")),
        };
        Store::new(root).with_limit(self.max_size)
    }

    /// Where the at-rest key lives.
    fn key_path(&self) -> PathBuf {
        match &self.key_file {
            Some(path) => PathBuf::from(path),
            None => self.store().default_key_path(),
        }
    }

    /// The passphrase, if one was supplied.
    ///
    /// From a file or `$PROOFWORK_PASSPHRASE`, never from a prompt. Reading a
    /// passphrase without echoing it needs terminal control this crate has no
    /// dependency for, and echoing one into a shell's scrollback and history is
    /// worse than not offering the option.
    fn passphrase(&self) -> Result<Option<String>, CliError> {
        if let Some(path) = &self.passphrase_file {
            return read_passphrase_file(path).map(Some);
        }
        Ok(env::var("PROOFWORK_PASSPHRASE")
            .ok()
            .filter(|value| !value.is_empty()))
    }
}

/// Read a passphrase from a file.
///
/// Only the trailing newline is stripped. A passphrase with leading or interior
/// whitespace is a passphrase, and trimming it would silently open a different
/// key than the one the operator wrote down.
fn read_passphrase_file(path: &str) -> Result<String, CliError> {
    let text = fs::read_to_string(path).map_err(|source| CliError::Io {
        context: format!("reading {path}"),
        source,
    })?;
    Ok(text.trim_end_matches(['\n', '\r']).to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Post {
        objective: String,
    },
    Commit {
        objective_id: String,
        submitter: String,
        artifact: String,
        /// `None` means "generate one", matching `args.nonce or token_hex(16)`.
        nonce: Option<String>,
        /// Identity file to sign with. When set, the signing key's public half
        /// replaces `--submitter`: a signed record's submitter *is* its key.
        identity: Option<String>,
    },
    Reveal {
        objective_id: String,
        submitter: String,
        artifact: String,
        nonce: String,
        cites: Vec<String>,
        /// Identity file to sign with. See `Commit::identity`.
        identity: Option<String>,
    },
    Settle,
    /// Sign the log's current state so a reader can pin what this operator
    /// claimed at a point in time.
    ///
    /// The counterpart to `verify --from`: without a way to *write* a
    /// checkpoint from the CLI, only the p2p daemon could publish one, and an
    /// operator not running p2p had nothing for a contributor to check
    /// against.
    Checkpoint {
        root_key: String,
        out: Option<String>,
    },
    /// Admit records queued by `proofwork-serve` into the log.
    ///
    /// Separate from the server on purpose: the server is a transport and this
    /// is the rules engine. A queued record has been parsed and schema-checked
    /// and *nothing else* -- every admission rule is re-derived here, against
    /// the whole log, by the same code path the CLI uses.
    Drain {
        queue: String,
        /// Report what would be admitted without appending anything.
        dry_run: bool,
    },
    Audit {
        rerun: bool,
    },
    Verify {
        checkpoint: String,
        /// Hex, or a path to a file holding hex. `None` trusts the key inside
        /// the checkpoint, which authenticates nothing -- see [`cmd_verify`].
        root_key: Option<String>,
        /// Also re-derive the rules over the signed prefix.
        audit: bool,
        rerun: bool,
    },
    /// Emit a Merkle inclusion proof for one entry.
    ///
    /// The half of [`Command::Checkpoint`] that was missing. A checkpoint says
    /// "the log at height H has root R"; this says "and entry N is under R",
    /// in fifteen hashes rather than 20,000 entries.
    Prove {
        seq: u64,
        /// Prove against the log's first `height` entries rather than all of
        /// them. A root is over a whole log, so a proof from a log that has
        /// grown since the reader's checkpoint was signed will not check
        /// against it -- this is how the prover meets the reader where they
        /// are.
        height: Option<u64>,
        out: Option<String>,
    },
    /// Check an inclusion proof against a root.
    ///
    /// The only command that reads neither a log nor a bundle. That is the
    /// point: whoever runs this has no copy of the log, which is why they were
    /// sent a proof.
    Check {
        proof: String,
        /// The root, as `sha256:` hex. Spelled `--merkle-root` rather than
        /// `--root`, which is the global flag naming the *bundle directory*: two
        /// meanings for one flag is how a caller silently checks against nothing.
        root: Option<String>,
        /// A signed checkpoint to take the root from, instead of `--root`.
        checkpoint: Option<String>,
        /// Verify the checkpoint's signature against this key first. Without
        /// it the checkpoint authenticates nothing -- see [`cmd_check`].
        root_key: Option<String>,
    },
    /// Availability: promise to hold the log, answer a sample, fund and pay.
    ///
    /// Grouped under one command because the four are one mechanism and a
    /// reader meeting `undertake` needs to find `answer` next to it.
    Availability {
        action: AvailabilityAction,
    },
    Attribute {
        params: FlowParams,
    },
    Blob {
        action: BlobAction,
    },
    /// Evaluate the node-operator incentives at a parameter set.
    ///
    /// The only command that reads no log. It answers a question about the
    /// *rules* rather than about anything that has happened, so it takes its
    /// whole input from flags and is safe to run anywhere.
    Incentives {
        params: Box<NodeParams>,
        /// Also report how far each parameter can move before the mechanism
        /// breaks. Opt-in because it is hundreds of full solver runs.
        robustness: bool,
        /// Parameters to walk across a grid instead of evaluating one point.
        ///
        /// Empty is the ordinary single-point report. Non-empty replaces the
        /// prose report with a table, because the two answer different
        /// questions and interleaving them would give a reader a hundred
        /// reports to compare by eye -- the thing the sweep exists to stop.
        sweep: Vec<sweep::Axis>,
        /// Where the table goes. `None` is standard output.
        out: Option<String>,
        format: TableFormat,
    },
    /// One bounty round end to end: post if needed, commit, wait, reveal.
    ///
    /// A convenience wrapper over the existing primitives and nothing more --
    /// no new record kind, no change to what `commit` and `reveal` accept, no
    /// change to how settlement orders. It exists because trying one artifact
    /// against one objective was five invocations with a manual sleep across
    /// the epoch boundary in the middle, which is what `scripts/demo.sh` and
    /// `scripts/ratchet-demo.sh` hand-roll in bash.
    Try {
        /// An objective id, or a file to post first.
        objective: String,
        submitter: String,
        artifact: String,
        nonce: Option<String>,
        identity: Option<String>,
        cites: Vec<String>,
        /// Also wait out the reveal epoch and settle, so the round ends with a
        /// payout rather than a "settles when epoch N closes".
        settle: bool,
    },
    /// Write the files a new objective starts from, and post nothing.
    ///
    /// The posting stays a separate, reviewed step: an objective's statement
    /// is untrusted text that a human decides to fund, and a tool that wrote
    /// and funded one in the same breath would remove the place that decision
    /// happens. See [`proofwork::scaffold`].
    Scaffold {
        request: Box<scaffold::Request>,
        /// Overwrite files that are already there. Off by default, because the
        /// obvious mistake is scaffolding over an objective already posted --
        /// whose pin is in the log and whose id covers it.
        force: bool,
    },
    /// Create an at-rest key.
    /// Canonicalize one JSON value and print its digest.
    Canon {
        input: String,
    },
    /// Decode one record and report whether it is admissible, without a log.
    Decode {
        kind: String,
        record: String,
    },
    /// Create a submitter identity: an ed25519 keypair whose public half is
    /// the submitter name.
    Identity {
        out: String,
    },
    /// Announce a peer identity in the log, or move one to a new address.
    ///
    /// The record that makes finding the network part of obtaining the log
    /// rather than a second bootstrap problem. See [`proofwork::records::PeerRecord`].
    Peer {
        identity: String,
        transport: String,
        addr: String,
        /// `None` means "one past whatever this identity has already said",
        /// which is what an operator moving house actually wants and what they
        /// would otherwise have to look up by reading their own log.
        seq: Option<u64>,
    },
    Keygen {
        wrap: bool,
    },
    /// Report or reclaim local storage.
    Store {
        action: StoreAction,
    },
    /// Copy the store to a directory of the operator's choosing.
    Sync {
        destination: String,
        options: mirror::Options,
    },
    Log,
    Help,
}

/// How a sweep's table is written.
///
/// Both are line-oriented, which is the point: whatever an operator already
/// plots with reads one of them, and neither needs this tool to grow a
/// formatter with opinions about column widths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TableFormat {
    Csv,
    Jsonl,
}

/// What `proofwork blob` was asked to do.
///
/// Collection is a command rather than something a sync round does on its way
/// past, and that is deliberate: a node cannot distinguish a blob nobody wants
/// from a blob pinned by an objective it has not synced yet, so a timer-driven
/// collector would delete exactly the code its peers are about to ask it for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BlobAction {
    /// Every content address held.
    List,
    /// Pins the log names that this node cannot obtain — why a verdict came
    /// back `unavailable`.
    Need,
    /// Copy every pinned file the bundle has into the store, so peers can fetch
    /// it. Idempotent, and what a log written before blobs existed needs.
    Publish,
    /// Drop blobs no objective in the log pins.
    Collect,
    /// Seed this node's blobs to strangers over the encrypted transport.
    ///
    /// The other half of [`BlobAction::Need`], which has always said a missing
    /// pin stays missing "until a peer serves them" while offering no way to
    /// *be* that peer.
    Serve { identity: String, listen: String },
    /// Fetch every pin this log names and this node lacks.
    Fetch {
        identity: String,
        peers: Vec<String>,
        seconds: u64,
    },
}

/// The four steps of the availability mechanism.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AvailabilityAction {
    /// Promise to hold this log at its current root and height.
    ///
    /// No `--height`. The promise covers the whole log as it stands, because
    /// the size of the promise is what the pool pays for, and a promiser who
    /// could choose it chose one entry and took a full share.
    Undertake { identity: String },
    /// Answer this epoch's sample for every promise this identity made.
    Answer {
        identity: String,
        epoch: Option<u64>,
    },
    /// Put up money for a run of epochs.
    Fund {
        funder: String,
        per_epoch: u64,
        from_epoch: u64,
        to_epoch: u64,
    },
    /// Pay the answers to a closed epoch and name the silence.
    Settle { epoch: Option<u64> },
    /// What is promised, what is funded, what has been answered.
    Status,
}

/// How long a `blob fetch` waits before giving up on a digest.
///
/// A blob fetch is a many-peer transfer over a network nobody controls, so
/// there is no principled value -- only one large enough that a slow seed is
/// not mistaken for an absent one, and small enough that an operator with a
/// dead peer list gets an answer. `--timeout` overrides it.
const DEFAULT_FETCH_SECONDS: u64 = 60;

#[derive(Debug, Clone, PartialEq, Eq)]
enum StoreAction {
    /// How much is used, split into what can and cannot be evicted.
    Status,
    /// Evict reclaimable content until the cap is met.
    Gc,
    /// Convert a plaintext log to a sealed one, in place.
    Encrypt,
    /// Write a plaintext copy of the log somewhere, leaving the store sealed.
    ///
    /// The inverse of `Encrypt`, and the reason it has to exist: without it,
    /// sealing a store is a one-way door out of the network's own verifiability
    /// claim -- the operator can no longer produce the readable log anyone else
    /// would audit.
    Export {
        /// Where to write it. Never the store's own log.
        out: String,
    },
    /// Re-seal the log under a fresh at-rest key.
    Rekey {
        /// Passphrase to wrap the *new* key with, from a file.
        ///
        /// Separate from `--passphrase-file`, which opens the *old* key. They
        /// have to be separable: the commonest reason to rotate is that the old
        /// secret is suspect, and a command that could only reuse it would be
        /// no help in the case it exists for.
        new_passphrase_file: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Invocation {
    options: Options,
    command: Command,
}

/// A position in the argument list.
///
/// Deliberately not an iterator: several of the parsers below need to look at
/// the next token *without* consuming it -- `--cites` stops at the first token
/// that looks like a flag -- and a cursor says that more plainly than a
/// `Peekable` threaded through six functions.
struct Cursor {
    tokens: Vec<String>,
    at: usize,
}

impl Cursor {
    fn new(tokens: Vec<String>) -> Cursor {
        Cursor { tokens, at: 0 }
    }

    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.at).map(String::as_str)
    }

    /// Peek, but owned. Callers match on this and then consume, which a borrowed
    /// peek would not allow while the match is still live.
    fn peek_owned(&self) -> Option<String> {
        self.peek().map(str::to_string)
    }

    fn take(&mut self) -> Option<String> {
        let token = self.tokens.get(self.at).cloned();
        if token.is_some() {
            // Saturating rather than `+= 1`: `at` never passes `tokens.len()`,
            // but a counter that cannot wrap needs no argument about why.
            self.at = self.at.saturating_add(1);
        }
        token
    }

    /// The value belonging to `flag`.
    ///
    /// A following flag is refused rather than swallowed, so `--submitter
    /// --artifact a.json` is an error instead of a submitter literally named
    /// `--artifact`. That mirrors `argparse` and, more to the point, stops a
    /// typo from being recorded in an append-only log.
    fn value(&mut self, flag: &str) -> Result<String, CliError> {
        let missing = || CliError::Usage(format!("{flag} needs a value"));
        match self.peek() {
            None => Err(missing()),
            Some(next) if is_flag(next) => Err(missing()),
            Some(_) => self.take().ok_or_else(missing),
        }
    }
}

/// Does this token look like an option rather than a value?
///
/// A bare `-` is not a flag: it is the conventional spelling of "standard
/// input", and refusing it here would be a surprise with no upside.
fn is_flag(token: &str) -> bool {
    token.starts_with('-') && token.chars().count() > 1
}

/// Rewrite `--flag=value` into `--flag` `value`.
///
/// `argparse` accepts both spellings and shell users expect both. Doing it as a
/// pre-pass keeps every parser below dealing with exactly one form. Only tokens
/// that already look like long options are touched, so a positional path
/// containing `=` survives intact.
fn expand_inline_values(tokens: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(tokens.len());
    for token in tokens {
        if token.starts_with("--") {
            if let Some(split) = token.find('=') {
                let (flag, rest) = token.split_at(split);
                out.push(flag.to_string());
                // `rest` starts with the single ASCII byte `=`, so skipping one
                // byte lands on a character boundary. `get` rather than a slice
                // expression, so that even a wrong assumption cannot panic.
                out.push(rest.get(1..).unwrap_or("").to_string());
                continue;
            }
        }
        out.push(token);
    }
    out
}

fn parse(argv: Vec<String>) -> Result<Invocation, CliError> {
    let mut cursor = Cursor::new(expand_inline_values(argv));
    let mut options = Options::from_env();

    while let Some(token) = cursor.peek_owned() {
        if token == "--log" {
            cursor.take();
            options.log = cursor.value("--log")?;
        } else if token == "--root" {
            cursor.take();
            options.root = cursor.value("--root")?;
        } else if token == "--data-dir" {
            cursor.take();
            let data = cursor.value("--data-dir")?;
            // Only redirect the log if nothing more specific already did.
            if env::var("PROOFWORK_LOG")
                .ok()
                .filter(|v| !v.is_empty())
                .is_none()
                && options.log == DEFAULT_LOG
            {
                options.log = Store::new(&data).log_path().display().to_string();
            }
            options.data = Some(data);
        } else if token == "--key-file" {
            cursor.take();
            options.key_file = Some(cursor.value("--key-file")?);
        } else if token == "--passphrase-file" {
            cursor.take();
            options.passphrase_file = Some(cursor.value("--passphrase-file")?);
        } else if token == "--max-size" {
            cursor.take();
            let text = cursor.value("--max-size")?;
            options.max_size = Some(proofwork::store::parse_size(&text).map_err(CliError::Store)?);
        } else if token == "-h" || token == "--help" {
            cursor.take();
            return Ok(Invocation {
                options,
                command: Command::Help,
            });
        } else {
            break;
        }
    }

    let name = match cursor.take() {
        Some(name) => name,
        None => return Err(CliError::Usage(String::from("no command given"))),
    };

    let command = match name.as_str() {
        "post" => parse_post(&mut cursor)?,
        "commit" => parse_commit(&mut cursor)?,
        "reveal" => parse_reveal(&mut cursor)?,
        "settle" => {
            expect_end(&mut cursor, "settle")?;
            Command::Settle
        }
        "checkpoint" => parse_checkpoint(&mut cursor)?,
        "drain" => parse_drain(&mut cursor)?,
        "audit" => parse_audit(&mut cursor)?,
        "verify" => parse_verify(&mut cursor)?,
        "prove" => parse_prove(&mut cursor)?,
        "check" => parse_check(&mut cursor)?,
        "availability" => parse_availability(&mut cursor)?,
        "attribute" => parse_attribute(&mut cursor)?,
        "blob" => parse_blob(&mut cursor)?,
        "incentives" => parse_incentives(&mut cursor)?,
        "scaffold" => parse_scaffold(&mut cursor)?,
        "try" => parse_try(&mut cursor)?,
        "canon" => {
            let mut input: Option<String> = None;
            while let Some(token) = cursor.take() {
                if token == "--input" {
                    input = Some(cursor.value("--input")?);
                } else if is_flag(&token) {
                    return Err(CliError::Usage(format!("canon: unknown option {token:?}")));
                } else if input.is_some() {
                    return Err(CliError::Usage(format!(
                        "canon: unexpected argument {token:?}"
                    )));
                } else {
                    input = Some(token);
                }
            }
            Command::Canon {
                input: require(input, "canon", "--input <file>")?,
            }
        }
        "decode" => {
            let mut kind: Option<String> = None;
            let mut record: Option<String> = None;
            while let Some(token) = cursor.take() {
                if token == "--record" {
                    record = Some(cursor.value("--record")?);
                } else if is_flag(&token) {
                    return Err(CliError::Usage(format!("decode: unknown option {token:?}")));
                } else if kind.is_some() {
                    return Err(CliError::Usage(format!(
                        "decode: unexpected argument {token:?}"
                    )));
                } else {
                    kind = Some(token);
                }
            }
            Command::Decode {
                kind: require(kind, "decode", "a record kind")?,
                record: require(record, "decode", "--record <file>")?,
            }
        }
        "peer" => parse_peer(&mut cursor)?,
        "identity" => {
            let mut out: Option<String> = None;
            while let Some(token) = cursor.take() {
                if token == "--out" {
                    out = Some(cursor.value("--out")?);
                } else if is_flag(&token) {
                    return Err(CliError::Usage(format!(
                        "identity: unknown option {token:?}"
                    )));
                } else if out.is_some() {
                    return Err(CliError::Usage(format!(
                        "identity: unexpected argument {token:?}"
                    )));
                } else {
                    out = Some(token);
                }
            }
            Command::Identity {
                out: require(out, "identity", "--out <file>")?,
            }
        }
        "keygen" => parse_keygen(&mut cursor)?,
        "store" => parse_store(&mut cursor)?,
        "sync" => parse_sync(&mut cursor)?,
        "log" => {
            expect_end(&mut cursor, "log")?;
            Command::Log
        }
        "help" => Command::Help,
        other => return Err(CliError::Usage(format!("unknown command {other:?}"))),
    };

    Ok(Invocation { options, command })
}

fn parse_post(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut objective: Option<String> = None;
    while let Some(token) = cursor.take() {
        if is_flag(&token) {
            return Err(CliError::Usage(format!("post: unknown option {token:?}")));
        }
        if objective.is_some() {
            return Err(CliError::Usage(format!(
                "post: unexpected argument {token:?}"
            )));
        }
        objective = Some(token);
    }
    Ok(Command::Post {
        objective: require(objective, "post", "an objective JSON file")?,
    })
}

fn parse_commit(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut objective_id: Option<String> = None;
    let mut submitter: Option<String> = None;
    let mut artifact: Option<String> = None;
    let mut nonce: Option<String> = None;
    let mut identity: Option<String> = None;

    while let Some(token) = cursor.take() {
        if token == "--submitter" {
            submitter = Some(cursor.value("--submitter")?);
        } else if token == "--artifact" {
            artifact = Some(cursor.value("--artifact")?);
        } else if token == "--nonce" {
            nonce = Some(cursor.value("--nonce")?);
        } else if token == "--identity" {
            identity = Some(cursor.value("--identity")?);
        } else if is_flag(&token) {
            return Err(CliError::Usage(format!("commit: unknown option {token:?}")));
        } else if objective_id.is_some() {
            return Err(CliError::Usage(format!(
                "commit: unexpected argument {token:?}"
            )));
        } else {
            objective_id = Some(token);
        }
    }

    Ok(Command::Commit {
        objective_id: require(objective_id, "commit", "an objective id")?,
        // With `--identity` the key decides the submitter, so the flag is
        // optional: requiring both invites them to disagree, and a record
        // whose submitter contradicts its signature is refused anyway.
        submitter: match (submitter, &identity) {
            (Some(submitter), _) => submitter,
            (None, Some(_)) => String::new(),
            (None, None) => {
                return Err(CliError::Usage(
                    "commit: --submitter or --identity is required".into(),
                ))
            }
        },
        artifact: require(artifact, "commit", "--artifact")?,
        // An explicitly empty `--nonce ""` generates one, exactly as Python's
        // `args.nonce or token_hex(16)` does. An empty nonce is not a nonce.
        nonce: nonce.filter(|value| !value.is_empty()),
        identity,
    })
}

fn parse_reveal(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut objective_id: Option<String> = None;
    let mut submitter: Option<String> = None;
    let mut artifact: Option<String> = None;
    let mut nonce: Option<String> = None;
    let mut identity: Option<String> = None;
    let mut cites: Vec<String> = Vec::new();

    while let Some(token) = cursor.take() {
        if token == "--submitter" {
            submitter = Some(cursor.value("--submitter")?);
        } else if token == "--artifact" {
            artifact = Some(cursor.value("--artifact")?);
        } else if token == "--nonce" {
            nonce = Some(cursor.value("--nonce")?);
        } else if token == "--identity" {
            identity = Some(cursor.value("--identity")?);
        } else if token == "--cites" {
            // `nargs="*"`: consume until the next flag or the end. Claim ids are
            // `sha256:` digests, so none of them can be mistaken for a flag.
            while let Some(next) = cursor.peek_owned() {
                if is_flag(&next) {
                    break;
                }
                cursor.take();
                cites.push(next);
            }
        } else if is_flag(&token) {
            return Err(CliError::Usage(format!("reveal: unknown option {token:?}")));
        } else if objective_id.is_some() {
            return Err(CliError::Usage(format!(
                "reveal: unexpected argument {token:?}"
            )));
        } else {
            objective_id = Some(token);
        }
    }

    Ok(Command::Reveal {
        objective_id: require(objective_id, "reveal", "an objective id")?,
        submitter: match (submitter, &identity) {
            (Some(submitter), _) => submitter,
            (None, Some(_)) => String::new(),
            (None, None) => {
                return Err(CliError::Usage(
                    "reveal: --submitter or --identity is required".into(),
                ))
            }
        },
        artifact: require(artifact, "reveal", "--artifact")?,
        // Required, unlike on `commit`: revealing is opening a commitment, and
        // the nonce is part of what that commitment hashed. There is nothing to
        // generate.
        nonce: require(nonce, "reveal", "--nonce")?,
        cites,
        identity,
    })
}

fn parse_audit(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut rerun = true;
    while let Some(token) = cursor.take() {
        if token == "--no-rerun" {
            rerun = false;
        } else {
            return Err(CliError::Usage(format!("audit: unknown option {token:?}")));
        }
    }
    Ok(Command::Audit { rerun })
}

fn parse_checkpoint(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut root_key: Option<String> = None;
    let mut out: Option<String> = None;
    while let Some(token) = cursor.take() {
        if token == "--root-key" {
            root_key = Some(cursor.value("--root-key")?);
        } else if token == "--out" {
            out = Some(cursor.value("--out")?);
        } else {
            return Err(CliError::Usage(format!(
                "checkpoint: unknown option {token:?}"
            )));
        }
    }
    Ok(Command::Checkpoint {
        root_key: require(root_key, "checkpoint", "--root-key FILE")?,
        out,
    })
}

fn parse_drain(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut queue: Option<String> = None;
    let mut dry_run = false;
    while let Some(token) = cursor.take() {
        if token == "--queue" {
            queue = Some(cursor.value("--queue")?);
        } else if token == "--dry-run" {
            dry_run = true;
        } else if is_flag(&token) {
            return Err(CliError::Usage(format!("drain: unknown option {token:?}")));
        } else if queue.is_none() {
            queue = Some(token);
        } else {
            return Err(CliError::Usage(format!("drain: unexpected {token:?}")));
        }
    }
    Ok(Command::Drain {
        queue: require(queue, "drain", "a queue directory")?,
        dry_run,
    })
}

fn parse_verify(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut checkpoint: Option<String> = None;
    let mut root_key: Option<String> = None;
    let mut audit = false;
    // Mirrors `audit`: re-running the verifiers is the default, and
    // `--no-rerun` is the way to ask for the cheap structural check.
    let mut rerun = true;

    while let Some(token) = cursor.take() {
        if token == "--from" {
            checkpoint = Some(cursor.value("--from")?);
        } else if token == "--root-key" {
            root_key = Some(cursor.value("--root-key")?);
        } else if token == "--audit" {
            audit = true;
        } else if token == "--no-rerun" {
            rerun = false;
        } else if is_flag(&token) {
            return Err(CliError::Usage(format!("verify: unknown option {token:?}")));
        } else if checkpoint.is_some() {
            return Err(CliError::Usage(format!(
                "verify: unexpected argument {token:?}"
            )));
        } else {
            checkpoint = Some(token);
        }
    }

    Ok(Command::Verify {
        checkpoint: require(checkpoint, "verify", "--from <checkpoint.json>")?,
        root_key,
        audit,
        rerun,
    })
}

fn parse_availability(cursor: &mut Cursor) -> Result<Command, CliError> {
    let action = cursor.take().unwrap_or_else(|| String::from("status"));
    let mut identity: Option<String> = None;
    let mut funder: Option<String> = None;
    let mut numbers: BTreeMap<&'static str, u64> = BTreeMap::new();
    while let Some(token) = cursor.take() {
        let name = match token.as_str() {
            "--identity" => {
                identity = Some(cursor.value("--identity")?);
                continue;
            }
            "--funder" => {
                funder = Some(cursor.value("--funder")?);
                continue;
            }
            "--epoch" => "epoch",
            "--per-epoch" => "per-epoch",
            "--from-epoch" => "from-epoch",
            "--to-epoch" => "to-epoch",
            other => {
                return Err(CliError::Usage(format!(
                    "availability {action}: unknown option {other:?}"
                )))
            }
        };
        let text = cursor.value(name)?;
        numbers.insert(name, parse_u64(&text, name)?);
    }
    let need_identity = |what: &str| -> Result<String, CliError> {
        identity
            .clone()
            .ok_or_else(|| CliError::Usage(format!("availability {what}: --identity <file>")))
    };
    let action = match action.as_str() {
        "undertake" => AvailabilityAction::Undertake {
            identity: need_identity("undertake")?,
        },
        "answer" => AvailabilityAction::Answer {
            identity: need_identity("answer")?,
            epoch: numbers.get("epoch").copied(),
        },
        "fund" => {
            let need = |name: &'static str| -> Result<u64, CliError> {
                numbers
                    .get(name)
                    .copied()
                    .ok_or_else(|| CliError::Usage(format!("availability fund: --{name} <units>")))
            };
            AvailabilityAction::Fund {
                funder: require(funder, "availability fund", "--funder <name>")?,
                per_epoch: need("per-epoch")?,
                from_epoch: need("from-epoch")?,
                to_epoch: need("to-epoch")?,
            }
        }
        "settle" => AvailabilityAction::Settle {
            epoch: numbers.get("epoch").copied(),
        },
        "status" => AvailabilityAction::Status,
        other => {
            return Err(CliError::Usage(format!(
                "availability: unknown action {other:?}; \
                 expected undertake, answer, fund, settle or status"
            )))
        }
    };
    Ok(Command::Availability { action })
}

fn parse_prove(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut seq: Option<String> = None;
    let mut height: Option<String> = None;
    let mut out: Option<String> = None;
    while let Some(token) = cursor.take() {
        if token == "--height" {
            height = Some(cursor.value("--height")?);
        } else if token == "--out" {
            out = Some(cursor.value("--out")?);
        } else if is_flag(&token) {
            return Err(CliError::Usage(format!("prove: unknown option {token:?}")));
        } else if seq.is_some() {
            return Err(CliError::Usage(format!(
                "prove: unexpected argument {token:?}"
            )));
        } else {
            seq = Some(token);
        }
    }
    let number = |what: &str, text: String| -> Result<u64, CliError> {
        text.parse::<u64>()
            .map_err(|_| CliError::Usage(format!("prove: {what} must be a number, got {text:?}")))
    };
    Ok(Command::Prove {
        seq: number("seq", require(seq, "prove", "an entry sequence number")?)?,
        height: height.map(|text| number("--height", text)).transpose()?,
        out,
    })
}

fn parse_check(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut proof: Option<String> = None;
    let mut root: Option<String> = None;
    let mut checkpoint: Option<String> = None;
    let mut root_key: Option<String> = None;
    while let Some(token) = cursor.take() {
        if token == "--merkle-root" {
            root = Some(cursor.value("--merkle-root")?);
        } else if token == "--from" {
            checkpoint = Some(cursor.value("--from")?);
        } else if token == "--root-key" {
            root_key = Some(cursor.value("--root-key")?);
        } else if is_flag(&token) {
            return Err(CliError::Usage(format!("check: unknown option {token:?}")));
        } else if proof.is_some() {
            return Err(CliError::Usage(format!(
                "check: unexpected argument {token:?}"
            )));
        } else {
            proof = Some(token);
        }
    }
    // Refused rather than ranked. Given both, a precedence rule would silently
    // ignore one of two roots the caller believed in -- and the case where they
    // disagree is exactly the case that matters.
    if root.is_some() && checkpoint.is_some() {
        return Err(CliError::Usage(String::from(
            "check: give --merkle-root or --from, not both",
        )));
    }
    if root.is_none() && checkpoint.is_none() {
        return Err(CliError::Usage(String::from(
            "check: needs --merkle-root <sha256:...> or --from <checkpoint.json>",
        )));
    }
    Ok(Command::Check {
        proof: require(proof, "check", "a proof JSON file")?,
        root,
        checkpoint,
        root_key,
    })
}

/// `try <objective-id|objective.json> --submitter S --artifact FILE [--nonce N]`
///
/// Takes the same flags `commit` and `reveal` take, because it is those two
/// commands with the wait in between. A flag that meant something different
/// here than it does there would be the whole cost of the convenience.
fn parse_try(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut objective: Option<String> = None;
    let mut submitter: Option<String> = None;
    let mut artifact: Option<String> = None;
    let mut nonce: Option<String> = None;
    let mut identity: Option<String> = None;
    let mut cites: Vec<String> = Vec::new();
    let mut settle = false;

    while let Some(token) = cursor.take() {
        if token == "--submitter" {
            submitter = Some(cursor.value("--submitter")?);
        } else if token == "--artifact" {
            artifact = Some(cursor.value("--artifact")?);
        } else if token == "--nonce" {
            nonce = Some(cursor.value("--nonce")?);
        } else if token == "--identity" {
            identity = Some(cursor.value("--identity")?);
        } else if token == "--settle" {
            settle = true;
        } else if token == "--cites" {
            // Same `nargs="*"` shape as `reveal`: claim ids are `sha256:`
            // digests, so none can be mistaken for a flag.
            while let Some(next) = cursor.peek_owned() {
                if is_flag(&next) {
                    break;
                }
                cursor.take();
                cites.push(next);
            }
        } else if is_flag(&token) {
            return Err(CliError::Usage(format!("try: unknown option {token:?}")));
        } else if objective.is_some() {
            return Err(CliError::Usage(format!(
                "try: unexpected argument {token:?}"
            )));
        } else {
            objective = Some(token);
        }
    }

    Ok(Command::Try {
        objective: require(objective, "try", "an objective id or a JSON file")?,
        submitter: match (submitter, &identity) {
            (Some(submitter), _) => submitter,
            (None, Some(_)) => String::new(),
            (None, None) => {
                return Err(CliError::Usage(
                    "try: --submitter or --identity is required".into(),
                ))
            }
        },
        artifact: require(artifact, "try", "--artifact")?,
        nonce: nonce.filter(|value| !value.is_empty()),
        identity,
        cites,
        settle,
    })
}

/// `scaffold <name> --kind <kind> [--out DIR] [--artifact-example FILE] ...`
///
/// Reads a worked artifact if one is offered and refuses everything it cannot
/// turn into a postable objective, so that the failure is a command line error
/// rather than a directory of files that `post` will reject.
fn parse_scaffold(cursor: &mut Cursor) -> Result<Command, CliError> {
    let name = match cursor.peek() {
        Some(token) if !is_flag(token) => cursor.take().unwrap_or_default(),
        _ => {
            return Err(CliError::Usage(String::from(
                "scaffold needs a name: scaffold <name> --kind <certificate|evaluator|statistical|replay|lean>",
            )))
        }
    };
    let mut kind: Option<scaffold::Kind> = None;
    let mut parent: Option<String> = None;
    let mut goal: Option<String> = None;
    let mut statement: Option<String> = None;
    let mut funder: Option<String> = None;
    let mut reward: Option<u64> = None;
    let mut example: Option<String> = None;
    let mut force = false;

    while let Some(token) = cursor.take() {
        match token.as_str() {
            "--kind" => {
                let value = cursor.value("--kind")?;
                kind = Some(scaffold::Kind::parse(&value).ok_or_else(|| {
                    CliError::Usage(format!(
                        "scaffold --kind: expected one of ({}), got {value:?}",
                        scaffold::KINDS
                            .iter()
                            .map(|kind| kind.name())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                })?);
            }
            "--out" => parent = Some(cursor.value("--out")?),
            "--goal" => goal = Some(cursor.value("--goal")?),
            "--statement" => statement = Some(cursor.value("--statement")?),
            "--funder" => funder = Some(cursor.value("--funder")?),
            "--reward" => reward = Some(parse_u64(&cursor.value("--reward")?, "--reward")?),
            "--artifact-example" => example = Some(cursor.value("--artifact-example")?),
            "--force" => force = true,
            other => {
                return Err(CliError::Usage(format!(
                    "scaffold: unknown option {other:?}"
                )))
            }
        }
    }

    let kind = kind.ok_or_else(|| {
        CliError::Usage(String::from(
            "scaffold needs --kind: the verifier decides what a submission has to be,              and there is no sensible default for that",
        ))
    })?;
    let mut request = scaffold::Request::new(name, kind);
    if let Some(parent) = parent {
        request.parent = parent;
    }
    if let Some(goal) = goal {
        request.goal = goal;
    }
    if let Some(statement) = statement {
        request.statement = statement;
    }
    if let Some(funder) = funder {
        request.funder = funder;
    }
    if let Some(reward) = reward {
        request.reward = reward;
    }
    if let Some(path) = example {
        request.artifact_example = Some(read_json(&path)?);
    }
    // Planned here so a bad name or an escaping --out is a usage error before
    // any directory is created.
    scaffold::plan(&request).map_err(|error| CliError::Usage(error.to_string()))?;

    Ok(Command::Scaffold {
        request: Box::new(request),
        force,
    })
}

/// `incentives [--nodes N] [--settled N] [--stake N] [--fee N/D] ...`
///
/// Every flag overrides one field of [`NodeParams::reference`], so an analyst
/// changes the number they care about and inherits a coherent set for the rest.
/// The alternative -- requiring all twenty-odd -- would make the command
/// unusable, and defaulting the ones the user forgot to zero would silently
/// produce an answer about a different network.
///
/// Rates are written as exact fractions (`1/100`), never as decimals. That is
/// not fussiness: the whole harness exists to make equilibrium comparisons
/// decidable, and accepting `0.01` here would mean parsing it into a float and
/// throwing that away at the first threshold comparison.
fn parse_incentives(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut params = NodeParams::reference();
    let mut robustness = false;
    let mut sweep_axes: Vec<sweep::Axis> = Vec::new();
    let mut out: Option<String> = None;
    let mut format = TableFormat::Csv;

    while let Some(token) = cursor.take() {
        match token.as_str() {
            "--robustness" => robustness = true,
            "--sweep" => {
                let spec = cursor.value("--sweep")?;
                let axis = sweep::Axis::parse(&spec)
                    .map_err(|error| CliError::Usage(error.to_string()))?;
                // A parameter swept twice is a grid with the same column
                // twice, where the second silently overwrites the first at
                // every point. Refused rather than resolved, because either
                // resolution surprises somebody.
                if sweep_axes.iter().any(|existing| existing.knob == axis.knob) {
                    return Err(CliError::Usage(format!(
                        "--sweep {}: swept twice; one range per parameter",
                        axis.knob.name()
                    )));
                }
                sweep_axes.push(axis);
            }
            "--out" => out = Some(cursor.value("--out")?),
            "--format" => {
                let value = cursor.value("--format")?;
                format = match value.as_str() {
                    "csv" => TableFormat::Csv,
                    "jsonl" => TableFormat::Jsonl,
                    other => {
                        return Err(CliError::Usage(format!(
                            "incentives --format: expected csv or jsonl, got {other:?}"
                        )))
                    }
                };
            }
            "--nodes" => params.nodes = parse_u32(&cursor.value("--nodes")?, "--nodes")?,
            "--settled" => {
                params.settled_value = parse_u64(&cursor.value("--settled")?, "--settled")?
            }
            "--fee" => params.fee = parse_rate(&cursor.value("--fee")?, "--fee")?,
            "--stake" => params.stake = parse_u64(&cursor.value("--stake")?, "--stake")?,
            "--slash-rate" => {
                params.slash_rate = parse_rate(&cursor.value("--slash-rate")?, "--slash-rate")?
            }
            "--verify-cost" => {
                params.verify_cost = parse_u64(&cursor.value("--verify-cost")?, "--verify-cost")?
            }
            "--storage-cost" => {
                params.storage_cost = parse_u64(&cursor.value("--storage-cost")?, "--storage-cost")?
            }
            "--operating-cost" => {
                params.operating_cost =
                    parse_u64(&cursor.value("--operating-cost")?, "--operating-cost")?
            }
            "--canary-rate" => {
                params.canary_rate = parse_rate(&cursor.value("--canary-rate")?, "--canary-rate")?
            }
            "--canary-leak" => {
                params.canary_leak = parse_rate(&cursor.value("--canary-leak")?, "--canary-leak")?
            }
            "--fraud-rate" => {
                params.fraud_rate = parse_rate(&cursor.value("--fraud-rate")?, "--fraud-rate")?
            }
            "--catch-bounty" => {
                params.catch_bounty = parse_u64(&cursor.value("--catch-bounty")?, "--catch-bounty")?
            }
            "--audit-rate" => {
                params.audit_rate = parse_rate(&cursor.value("--audit-rate")?, "--audit-rate")?
            }
            "--committee" => {
                params.committee = parse_u32(&cursor.value("--committee")?, "--committee")?
            }
            "--threshold" => {
                params.threshold = parse_u32(&cursor.value("--threshold")?, "--threshold")?
            }
            "--sealed-value" => {
                params.sealed_value = parse_u64(&cursor.value("--sealed-value")?, "--sealed-value")?
            }
            "--detection-rate" => {
                params.detection_rate =
                    parse_rate(&cursor.value("--detection-rate")?, "--detection-rate")?
            }
            "--per-node-rewards" => params.reward_rule = proofwork::incentive::RewardRule::PerNode,
            other => {
                return Err(CliError::Usage(format!(
                    "incentives: unknown option {other:?}"
                )))
            }
        }
    }

    // Validated here so a nonsense network is a command line error rather than
    // a surprise partway through a report.
    //
    // The base point of a sweep is exempt: an axis overwrites the field it
    // names at every point, so a base that is invalid only *because* of a
    // field some axis replaces is not a network anyone was asked about. The
    // per-point check in `sweep::run` is the one that decides, and it reports
    // a refused point as a row rather than as a usage error.
    if sweep_axes.is_empty() {
        params.validate().map_err(CliError::Params)?;
    }
    if sweep_axes.is_empty() && (out.is_some() || format != TableFormat::Csv) {
        return Err(CliError::Usage(String::from(
            "incentives --out/--format describe a sweep's table: add --sweep NAME=LO..HI[:STEPS]",
        )));
    }
    Ok(Command::Incentives {
        params: Box::new(params),
        robustness,
        sweep: sweep_axes,
        out,
        format,
    })
}

/// A rate as an exact fraction: `1/100`, or a bare `0` or `1`.
fn parse_rate(text: &str, flag: &str) -> Result<Rat, CliError> {
    let bad = || {
        CliError::Usage(format!(
            "{flag}: expected an exact fraction in [0, 1] such as 1/100, got {text:?}"
        ))
    };
    let (num, den) = match text.split_once('/') {
        Some((num, den)) => (num, den),
        None => (text, "1"),
    };
    let num: u32 = num.trim().parse().map_err(|_| bad())?;
    let den: u32 = den.trim().parse().map_err(|_| bad())?;
    Rat::rate(num, den).ok_or_else(bad)
}

fn parse_peer(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut identity: Option<String> = None;
    let mut transport: Option<String> = None;
    let mut addr: Option<String> = None;
    let mut seq: Option<u64> = None;
    while let Some(token) = cursor.take() {
        match token.as_str() {
            "--identity" => identity = Some(cursor.value("--identity")?),
            "--transport" => transport = Some(cursor.value("--transport")?),
            "--addr" => addr = Some(cursor.value("--addr")?),
            "--seq" => {
                let text = cursor.value("--seq")?;
                seq = Some(parse_u64(&text, "--seq")?);
            }
            other => return Err(CliError::Usage(format!("peer: unknown option {other:?}"))),
        }
    }
    Ok(Command::Peer {
        identity: require(identity, "peer", "--identity <file>")?,
        transport: require(transport, "peer", "--transport <peer-id>")?,
        addr: require(addr, "peer", "--addr <host:port>")?,
        seq,
    })
}

fn parse_keygen(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut wrap = false;
    while let Some(token) = cursor.take() {
        match token.as_str() {
            "--passphrase" => wrap = true,
            other => return Err(CliError::Usage(format!("keygen: unknown option {other:?}"))),
        }
    }
    Ok(Command::Keygen { wrap })
}

fn parse_store(cursor: &mut Cursor) -> Result<Command, CliError> {
    let action = match cursor.take().as_deref() {
        Some("status") | None => StoreAction::Status,
        Some("gc") => StoreAction::Gc,
        Some("encrypt") => StoreAction::Encrypt,
        Some("rekey") => {
            let mut new_passphrase_file: Option<String> = None;
            while let Some(token) = cursor.take() {
                if token == "--new-passphrase-file" {
                    new_passphrase_file = Some(cursor.value("--new-passphrase-file")?);
                } else {
                    return Err(CliError::Usage(format!(
                        "store rekey: unknown option {token:?}"
                    )));
                }
            }
            StoreAction::Rekey {
                new_passphrase_file,
            }
        }
        Some("export") => {
            let mut destination: Option<String> = None;
            while let Some(token) = cursor.take() {
                if token == "--out" {
                    destination = Some(cursor.value("--out")?);
                } else if is_flag(&token) {
                    return Err(CliError::Usage(format!(
                        "store export: unknown option {token:?}"
                    )));
                } else if destination.is_some() {
                    return Err(CliError::Usage(format!(
                        "store export: unexpected argument {token:?}"
                    )));
                } else {
                    destination = Some(token);
                }
            }
            StoreAction::Export {
                out: require(destination, "store export", "--out <file>")?,
            }
        }
        Some(other) => {
            return Err(CliError::Usage(format!(
                "store: unknown action {other:?}; try status, gc, encrypt, rekey, or export"
            )))
        }
    };
    expect_end(cursor, "store")?;
    Ok(Command::Store { action })
}

fn parse_sync(cursor: &mut Cursor) -> Result<Command, CliError> {
    let mut destination: Option<String> = None;
    let mut options = mirror::Options::default();
    while let Some(token) = cursor.take() {
        match token.as_str() {
            "--prune" => options.prune = true,
            "--dry-run" => options.dry_run = true,
            other if is_flag(other) => {
                return Err(CliError::Usage(format!("sync: unknown option {other:?}")))
            }
            other => {
                if destination.is_some() {
                    return Err(CliError::Usage(format!(
                        "sync: unexpected argument {other:?}"
                    )));
                }
                destination = Some(other.to_string());
            }
        }
    }
    Ok(Command::Sync {
        destination: require(destination, "sync", "a destination directory")?,
        options,
    })
}

fn parse_attribute(cursor: &mut Cursor) -> Result<Command, CliError> {
    // Seeded from `FlowParams::default()` so the defaults live in one place --
    // the module that has to honour them -- rather than being restated here.
    let defaults = FlowParams::default();
    let mut delta_num = defaults.delta_num();
    let mut delta_den = defaults.delta_den();
    let mut max_depth = defaults.max_depth();

    while let Some(token) = cursor.take() {
        if token == "--delta-num" {
            delta_num = parse_u64(&cursor.value("--delta-num")?, "--delta-num")?;
        } else if token == "--delta-den" {
            delta_den = parse_u64(&cursor.value("--delta-den")?, "--delta-den")?;
        } else if token == "--max-depth" {
            max_depth = parse_u32(&cursor.value("--max-depth")?, "--max-depth")?;
        } else {
            return Err(CliError::Usage(format!(
                "attribute: unknown option {token:?}"
            )));
        }
    }

    // Validated here rather than at use, so an impossible delta is a command
    // line error and not a surprise partway through a payout table.
    let params = FlowParams::new(delta_num, delta_den, max_depth).map_err(CliError::Flow)?;
    Ok(Command::Attribute { params })
}

fn expect_end(cursor: &mut Cursor, command: &str) -> Result<(), CliError> {
    match cursor.take() {
        None => Ok(()),
        Some(token) => Err(CliError::Usage(format!(
            "{command}: unexpected argument {token:?}"
        ))),
    }
}

fn require(value: Option<String>, command: &str, what: &str) -> Result<String, CliError> {
    value.ok_or_else(|| CliError::Usage(format!("{command}: {what} is required")))
}

fn parse_blob(cursor: &mut Cursor) -> Result<Command, CliError> {
    let action = match cursor.take() {
        // Bare `blob` lists, because "what do I have" is the question an
        // operator diagnosing an `unavailable` verdict asks first.
        None => BlobAction::List,
        Some(word) => match word.as_str() {
            "ls" | "list" => BlobAction::List,
            "need" => BlobAction::Need,
            "publish" => BlobAction::Publish,
            "gc" => BlobAction::Collect,
            "serve" => parse_blob_serve(cursor)?,
            "fetch" => parse_blob_fetch(cursor)?,
            other => {
                return Err(CliError::Usage(format!(
                    "blob: unknown action {other:?}; expected ls, need, publish, gc, serve, \
                     or fetch"
                )))
            }
        },
    };
    expect_end(cursor, "blob")?;
    Ok(Command::Blob { action })
}

fn parse_blob_serve(cursor: &mut Cursor) -> Result<BlobAction, CliError> {
    let mut identity: Option<String> = None;
    let mut listen: Option<String> = None;
    while let Some(token) = cursor.take() {
        match token.as_str() {
            "--identity" => identity = Some(cursor.value("--identity")?),
            "--listen" => listen = Some(cursor.value("--listen")?),
            other => {
                return Err(CliError::Usage(format!(
                    "blob serve: unknown option {other:?}"
                )))
            }
        }
    }
    Ok(BlobAction::Serve {
        identity: require(identity, "blob serve", "--identity <file>")?,
        // A loopback default, deliberately. Serving is publishing, and a
        // command that binds every interface because the operator did not say
        // otherwise has made that decision for them.
        listen: listen.unwrap_or_else(|| String::from("127.0.0.1:0")),
    })
}

fn parse_blob_fetch(cursor: &mut Cursor) -> Result<BlobAction, CliError> {
    let mut identity: Option<String> = None;
    let mut peers: Vec<String> = Vec::new();
    let mut seconds = DEFAULT_FETCH_SECONDS;
    while let Some(token) = cursor.take() {
        match token.as_str() {
            "--identity" => identity = Some(cursor.value("--identity")?),
            "--peer" => peers.push(cursor.value("--peer")?),
            "--timeout" => {
                let raw = cursor.value("--timeout")?;
                seconds = parse_u64(&raw, "--timeout")?;
                if seconds == 0 {
                    return Err(CliError::Usage(String::from(
                        "blob fetch: --timeout must be at least 1 second",
                    )));
                }
            }
            other => {
                return Err(CliError::Usage(format!(
                    "blob fetch: unknown option {other:?}"
                )))
            }
        }
    }
    Ok(BlobAction::Fetch {
        identity: require(identity, "blob fetch", "--identity <file>")?,
        peers,
        seconds,
    })
}

/// Negative numbers are rejected by the type, not by a range check: `-1` does
/// not parse as `u64` and never reaches [`FlowParams`].
fn parse_u64(text: &str, flag: &str) -> Result<u64, CliError> {
    text.parse::<u64>().map_err(|_| {
        CliError::Usage(format!(
            "{flag} expects a non-negative integer, got {text:?}"
        ))
    })
}

fn parse_u32(text: &str, flag: &str) -> Result<u32, CliError> {
    text.parse::<u32>().map_err(|_| {
        CliError::Usage(format!(
            "{flag} expects a non-negative integer, got {text:?}"
        ))
    })
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// Write one line, treating a closed pipe as the end of output.
///
/// `println!` panics if the write fails, and `proofwork post ... | head -1` --
/// which `scripts/demo.sh` runs to pick the objective id out of field 2 -- is
/// the ordinary way to make it fail. A CLI dying with a Rust panic because the
/// reader stopped reading is both ugly and a violation of this crate's no-panic
/// rule.
fn say(out: &mut dyn Write, text: impl AsRef<str>) {
    let _ = writeln!(out, "{}", text.as_ref());
}

fn print_help(out: &mut dyn Write) {
    say(out, "proofwork -- verified results as the unit of account");
    say(out, "");
    say(out, "usage: proofwork [--log PATH] [--root PATH] <command>");
    say(out, "");
    say(out, "commands:");
    say(out, "  post <objective.json>");
    say(out, "      fund a checkable question");
    say(
        out,
        "  commit <objective-id> --submitter S --artifact FILE [--nonce N]",
    );
    say(out, "      bind to an artifact without revealing it");
    say(
        out,
        "  reveal <objective-id> --submitter S --artifact FILE --nonce N [--cites ID ...]",
    );
    say(
        out,
        "      reveal a committed artifact and verify it (settles when the epoch closes)",
    );
    say(out, "  settle");
    say(out, "      pay out every reveal epoch that has closed");
    say(out, "  checkpoint --root-key FILE [--out FILE]");
    say(
        out,
        "      sign the log's current height, head, and Merkle root",
    );
    say(out, "  drain --queue DIR [--dry-run]");
    say(
        out,
        "      admit records queued by proofwork-serve, re-checking every rule",
    );
    say(out, "  audit [--no-rerun]");
    say(out, "      re-derive the entire log independently");
    say(
        out,
        "  verify --from CHECKPOINT [--root-key HEX|FILE] [--audit] [--no-rerun]",
    );
    say(
        out,
        "      check a signed checkpoint against this log's prefix",
    );
    say(out, "  prove <seq> [--height N] [--out FILE]");
    say(
        out,
        "      emit a Merkle proof that one entry is in this log",
    );
    say(
        out,
        "  check FILE (--merkle-root sha256:HEX | --from CHECKPOINT [--root-key HEX|FILE])",
    );
    say(
        out,
        "      check such a proof -- needs no log, which is the point",
    );
    say(
        out,
        "  attribute [--delta-num N] [--delta-den N] [--max-depth N]",
    );
    say(out, "      compute citation-flow payouts");
    say(out, "  blob [ls|need|publish|gc]");
    say(
        out,
        "      inspect the content-addressed store of pinned verifier code",
    );
    say(out, "  blob serve --identity <file> [--listen <addr>]");
    say(
        out,
        "      seed this node's blobs to strangers over the encrypted transport,",
    );
    say(
        out,
        "      and print the endpoint a fetcher needs; Ctrl-C to stop",
    );
    say(
        out,
        "  blob fetch --identity <file> --peer <file> [--peer <file>]... [--timeout N]",
    );
    say(
        out,
        "      fetch every pin this log names and this node lacks; --peer takes the",
    );
    say(out, "      {addr, public} file `blob serve` printed");
    say(
        out,
        "  incentives [--nodes N] [--settled N] [--canary-rate N/D] ...",
    );
    say(
        out,
        "      evaluate the node-operator game at a parameter set",
    );
    say(
        out,
        "  incentives --sweep NAME=LO..HI[:STEPS] [--sweep ...] [--out FILE] [--format csv|jsonl]",
    );
    say(
        out,
        "      evaluate the same game across a grid and emit one row per point,",
    );
    say(
        out,
        "      e.g. --sweep canary-rate=1/20..1/5:5 --sweep stake=1000..10000:4",
    );
    say(
        out,
        "  try <objective-id|objective.json> --submitter <who> --artifact <file> [--settle]",
    );
    say(
        out,
        "      one round end to end: post if needed, commit, wait out the epoch, reveal.",
    );
    say(
        out,
        "      A real round takes a real epoch (600s); $PROOFWORK_EPOCH_SECONDS shortens it",
    );
    say(
        out,
        "      for a local trial, against a log used for nothing else",
    );
    say(
        out,
        "  scaffold <name> --kind <certificate|evaluator|statistical|replay|lean>",
    );
    say(
        out,
        "           [--out DIR] [--artifact-example FILE] [--reward N] [--funder WHO]",
    );
    say(
        out,
        "      write the files a new objective starts from -- and post nothing, because",
    );
    say(
        out,
        "      funding a statement is a decision a person makes after reading it",
    );
    say(out, "  log");
    say(out, "      print the log");
    say(out, "  canon --input <file>");
    say(
        out,
        "      canonicalize one JSON value and print its digest",
    );
    say(
        out,
        "  decode <objective|commitment|claim|peer> --record <file>",
    );
    say(
        out,
        "      check one record without a log: is it admissible, and what is its id",
    );
    say(out, "  identity --out <file>");
    say(
        out,
        "      create a submitter identity; the public key IS the submitter name,",
    );
    say(
        out,
        "      so a name you sign for cannot be claimed by anyone else",
    );
    say(
        out,
        "  peer --identity <file> --transport <peer-id> --addr <host:port>",
    );
    say(
        out,
        "      announce where your identity answers, or move it; obtaining the log",
    );
    say(
        out,
        "      is then obtaining the address book, so discovery needs no second file",
    );
    say(out, "  keygen [--passphrase]");
    say(
        out,
        "      create the at-rest key that seals the local store",
    );
    say(out, "  store [status|gc|encrypt]");
    say(
        out,
        "      report local usage, reclaim space, or seal an existing log",
    );
    say(out, "  store rekey [--new-passphrase-file PATH]");
    say(
        out,
        "      re-seal the log under a fresh at-rest key; the old key is kept",
    );
    say(
        out,
        "      at <key>.previous, because older copies are still sealed under it",
    );
    say(out, "  store export --out <file>");
    say(
        out,
        "      write a plaintext copy of the log for someone else to audit",
    );
    say(out, "  sync <dir> [--prune] [--dry-run]");
    say(
        out,
        "      copy the store to a directory of your choosing, still encrypted",
    );
    say(out, "  help");
    say(out, "      this message");
    say(out, "");
    say(out, "options:");
    say(
        out,
        "  --log PATH    JSONL log (default: $PROOFWORK_LOG, else proofwork.jsonl)",
    );
    say(
        out,
        "  --root PATH   root for pinned verifier code (default: .)",
    );
    say(
        out,
        "  --data-dir PATH        where node data lives (default: $PROOFWORK_DATA)",
    );
    say(
        out,
        "  --key-file PATH        at-rest key (default: $PROOFWORK_KEY, else ~/.proofwork/key)",
    );
    say(
        out,
        "  --passphrase-file PATH passphrase for a wrapped key (else $PROOFWORK_PASSPHRASE)",
    );
    say(
        out,
        "  --max-size SIZE        cap on the data directory, e.g. 20GB or 20GiB",
    );
    say(out, "");
    say(out, "exit codes:");
    say(out, "  0  success");
    say(
        out,
        "  1  audit found problems, a checkpoint did not match, or incentives do not hold",
    );
    say(out, "  2  refused, or bad input");
    say(out, "  3  reveal produced a verdict that settles nothing");
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Read a JSON file as a canonical value.
///
/// Floats are refused here, at the boundary, rather than deeper in: a float
/// cannot be canonically serialized, so an artifact carrying one has no stable
/// identity and no two nodes would agree on its hash.
fn read_json(path: &str) -> Result<Value, CliError> {
    let text = fs::read_to_string(path).map_err(|source| CliError::Io {
        context: format!("reading {path}"),
        source,
    })?;
    Value::from_json(&text).map_err(|source| CliError::Json {
        path: path.to_string(),
        source,
    })
}

fn cmd_post(out: &mut dyn Write, options: &Options, path: &str) -> Result<i32, CliError> {
    post_objective_file(out, options, path)?;
    Ok(0)
}

/// Post the objective in `path` and return its id.
///
/// Split out of [`cmd_post`] so [`cmd_try`] posts by exactly the same route
/// rather than by a second copy of it. The copy is what would eventually drift
/// -- specifically past the unresolved-pin warning below, which is the one
/// output here that tells a funder they have minted a bounty nobody can settle.
fn post_objective_file(
    out: &mut dyn Write,
    options: &Options,
    path: &str,
) -> Result<String, CliError> {
    let mut node = open_node_for_writing(options)?;
    let data = read_json(path)?;
    // The published schema runs *before* the constructor. `Objective::from_value`
    // is permissive by necessity -- it has to read back records written by older
    // versions of this code -- so it is the wrong place to enforce the contract
    // third parties implement against. Gating here means nothing enters the log
    // that `spec/objective.schema.json` would reject.
    validate_objective(&data).map_err(CliError::Schema)?;
    let objective = Objective::from_value(&data).map_err(CliError::Record)?;
    let id = post_objective(&mut node, &objective, &timestamp())?;

    // Field 2 of this line is the objective id, and `scripts/demo.sh` reads it
    // with `awk '{print $2}'`. Keep it first, and keep the id second.
    say(out, format!("objective {id}"));
    say(
        out,
        format!(
            "  reward {}  verifier {}",
            objective.reward,
            objective.verifier_kind().unwrap_or("?")
        ),
    );

    // A pin this node cannot resolve is not an error: content addressing is
    // what lets a node post an objective whose checker a peer will serve, and
    // record sync admits objectives from nodes that never had the bundle. So
    // this cannot refuse.
    //
    // Saying nothing is the wrong answer too. The id covers the pin, so a
    // typo'd hash does not fail -- it mints a *different* objective, one whose
    // every claim returns InvalidSpec forever and whose reward is stranded.
    // The funder finds out when strangers have already burned compute on a
    // bounty that could never settle. The distinction the operator needs is
    // between "a peer will serve this" and "I mistyped it", and only they can
    // draw it, so name the addresses and let them.
    let missing = node.registry().missing_code(&objective.verifier);
    if !missing.is_empty() {
        say(
            out,
            format!(
                "  warning: {} pinned file(s) do not resolve on this node yet:",
                missing.len()
            ),
        );
        for address in &missing {
            say(out, format!("    {address}"));
        }
        say(
            out,
            "  Expected if a peer will serve them. If not, the pin is wrong -- and because \
             the id covers it, this is now a different objective that can never settle.",
        );
    }
    Ok(id)
}

/// Read a submitter identity from disk, if one was asked for.
///
/// The file is `{"secret": "<64 hex>", "public": "<64 hex>"}` -- the same
/// shape the p2p daemon writes for its transport key, so an operator has one
/// format to learn rather than two. `public` is checked against the secret
/// rather than trusted: a file whose halves disagree would sign records under
/// a name its owner cannot prove, and finding that out at submission time is
/// finding out too late.
fn load_identity(path: Option<&str>) -> Result<Option<Identity>, CliError> {
    let Some(path) = path else {
        return Ok(None);
    };
    let value = read_json(path)?;
    let field = |name: &'static str| -> Result<String, CliError> {
        value
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                CliError::Usage(format!("{path}: identity file needs a {name:?} hex field"))
            })
    };
    let secret = field("secret")?;
    let bytes = decode_hex32(&secret)
        .ok_or_else(|| CliError::Usage(format!("{path}: \"secret\" must be 32 bytes of hex")))?;
    let identity = Identity::from_secret_bytes(bytes);
    if let Ok(declared) = field("public") {
        if declared != identity.submitter_id() {
            return Err(CliError::Usage(format!(
                "{path}: \"public\" does not match \"secret\" -- this file would sign \
                 records under {}, not {declared}",
                identity.submitter_id()
            )));
        }
    }
    Ok(Some(identity))
}

/// 32 bytes from a 64-character hex string.
fn decode_hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(text.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// Canonicalize one JSON value and print its digest.
///
/// The format contract at its narrowest: same bytes in, same bytes and same
/// digest out, in every implementation. `scripts/fuzz-differential.sh` drives
/// this on random input, which is where an encoder disagreement surfaces
/// before it ever reaches a record.
fn cmd_canon(out: &mut dyn Write, input_path: &str) -> Result<i32, CliError> {
    match read_json(input_path) {
        Ok(value) => {
            say(
                out,
                format!("ok {} {}", value.digest(), value.canonical_string()),
            );
            Ok(0)
        }
        Err(error) => {
            say(out, "refused");
            eprintln!("  {error}");
            Ok(1)
        }
    }
}

/// Decode one record and say whether it is admissible, touching no log.
///
/// Useful before posting something, and it is the surface
/// `scripts/differential.sh` drives to prove this implementation and
/// `reference/rust/` classify every record identically. Two implementations
/// that disagree about which records are valid disagree about what was
/// settled, so that agreement is checked rather than assumed.
fn cmd_decode(out: &mut dyn Write, kind: &str, record_path: &str) -> Result<i32, CliError> {
    let value = read_json(record_path)?;
    let decoded = match kind {
        "objective" => Objective::from_value(&value)
            .map(|record| record.id())
            .map_err(|error| error.to_string()),
        "commitment" => Commitment::from_value(&value)
            .map_err(|error| error.to_string())
            .and_then(|record| {
                record.verify_signature().map_err(|e| e.to_string())?;
                Ok(record.id())
            }),
        "claim" => Claim::from_value(&value)
            .map_err(|error| error.to_string())
            .and_then(|record| {
                record.verify_signature().map_err(|e| e.to_string())?;
                Ok(record.id())
            }),
        "peer" => PeerRecord::from_value(&value)
            .map_err(|error| error.to_string())
            .and_then(|record| {
                record.verify_signature().map_err(|e| e.to_string())?;
                Ok(record.id())
            }),
        other => return Err(CliError::Usage(format!("unknown record kind {other:?}"))),
    };
    match decoded {
        Ok(id) => {
            say(out, format!("ok {id}"));
            Ok(0)
        }
        Err(reason) => {
            say(out, "refused");
            eprintln!("  {reason}");
            Ok(1)
        }
    }
}

/// Append a peer record: this identity answers on this transport, here.
///
/// The signing key's public half *becomes* the record's identity — a name you
/// sign for cannot be worn by anyone else — so there is no `--submitter` here
/// and no way to announce on somebody else's behalf.
fn cmd_peer(
    out: &mut dyn Write,
    options: &Options,
    identity_path: &str,
    transport: &str,
    addr: &str,
    seq: Option<u64>,
) -> Result<i32, CliError> {
    let identity = load_identity(Some(identity_path))?
        .ok_or_else(|| CliError::Usage(String::from("peer: --identity is required")))?;
    let mut node = open_node(options)?;

    // Default to one past whatever this identity has already said. An operator
    // moving house should not have to read their own log to find the number,
    // and getting it wrong is a refusal rather than a silent no-op.
    let seq = match seq {
        Some(seq) => seq,
        None => node
            .peers()
            .get(&identity.submitter_id())
            .map(|held| held.seq.saturating_add(1))
            .unwrap_or(1),
    };
    let record = PeerRecord::new(identity.submitter_id(), transport, addr, seq, timestamp())
        .signed_with(&identity);

    let id = post_peer_record(&mut node, &record, &timestamp())?;
    say(out, format!("peer {id}"));
    say(out, format!("  identity  {}", record.identity));
    say(out, format!("  transport {}", short(&record.transport)));
    say(out, format!("  addr      {} (seq {seq})", record.addr));
    say(out, "");
    say(
        out,
        "The address is a hint and the transport id is a promise: a peer dialling",
    );
    say(
        out,
        "it derives that id from the handshake or gets no session. A wrong record",
    );
    say(out, "costs a dial and can never cost a wrong result.");
    Ok(0)
}

fn cmd_identity(out: &mut dyn Write, path: &str) -> Result<i32, CliError> {
    use rand_core::{OsRng, RngCore};
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let identity = Identity::from_secret_bytes(secret);
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    let body = Value::object([
        ("secret", Value::string(hex(&secret))),
        ("public", Value::string(identity.submitter_id())),
    ]);
    write_private_file(std::path::Path::new(path), &body.canonical_string())
        .map_err(|error| CliError::Usage(format!("{path}: {error}")))?;

    say(out, format!("identity written to {path}"));
    say(out, format!("  submitter {}", identity.submitter_id()));
    say(
        out,
        "  That id IS your public key, which is what makes it unforgeable: submit with",
    );
    say(
        out,
        "  --identity <file> and nobody else can claim it. Back the file up -- losing it",
    );
    say(out, "  loses the name, and there is no recovery.");
    Ok(0)
}

/// Write a file only the owner can read, via a temporary so a crash cannot
/// leave a half-written key behind.
fn write_private_file(path: &std::path::Path, text: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    let tmp = path.with_file_name(name);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}

fn cmd_commit(
    out: &mut dyn Write,
    options: &Options,
    objective_id: &str,
    who: Submitter<'_>,
    artifact_path: &str,
    nonce: Option<&str>,
) -> Result<i32, CliError> {
    let mut node = open_node_for_writing(options)?;
    let artifact = read_json(artifact_path)?;
    let nonce = match nonce {
        Some(nonce) => nonce.to_string(),
        None => random_nonce()?,
    };
    // The key decides the submitter when there is one. The commitment hash
    // binds the submitter string, so it has to be settled *before* the hash is
    // computed -- signing a hash that bound a different name would produce a
    // commitment no claim could ever open.
    let (submitter, identity) = who.resolve()?;

    // One clock reading for the record and the log entry alike, so a commitment
    // cannot appear to have been created after it was appended.
    let stamp = timestamp();
    let hash = commitment_hash(objective_id, &submitter, &artifact, &nonce);
    let commitment = Commitment::new(objective_id, &submitter, hash.as_str(), stamp.as_str());
    let commitment = match &identity {
        Some(identity) => commitment.signed_with(identity),
        None => commitment,
    };
    post_commitment(&mut node, &commitment, &stamp)?;

    say(out, format!("committed {}", short(&hash)));
    say(
        out,
        format!("  nonce {nonce}   <- keep this; you need it to reveal"),
    );
    Ok(0)
}

/// Who is submitting, and how they prove it.
///
/// Grouped because these three always travel together and always resolve the
/// same way: an identity file, when given, *is* the submitter, so passing them
/// separately invites a caller to let the name and the key disagree.
struct Submitter<'a> {
    declared: &'a str,
    identity: Option<&'a str>,
}

impl Submitter<'_> {
    /// Resolve to the name that will appear in the record, plus the key that
    /// must sign it.
    fn resolve(&self) -> Result<(String, Option<Identity>), CliError> {
        let identity = load_identity(self.identity)?;
        let name = match &identity {
            Some(identity) => identity.submitter_id(),
            None => self.declared.to_string(),
        };
        Ok((name, identity))
    }
}

fn cmd_reveal(
    out: &mut dyn Write,
    options: &Options,
    objective_id: &str,
    who: Submitter<'_>,
    artifact_path: &str,
    nonce: &str,
    cites: &[String],
) -> Result<i32, CliError> {
    let mut node = open_node_for_writing(options)?;
    let artifact = read_json(artifact_path)?;
    let (submitter, identity) = who.resolve()?;
    let stamp = timestamp();
    let claim = Claim::new(
        objective_id,
        &submitter,
        artifact,
        nonce,
        stamp.as_str(),
        cites.to_vec(),
    )
    .map_err(CliError::Record)?;
    let claim = match &identity {
        Some(identity) => claim.signed_with(identity),
        None => claim,
    };
    validate_claim(&claim.to_value()).map_err(CliError::Schema)?;

    let report = reveal_claim(&mut node, &claim, &stamp)?;
    // Print the FULL claim id, not the display-shortened form. Citing this claim
    // is the next thing anyone does with it -- an improvement on a progressive
    // objective is *required* to cite the frontier it beat -- and a truncated id
    // cannot be passed to `--cites`. A convenience abbreviation that makes the
    // output unusable for the workflow that follows is not a convenience.
    say(out, format!("claim {}", report.claim_id));
    say(
        out,
        format!("  verdict  {}: {}", report.status, report.detail),
    );
    match report.pending_epoch {
        Some(epoch) => say(
            out,
            format!("  pending  settles when epoch {epoch} closes  (`proofwork settle`)"),
        ),
        None => say(
            out,
            format!(
                "  settled  {}  reward {}  ({})",
                report.settled, report.reward, report.note
            ),
        ),
    }

    // See the module docs: a rejection is a real answer and exits 0. Only a
    // verdict that settles nothing -- `unavailable`, `invalid_spec` -- exits 3,
    // because in that case nothing was learned and the objective is still open.
    Ok(if report.settles { 0 } else { 3 })
}

/// Close every reveal epoch that is over and pay out its batch.
///
/// Exists because settlement is deferred: a claim accepted in epoch N is paid
/// when N closes, in an order derived from a beacon rather than from arrival.
/// Every other command drains due batches on its way in, so this is only needed
/// when nothing else is happening -- which is exactly the case a demo, a cron
/// job, or an operator winding a quiet objective down finds itself in.
fn cmd_settle(out: &mut dyn Write, options: &Options) -> Result<i32, CliError> {
    let mut node = open_node_for_writing(options)?;
    let settled = settle_now(&mut node, &timestamp())?;
    if settled.is_empty() {
        say(out, "no batch was due");
        return Ok(0);
    }
    for (claim_id, moved, reward, note) in &settled {
        say(out, format!("claim {claim_id}"));
        say(
            out,
            format!("  settled  {moved}  reward {reward}  ({note})"),
        );
    }
    Ok(0)
}

/// Sign the log's current state.
///
/// The counterpart to `verify --from`. A checkpoint pins `(height, head,
/// merkle_root)` under an ML-DSA-65 signature, so a reader who has the
/// operator's public key can tell a log that grew from a log that was
/// *rewritten* -- the property a bare hash chain cannot give them, because an
/// operator who rewrites history rewrites the chain with it.
///
/// The key file is the one `proofwork-p2p` creates: `{"public": hex, "secret":
/// hex}`. Read-only on the log, because signing observes and changes nothing.
fn cmd_checkpoint(
    out: &mut dyn Write,
    options: &Options,
    root_key: &str,
    destination: Option<&str>,
) -> Result<i32, CliError> {
    let key = read_root_key_file(root_key)?;
    let node = open_node(options)?;
    let ledger = ledger_of(&node);
    if ledger.is_empty() {
        return Err(CliError::Usage(String::from(
            "the log is empty; there is nothing to check-point",
        )));
    }
    let signed = key.sign_ledger(ledger, timestamp());
    let text = signed.to_value().canonical_string();

    match destination {
        Some(path) => {
            fs::write(path, format!("{text}\n")).map_err(|error| CliError::Io {
                context: format!("writing {path}"),
                source: error,
            })?;
            say(out, format!("wrote {path}"));
        }
        None => say(out, &text),
    }
    say(
        out,
        format!(
            "  height {}  root {}",
            ledger.len(),
            ledger.root().as_deref().map(short).unwrap_or_default()
        ),
    );
    say(
        out,
        format!("  public key {}", short(&hex_encode(&key.public_key()))),
    );
    say(
        out,
        "  Readers verify with `proofwork verify --from <file> --root-key <hex|file>`.",
    );
    say(
        out,
        format!(
            "  A reader who wants one entry rather than the log asks for \
             `proofwork prove <seq> --height {}`.",
            ledger.len()
        ),
    );
    say(
        out,
        "  Publish the public key somewhere they already trust: a key served",
    );
    say(
        out,
        "  alongside what it authenticates authenticates nothing.",
    );
    Ok(0)
}

/// Load the ML-DSA-65 root key from the file `proofwork-p2p` writes.
fn read_root_key_file(path: &str) -> Result<RootKey, CliError> {
    let value = read_json(path)?;
    let secret = value
        .get("secret")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Usage(format!("{path}: no \"secret\" field")))?;
    let bytes = decode_hex(secret)
        .map_err(|why| CliError::Usage(format!("{path}: secret is not hex ({why})")))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CliError::Usage(format!("{path}: secret must be 32 bytes")))?;
    let key = RootKey::from_secret_bytes(bytes);
    // A file whose halves disagree is a file somebody edited; signing with it
    // would produce checkpoints nobody can verify against the published key.
    if let Some(public) = value.get("public").and_then(Value::as_str) {
        let declared = decode_hex(public)
            .map_err(|why| CliError::Usage(format!("{path}: public is not hex ({why})")))?;
        if declared != key.public_key() {
            return Err(CliError::Usage(format!(
                "{path}: the public key does not match the secret"
            )));
        }
    }
    Ok(key)
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if !text.len().is_multiple_of(2) {
        return Err(String::from("odd number of digits"));
    }
    let digits: Vec<char> = text.chars().collect();
    digits
        .chunks(2)
        .map(|pair| {
            let hex: String = pair.iter().collect();
            u8::from_str_radix(&hex, 16).map_err(|_| format!("{hex:?} is not hex"))
        })
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Admit records queued by `proofwork-serve`, oldest first.
///
/// The queue holds *proposals*. Every rule is re-derived here against the
/// whole log, by the same `Node::commit` / `Node::reveal` the CLI uses, so a
/// record that arrived over the network is admitted on exactly the terms one
/// typed by the operator would be. The server deliberately decides nothing.
///
/// A refused record is dropped from the queue rather than retried forever:
/// almost every refusal is permanent (a stale epoch, a citation that is not
/// an accepted claim, a duplicate artifact), and a queue that retries a
/// permanent failure is a queue that never empties. The refusal is printed, so
/// an operator watching the output sees why.
fn cmd_drain(
    out: &mut dyn Write,
    options: &Options,
    queue: &str,
    dry_run: bool,
) -> Result<i32, CliError> {
    let spool = Spool::at(queue);
    let pending = spool.pending();
    if pending.is_empty() {
        say(out, format!("nothing queued in {queue}"));
        return Ok(0);
    }

    // Opened for writing even on a dry run: holding the lock is what makes the
    // report honest, since admission depends on a log nobody else is moving.
    let mut node = open_node_for_writing(options)?;
    let ts = timestamp();
    let (mut admitted, mut refused) = (0usize, 0usize);

    // The rules live in `serve::drain_into`, not here. They used to live here,
    // which put them out of reach of `proofwork-p2p` -- so a node that was
    // online could not accept a submission, because `drain` wanted the write
    // lock the daemon holds. One copy, two callers.
    for (path, admission) in proofwork::serve::drain_into(&mut node, &spool, &ts, dry_run) {
        if admission.admitted {
            admitted += 1;
        } else {
            refused += 1;
        }
        say(out, format!("  {}", admission.note));
        if !dry_run {
            spool.take(&path).map_err(|e| CliError::Io {
                context: format!("removing {}", path.display()),
                source: e,
            })?;
        }
    }

    // Settlement is deferred, so a drain that admitted a reveal into a closed
    // epoch should pay it rather than wait for the next command.
    if !dry_run {
        for (claim_id, moved, reward, note) in settle_now(&mut node, &ts)? {
            say(
                out,
                format!(
                    "  settled {}  {moved}  reward {reward}  ({note})",
                    short(&claim_id)
                ),
            );
        }
    }

    say(
        out,
        format!(
            "{} admitted, {refused} refused{}",
            admitted,
            if dry_run {
                " (dry run, nothing written)"
            } else {
                ""
            }
        ),
    );
    Ok(0)
}

fn cmd_audit(out: &mut dyn Write, options: &Options, rerun: bool) -> Result<i32, CliError> {
    let node = open_node(options)?;
    let problems = audit_log(&node, rerun);
    let ledger = ledger_of(&node);

    say(
        out,
        format!(
            "entries {}   head {}",
            ledger.len(),
            short(ledger.head().unwrap_or("-"))
        ),
    );
    say(
        out,
        format!(
            "merkle  {}",
            ledger.root().unwrap_or_else(|| String::from("-"))
        ),
    );

    if !problems.is_empty() {
        say(out, "");
        say(out, format!("{} problem(s):", problems.len()));
        for problem in &problems {
            say(out, format!("  ! {problem}"));
        }
        return Ok(1);
    }

    say(out, "");
    say(
        out,
        "log verified: chain intact, every settled claim re-verified",
    );
    Ok(0)
}

/// Check a signed checkpoint against the local log.
///
/// The question this answers is the one a hash chain cannot answer alone: *is
/// my copy of the log a prefix-consistent view of what the operator published?*
/// A truncated log is internally consistent -- every link checks out -- so
/// rollback is invisible without an external anchor, and this is the anchor.
///
/// Three exit codes, and the split between them is deliberate. A signature that
/// does not verify and a root that does not match are the *same* answer to the
/// reader: the log in front of them is not the one that was signed. Both are 1.
/// A missing file or an unparsable checkpoint is 2, because nothing was
/// checked either way and reporting "mismatch" would be a false accusation.
fn cmd_verify(
    out: &mut dyn Write,
    options: &Options,
    checkpoint_path: &str,
    root_key: Option<&str>,
    audit: bool,
    rerun: bool,
) -> Result<i32, CliError> {
    let signed = SignedCheckpoint::from_value(&read_json(checkpoint_path)?)
        .map_err(|source| CliError::Checkpoint(source.to_string()))?;

    // Without an out-of-band key this verifies only that the file is
    // self-consistent: an operator rewriting history signs the rewrite with a
    // fresh key and the check passes. Said plainly rather than left to the
    // reader to work out, because a verification that proves nothing is worse
    // than none -- it is the one that gets quoted.
    let expected = match root_key {
        Some(source) => read_root_key(source)?,
        None => signed.public_key.clone(),
    };

    let node = open_node(options)?;
    let ledger = ledger_of(&node);
    if let Err(error) = signed.verify_prefix(ledger, &expected) {
        say(out, format!("checkpoint FAILED: {error}"));
        return Ok(1);
    }

    say(
        out,
        format!(
            "checkpoint ok: height {}  head {}  issued {}",
            signed.checkpoint.height,
            short(signed.checkpoint.head.as_deref().unwrap_or("-")),
            signed.checkpoint.issued_at
        ),
    );
    if root_key.is_none() {
        say(
            out,
            "  warning: no --root-key given, so this checks the file against itself; \
             pin the operator's published key to make it mean anything",
        );
    }
    let local = ledger.len();
    let height = signed.checkpoint.height;
    if local as u64 > height {
        say(
            out,
            format!("  local log continues past the checkpoint ({local} entries)"),
        );
    }

    if !audit {
        return Ok(0);
    }

    // Audit the signed prefix, not the whole log: entries appended after the
    // checkpoint have not been vouched for by anyone, and folding their
    // problems into this result would make a valid checkpoint look broken.
    let height = usize::try_from(height)
        .map_err(|_| CliError::Overflow(String::from("checkpoint height")))?;
    let prefix = match ledger.prefix(height) {
        Some(prefix) => prefix,
        // Unreachable: `verify_prefix` already refused a short log above. An
        // error rather than an unwrap all the same -- this is the money path.
        None => {
            return Err(CliError::Checkpoint(format!(
                "log is shorter than {height}"
            )))
        }
    };
    let problems = Node::new(prefix, options.root.as_str()).audit(rerun);
    if !problems.is_empty() {
        say(out, "");
        say(
            out,
            format!("{} problem(s) inside the signed prefix:", problems.len()),
        );
        for problem in &problems {
            say(out, format!("  ! {problem}"));
        }
        return Ok(1);
    }
    say(out, "  signed prefix re-derives cleanly");
    Ok(0)
}

/// The availability mechanism, from the operator's side.
///
/// Nothing here talks to a network. A promise is a record, the challenge is a
/// pure function of the log, and the answer is a record -- so all four steps
/// are local, and an auditor re-derives every one of them from the log alone.
fn cmd_availability(
    out: &mut dyn Write,
    options: &Options,
    action: &AvailabilityAction,
) -> Result<i32, CliError> {
    match action {
        AvailabilityAction::Undertake { identity } => {
            let signer = load_identity(Some(identity))?.ok_or_else(|| {
                CliError::Usage(String::from(
                    "availability undertake: --identity is required",
                ))
            })?;
            let mut node = open_node_for_writing(options)?;
            let height = ledger_of(&node).len();
            let root = ledger_of(&node)
                .root()
                .ok_or_else(|| CliError::Usage(String::from("the log is empty")))?;
            let record = Undertaking::new(signer.submitter_id(), &root, height as u64, timestamp())
                .signed_with(&signer);
            let id = refused(node.post_undertaking(&record, &timestamp()))?;
            say(out, format!("undertaking {id}"));
            say(
                out,
                format!("  {height} entries rooted at {}", short(&root)),
            );
            say(
                out,
                "  Answer each epoch's sample with `proofwork availability answer`;",
            );
            say(
                out,
                "  a promise that goes unanswered is named in the settlement.",
            );
            Ok(0)
        }
        AvailabilityAction::Answer { identity, epoch } => {
            let signer = load_identity(Some(identity))?.ok_or_else(|| {
                CliError::Usage(String::from("availability answer: --identity is required"))
            })?;
            let mut node = open_node_for_writing(options)?;
            let epoch = match epoch {
                Some(epoch) => *epoch,
                None => current_epoch()?,
            };
            let mine: Vec<Undertaking> = node
                .undertakings()
                .into_iter()
                .filter(|promise| promise.identity == signer.submitter_id())
                .collect();
            if mine.is_empty() {
                say(out, "no undertakings for this identity");
                say(
                    out,
                    "  Promise first with `proofwork availability undertake --identity <file>`.",
                );
                return Ok(2);
            }
            let mut answered = 0usize;
            for promise in &mine {
                // The position this answer will land at, which is where the
                // rules will re-derive the index from.
                let landing = ledger_of(&node).len();
                let index = node
                    .sampled_index(promise, epoch, landing)
                    .map_err(|why| CliError::Usage(format!("cannot draw a sample: {why}")))?;
                let height = usize::try_from(promise.height)
                    .map_err(|_| CliError::Overflow(String::from("undertaking height")))?;
                // Built from this node's own copy of the log, which is the
                // whole point: a node that does not hold it cannot get here.
                // Both halves come from this node's own copy, which is the
                // point: the entry proves it held the bytes, the path proves
                // they are under the root it promised.
                let answer = ledger_of(&node).prefix(height).and_then(|prefix| {
                    prefix
                        .prove(index)
                        .map(|proof| (proof.entry.body_with_hash(), proof.inclusion.siblings))
                });
                let Some((entry, path)) = answer else {
                    say(
                        out,
                        format!(
                            "  ! {} cannot be answered: entry {index} is not in this copy",
                            short(&promise.id())
                        ),
                    );
                    continue;
                };
                let record = Availability::new(
                    signer.submitter_id(),
                    promise.id(),
                    epoch,
                    entry,
                    path,
                    timestamp(),
                )
                .signed_with(&signer);
                match node.post_availability(&record, &timestamp()) {
                    Ok(id) => {
                        answered += 1;
                        say(out, format!("answered {id}"));
                        say(
                            out,
                            format!(
                                "  undertaking {}  epoch {epoch}  entry {index}",
                                short(&promise.id())
                            ),
                        );
                    }
                    Err(why) => say(out, format!("  ! {}: {why}", short(&promise.id()))),
                }
            }
            Ok(if answered > 0 { 0 } else { 2 })
        }
        AvailabilityAction::Fund {
            funder,
            per_epoch,
            from_epoch,
            to_epoch,
        } => {
            let mut node = open_node_for_writing(options)?;
            let pool = AvailabilityPool {
                funder: funder.clone(),
                per_epoch: *per_epoch,
                from_epoch: *from_epoch,
                to_epoch: *to_epoch,
                created_at: timestamp(),
            };
            let id = refused(node.post_availability_pool(&pool, &timestamp()))?;
            say(out, format!("pool {id}"));
            say(
                out,
                format!(
                    "  {per_epoch} units per epoch, epochs {from_epoch}..={to_epoch}, ceiling {}",
                    pool.ceiling()
                ),
            );
            Ok(0)
        }
        AvailabilityAction::Settle { epoch } => {
            let mut node = open_node_for_writing(options)?;
            let now = current_epoch()?;
            // Only closed epochs, for the same reason claims settle a closed
            // epoch: a node still inside the epoch has not run out of time to
            // answer, and paying early would record silence that was not.
            let epoch = match epoch {
                Some(epoch) => *epoch,
                None => match now.checked_sub(1) {
                    Some(previous) => previous,
                    None => {
                        say(out, "no epoch has closed yet");
                        return Ok(0);
                    }
                },
            };
            if epoch >= now {
                return Err(CliError::Usage(format!(
                    "epoch {epoch} has not closed yet (it is now {now}); a node inside \
                     an epoch has not run out of time to answer"
                )));
            }
            match refused(node.settle_availability(epoch, &timestamp()))? {
                None => {
                    say(out, format!("epoch {epoch}: nothing to settle"));
                    Ok(0)
                }
                Some(outcome) => {
                    say(
                        out,
                        format!(
                            "epoch {}: {} answered, {} silent",
                            outcome.epoch, outcome.answered, outcome.silent
                        ),
                    );
                    say(
                        out,
                        format!(
                            "  {} units paid by weight, {} left in the pot",
                            outcome.paid, outcome.unpaid
                        ),
                    );
                    Ok(0)
                }
            }
        }
        AvailabilityAction::Status => {
            let node = open_node(options)?;
            let now = current_epoch()?;
            let promises = node.undertakings();
            let pools = node.availability_pools();
            say(
                out,
                format!(
                    "epoch {now}  {} promise(s)  {} pool(s)  {} units offered this epoch",
                    promises.len(),
                    pools.len(),
                    node.availability_offered(now)
                ),
            );
            let answers = node.availability_answers();
            for promise in &promises {
                let id = promise.id();
                let answered = answers
                    .iter()
                    .filter(|answer| answer.undertaking == id)
                    .count();
                let sample = node
                    .sampled_index(promise, now, node.ledger().len())
                    .map(|index| index.to_string())
                    .unwrap_or_else(|_| String::from("-"));
                say(
                    out,
                    format!(
                        "  {}  {} entries by {}  {answered} answer(s)  this epoch: entry {sample}",
                        short(&id),
                        promise.height,
                        short(&promise.identity),
                    ),
                );
            }
            Ok(0)
        }
    }
}

/// The epoch containing this moment, by the same rule every record uses.
fn current_epoch() -> Result<u64, CliError> {
    epoch_of_stamp(&timestamp())
}

/// The epoch a record stamped `ts` belongs to.
///
/// The epoch of a record is derived from the record, never from a clock -- see
/// the module docs on [`proofwork::partition`]. Anything that reads a clock
/// again to decide a record's epoch is reading a different number.
fn epoch_of_stamp(ts: &str) -> Result<u64, CliError> {
    let seconds = proofwork::time::parse_rfc3339(ts)
        .and_then(|seconds| u64::try_from(seconds).ok())
        .ok_or_else(|| {
            CliError::Usage(format!("cannot read the timestamp {ts:?} as an instant"))
        })?;
    Ok(proofwork::partition::epoch_of(
        seconds,
        proofwork::partition::epoch_seconds(),
    ))
}

/// Emit a Merkle inclusion proof for one entry.
///
/// `checkpoint` gives a reader a root; this gives them a reason to care about
/// one. Without it a reader who wants to check a single settlement has two
/// options, both bad: take the operator's word for it, or download the log.
///
/// The proof is against the root of the log *as it stands*, which is almost
/// never the root a reader already holds -- theirs was signed at some earlier
/// height. `--height` is the fix, and the summary prints the height used so
/// that a proof and a checkpoint that will not meet are visibly not going to.
fn cmd_prove(
    out: &mut dyn Write,
    options: &Options,
    seq: u64,
    height: Option<u64>,
    destination: Option<&str>,
) -> Result<i32, CliError> {
    let node = open_node(options)?;
    let full = ledger_of(&node);
    let trimmed = match height {
        None => None,
        Some(height) => {
            let height = usize::try_from(height)
                .map_err(|_| CliError::Overflow(String::from("--height")))?;
            Some(full.prefix(height).ok_or_else(|| {
                CliError::Usage(format!(
                    "--height {height} but the log has only {} entries",
                    full.len()
                ))
            })?)
        }
    };
    let ledger: &Ledger = trimmed.as_ref().unwrap_or(full);
    let proof = ledger.prove(seq).ok_or_else(|| {
        CliError::Usage(format!(
            "no entry {seq}: the log covers seq 0..{}",
            ledger.len().saturating_sub(1)
        ))
    })?;
    // Belt and braces. A proof this binary emits that does not check is a bug
    // here, and the person who would discover it is a stranger with no way to
    // tell that from a lying operator.
    let root = ledger
        .root()
        .ok_or_else(|| CliError::Usage(String::from("the log is empty")))?;
    if let Err(why) = proof.check(&root) {
        return Err(CliError::Checkpoint(format!(
            "refusing to emit a proof that does not check: {why}"
        )));
    }

    let text = proof.to_value().canonical_string();
    match destination {
        Some(path) => {
            fs::write(path, format!("{text}\n")).map_err(|error| CliError::Io {
                context: format!("writing {path}"),
                source: error,
            })?;
            say(out, format!("wrote {path}"));
        }
        None => say(out, &text),
    }
    say(
        out,
        format!(
            "  entry {seq} ({})  height {}  root {}  path {} hashes",
            proof.entry.kind,
            ledger.len(),
            short(&root),
            proof.inclusion.siblings.len()
        ),
    );
    say(
        out,
        "  Readers check with `proofwork check <file> --from <checkpoint.json> --root-key <hex|file>`.",
    );
    if height.is_none() && full.len() > 1 {
        say(
            out,
            "  This is against the log's current height. A reader holding an older",
        );
        say(out, "  checkpoint needs `--height <their height>` instead.");
    }
    Ok(0)
}

/// Check an inclusion proof against a root.
///
/// Runs with no log, no bundle, and no network -- everything it needs is the
/// proof and one root. That is what makes it a light client rather than a
/// second operator.
///
/// Exit codes follow `verify`: 1 is "checked, and the answer is no", 2 is
/// "could not check", and the two must not be confused by anyone scripting
/// against this.
fn cmd_check(
    out: &mut dyn Write,
    proof_path: &str,
    root: Option<&str>,
    checkpoint_path: Option<&str>,
    root_key: Option<&str>,
) -> Result<i32, CliError> {
    let proof = Proof::from_value(&read_json(proof_path)?)
        .map_err(|source| CliError::Checkpoint(format!("{proof_path}: {source}")))?;

    let mut unauthenticated = false;
    let (root, height) = match (root, checkpoint_path) {
        (Some(root), _) => (root.to_string(), None),
        (None, Some(path)) => {
            let signed = SignedCheckpoint::from_value(&read_json(path)?)
                .map_err(|source| CliError::Checkpoint(source.to_string()))?;
            // Same trap as `verify`, and the same answer: without a key from
            // somewhere else this checks the file against itself, and an
            // operator rewriting history signs the rewrite with a fresh key.
            let expected = match root_key {
                Some(source) => read_root_key(source)?,
                None => {
                    unauthenticated = true;
                    signed.public_key.clone()
                }
            };
            if let Err(error) = signed.verify(&expected) {
                say(out, format!("checkpoint FAILED: {error}"));
                return Ok(1);
            }
            match signed.checkpoint.root.clone() {
                Some(root) => (root, Some(signed.checkpoint.height)),
                None => {
                    say(out, "checkpoint FAILED: it pins no root (empty log)");
                    return Ok(1);
                }
            }
        }
        // Unreachable: the parser already refused neither-and-both.
        (None, None) => {
            return Err(CliError::Usage(String::from(
                "check: needs --merkle-root or --from",
            )))
        }
    };

    // A proof is against a tree of one particular size, so a proof and a
    // checkpoint that disagree on the height are about two different logs. The
    // path check below would catch it, but as "does not reach the root", which
    // reads as dishonesty when the honest cause is a stale checkpoint.
    if let Some(height) = height {
        if u64::try_from(proof.inclusion.leaves).ok() != Some(height) {
            say(
                out,
                format!(
                    "proof FAILED: it is against a log of {} entries, \
                     but the checkpoint pins {height}",
                    proof.inclusion.leaves
                ),
            );
            say(
                out,
                format!(
                    "  ask the holder for `proofwork prove {} --height {height}`",
                    proof.entry.seq
                ),
            );
            return Ok(1);
        }
    }

    if let Err(why) = proof.check(&root) {
        say(out, format!("proof FAILED: {why}"));
        return Ok(1);
    }

    say(
        out,
        format!(
            "proof ok: entry {} ({}) is in the log rooted at {}",
            proof.entry.seq,
            proof.entry.kind,
            short(&root)
        ),
    );
    say(
        out,
        format!(
            "  {} entries, {} hashes checked, ts {}",
            proof.inclusion.leaves,
            proof.inclusion.siblings.len(),
            proof.entry.ts
        ),
    );
    if unauthenticated {
        say(
            out,
            "  warning: no --root-key given, so the checkpoint was checked against \
             itself; pin the operator's published key to make this mean anything",
        );
    }
    Ok(0)
}

/// A root key given as hex on the command line, or as a file holding hex.
///
/// Both spellings, because a 1952-byte ML-DSA-65 key is 3904 hex characters and
/// no one is pasting that into a shell. Which one was meant is decided by
/// whether the argument names an existing file, not by a flag: a path and a
/// hex blob are not confusable.
fn read_root_key(source: &str) -> Result<Vec<u8>, CliError> {
    let text = if Path::new(source).is_file() {
        fs::read_to_string(source).map_err(|error| CliError::Io {
            context: format!("reading {source}"),
            source: error,
        })?
    } else {
        source.to_string()
    };
    let text: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if !text.len().is_multiple_of(2) {
        return Err(CliError::Usage(String::from(
            "--root-key: hex has an odd number of digits",
        )));
    }
    let mut bytes = Vec::with_capacity(text.len() / 2);
    let digits: Vec<char> = text.chars().collect();
    for pair in digits.chunks(2) {
        let hex: String = pair.iter().collect();
        let byte = u8::from_str_radix(&hex, 16)
            .map_err(|_| CliError::Usage(format!("--root-key: {hex:?} is not hex")))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn cmd_attribute(
    out: &mut dyn Write,
    options: &Options,
    params: &FlowParams,
) -> Result<i32, CliError> {
    let node = open_node(options)?;
    let ledger = ledger_of(&node);
    let claims = claim_index(ledger)?;
    let settlements = settlements_of(ledger)?;
    let payouts = payouts_over(&settlements, &claims, params).map_err(CliError::Flow)?;

    for line in render_attribution(params, &payouts)? {
        say(out, line);
    }
    Ok(0)
}

/// Print the incentive report and say whether the mechanism holds.
///
/// Exit code 1 when it does not, matching `audit`: both are "the tool ran fine
/// and the answer is bad news", which a script has to be able to tell from "the
/// tool could not run". A failing report is still printed in full -- the useful
/// part is *which* line failed.
fn cmd_incentives(
    out: &mut dyn Write,
    params: &NodeParams,
    robustness: bool,
) -> Result<i32, CliError> {
    let report = IncentiveReport::of(params).map_err(|error| CliError::Usage(error.to_string()))?;
    for line in report.to_string().lines() {
        say(out, line);
    }
    if robustness {
        say(out, "");
        say(
            out,
            "robustness -- how far each parameter moves before honesty stops holding",
        );
        // Progress to stderr, so `incentives --robustness > report.txt` still
        // writes exactly the report. The sweep re-evaluates the whole mechanism
        // once per rung and takes minutes; silent, that is indistinguishable
        // from a hang, and the usual response to a hang is to kill it.
        eprintln!(
            "  (each parameter is walked out along a 12-rung ladder in both \
             directions, re-evaluating the whole mechanism at every rung -- \
             this takes minutes)"
        );
        let margins = proofwork::incentive::robustness::margins_reporting(
            params,
            |parameter, done, total| {
                eprintln!("  [{done}/{total}] {parameter}");
            },
        )
        .map_err(|error| CliError::Usage(error.to_string()))?;
        for margin in &margins {
            say(out, format!("  {margin}"));
        }
        // The line that changes what somebody does next. A verdict says the
        // mechanism works; this says which measurement it is betting on.
        match margins.iter().find(|m| m.factor.is_some()) {
            Some(binding) => say(
                out,
                format!(
                    "  binding constraint    {} -- measure this one first",
                    binding.parameter
                ),
            ),
            None => say(
                out,
                "  no parameter breaks within the ladder, or the point already fails",
            ),
        }
    }
    Ok(if report.passes() { 0 } else { 1 })
}

/// `try <objective-id|objective.json> --submitter S --artifact FILE ...`
///
/// Post if needed, commit, wait for the epoch to turn, reveal, print the
/// verdict. A wrapper over the existing primitives -- it appends nothing the
/// five commands it calls would not have appended, in the same order.
///
/// Two things it is careful about.
///
/// **It waits by polling the epoch, not by sleeping a duration.** The rule is
/// that a reveal must land in a *strictly later epoch* than its commitment, and
/// an epoch comes from the record rather than from a clock. `sleep 610` is a
/// guess at that rule; re-reading the epoch until it changes is the rule.
///
/// **It never shortens the epoch itself.** A real round takes a real epoch --
/// 600 seconds by default -- and `PROOFWORK_EPOCH_SECONDS` exists for exactly
/// this kind of local trial. Setting it here, silently, for a command that
/// writes to whatever log it was pointed at, is the documented footgun in
/// `docs/launch-review.md`: a log written under a short epoch and read back
/// under a long one puts every commitment and its claim in the same epoch, so
/// every replayed reveal is refused and record sync stops importing work
/// without erroring. So the wait is announced up front, in seconds, with the
/// variable named -- and the operator decides.
/// One round's inputs, grouped because they travel together and because most
/// of them are strings -- passed positionally, swapping two would compile
/// cleanly and write the wrong record.
struct Round<'a> {
    /// An objective id, or a file to post first.
    objective: &'a str,
    who: Submitter<'a>,
    artifact_path: &'a str,
    nonce: Option<&'a str>,
    cites: &'a [String],
    settle: bool,
}

fn cmd_try(out: &mut dyn Write, options: &Options, round: Round<'_>) -> Result<i32, CliError> {
    let Round {
        objective,
        who,
        artifact_path,
        nonce,
        cites,
        settle,
    } = round;
    // A file, or an id already in the log. Deciding by prefix rather than by
    // `Path::exists` keeps the two cases from swapping under a stray file
    // named after a digest.
    let objective_id = if objective.starts_with("sha256:") {
        objective.to_string()
    } else {
        // Posting an objective already in the log is not an error *here*, even
        // though `post` refuses it. An objective's id is the hash of its own
        // content, so "already posted" means byte-identical -- there is nothing
        // to reconcile and no rule being relaxed. Refusing would break the one
        // thing this command exists for: pointing it at the same file again
        // after editing an artifact is the local iteration loop.
        let data = read_json(objective)?;
        validate_objective(&data).map_err(CliError::Schema)?;
        let id = Objective::from_value(&data).map_err(CliError::Record)?.id();
        if open_node(options)?.objectives().contains_key(&id) {
            say(out, format!("objective {id}"));
            say(out, "  already posted; using it");
            id
        } else {
            post_objective_file(out, options, objective)?
        }
    };

    let nonce = match nonce {
        Some(nonce) => nonce.to_string(),
        None => random_nonce()?,
    };
    let (submitter, identity) = who.resolve()?;
    let artifact = read_json(artifact_path)?;

    let stamp = timestamp();
    let hash = commitment_hash(&objective_id, &submitter, &artifact, &nonce);
    let commitment = Commitment::new(&objective_id, &submitter, hash.as_str(), stamp.as_str());
    let commitment = match &identity {
        Some(identity) => commitment.signed_with(identity),
        None => commitment,
    };
    {
        let mut node = open_node_for_writing(options)?;
        post_commitment(&mut node, &commitment, &stamp)?;
    }
    // From the commitment's own `created_at`, not from a second clock reading.
    // The rule is that an epoch comes from the record, and a clock read a
    // moment later can land on the far side of a boundary the record did not
    // cross -- which would make this wait a whole extra epoch for nothing.
    let committed_in = epoch_of_stamp(&stamp)?;
    say(out, format!("commit {}", short(&hash)));
    say(out, format!("  nonce {nonce}"));

    // Announced before the wait, not after it: a command that goes quiet for
    // ten minutes is indistinguishable from one that has hung, and the usual
    // response to a hang is to kill it -- which leaves a commitment nobody
    // ever opened.
    let length = proofwork::partition::epoch_seconds();
    say(
        out,
        format!(
            "  waiting for epoch {} to start; epochs are {length}s here, so this takes up to \
             {length}s",
            committed_in.saturating_add(1)
        ),
    );
    if length >= proofwork::partition::EPOCH_SECONDS {
        say(
            out,
            format!(
                "  (set ${}=10 for a local trial -- but only against a log used for nothing \
                 else: epochs are derived from record timestamps, so two settings disagree \
                 about which reveals were legal)",
                proofwork::partition::EPOCH_SECONDS_ENV
            ),
        );
    }
    wait_for_epoch_after(committed_in)?;

    // The frontier citation is mechanical, not a choice: once an objective has
    // a frontier, *every* submission must cite the claim holding it, and a
    // reveal without it is refused. Added here rather than left to the caller
    // because a wrapper that reliably fails on every progressive objective is
    // not a wrapper. Anything the caller passed is kept -- claims you actually
    // built on are yours to name and nothing else may be added.
    let mut cites = cites.to_vec();
    {
        let node = open_node(options)?;
        if let Some(frontier) = node.frontier_of(&objective_id) {
            if !cites.iter().any(|cited| cited == &frontier.claim_id) {
                say(out, format!("  citing the frontier {}", frontier.claim_id));
                cites.push(frontier.claim_id);
            }
        }
    }

    let stamp = timestamp();
    let claim = Claim::new(
        &objective_id,
        &submitter,
        artifact,
        &nonce,
        stamp.as_str(),
        cites,
    )
    .map_err(CliError::Record)?;
    let claim = match &identity {
        Some(identity) => claim.signed_with(identity),
        None => claim,
    };
    validate_claim(&claim.to_value()).map_err(CliError::Schema)?;

    let mut node = open_node_for_writing(options)?;
    let report = reveal_claim(&mut node, &claim, &stamp)?;
    say(out, format!("claim {}", report.claim_id));
    say(
        out,
        format!("  verdict  {}: {}", report.status, report.detail),
    );

    match report.pending_epoch {
        Some(epoch) if settle => {
            drop(node);
            say(
                out,
                format!("  waiting for epoch {epoch} to close, then settling"),
            );
            wait_for_epoch_after(epoch)?;
            let mut node = open_node_for_writing(options)?;
            let settled = settle_now(&mut node, &timestamp())?;
            match settled
                .iter()
                .find(|(claim_id, _, _, _)| claim_id == &report.claim_id)
            {
                Some((_, moved, reward, note)) => say(
                    out,
                    format!("  settled  {moved}  reward {reward}  ({note})"),
                ),
                // The batch closed without this claim in it. Reported rather
                // than assumed: settlement order is not ours to predict, and a
                // claim missing from its own batch is worth looking at.
                None => say(
                    out,
                    "  settled  nothing moved for this claim in the batch that just closed",
                ),
            }
        }
        Some(epoch) => say(
            out,
            format!(
                "  pending  settles when epoch {epoch} closes  (`proofwork try --settle`, or \
                 `proofwork settle` later)"
            ),
        ),
        None => say(
            out,
            format!(
                "  settled  {}  reward {}  ({})",
                report.settled, report.reward, report.note
            ),
        ),
    }

    // Same exit meaning as `reveal`: a rejection is a real answer and exits 0,
    // a verdict that settles nothing exits 3.
    Ok(if report.settles { 0 } else { 3 })
}

/// Block until the current epoch is strictly after `epoch`.
///
/// Polls rather than sleeping a computed duration. The seconds-remaining
/// arithmetic is advisory -- it reads a clock, and the rule reads records --
/// so it decides only how long to nap between checks, never when to stop.
fn wait_for_epoch_after(epoch: u64) -> Result<(), CliError> {
    // Progress to stderr, so `try ... > verdict.txt` still captures exactly the
    // round. A minute of silence is what makes a caller reach for Ctrl-C, and a
    // killed `try` leaves a commitment nobody ever opened.
    const TICK: u64 = 1;
    const REPORT_EVERY: u64 = 30;
    let mut waited = 0u64;
    loop {
        if current_epoch()? > epoch {
            if waited >= REPORT_EVERY {
                eprintln!("  epoch turned after {waited}s");
            }
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(TICK));
        waited = waited.saturating_add(TICK);
        if waited.is_multiple_of(REPORT_EVERY) {
            eprintln!(
                "  still waiting for epoch {} ({waited}s)",
                epoch.saturating_add(1)
            );
        }
    }
}

/// `scaffold <name> --kind <kind> [--out DIR] ...`
///
/// Writes files and stops. The next step is a human reading them and running
/// the `post` line this prints -- see [`proofwork::scaffold`] for why that
/// boundary is where it is.
fn cmd_scaffold(
    out: &mut dyn Write,
    options: &Options,
    request: &scaffold::Request,
    force: bool,
) -> Result<i32, CliError> {
    let plan = scaffold::plan(request).map_err(|error| CliError::Usage(error.to_string()))?;
    let root = Path::new(&options.root);

    // Every collision found before anything is written, so a refusal leaves the
    // directory exactly as it was. Scaffolding over an objective already posted
    // is the mistake worth being careful about: its pin is in the log and its
    // id covers it, so the log would still name a file that no longer exists.
    if !force {
        let existing: Vec<&str> = plan
            .files
            .iter()
            .map(|(path, _)| path.as_str())
            .filter(|path| root.join(path).exists())
            .collect();
        if !existing.is_empty() {
            return Err(CliError::Usage(format!(
                "scaffold would overwrite {}: {}. Pass --force if that is what you meant \
                 -- but if any of these is already posted, its pin is in the log and its \
                 id covers it",
                existing.len(),
                existing.join(", ")
            )));
        }
    }

    for (path, contents) in &plan.files {
        let target = root.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|source| CliError::Io {
                context: format!("creating {}", parent.display()),
                source,
            })?;
        }
        fs::write(&target, contents).map_err(|source| CliError::Io {
            context: format!("writing {}", target.display()),
            source,
        })?;
        say(out, format!("wrote {path}"));
    }

    say(out, "");
    say(out, "before posting, decide:");
    for item in &plan.todo {
        say(out, format!("  - {item}"));
    }
    say(out, "");
    // Printed rather than run. The scaffolder writes files; funding one is a
    // human decision, and this is where it is handed back.
    //
    // The paths here are where the files actually landed, which is not the path
    // inside the record: a pin resolves against `--root`, while `post` and
    // `--artifact` read relative to the working directory. Printing the record's
    // spelling would hand back a command that works only when the two coincide.
    let root_flag = if options.root == "." {
        String::new()
    } else {
        format!(" --root {}", options.root)
    };
    let on_disk = |path: &str| root.join(path).display().to_string();
    let artifact = plan
        .objective_path
        .strip_suffix("objective.json")
        .map(|dir| format!("{dir}artifact.json"))
        .unwrap_or_else(|| String::from("artifact.json"));
    say(out, "then post it:");
    say(
        out,
        format!(
            "  proofwork{root_flag} post {}",
            on_disk(&plan.objective_path)
        ),
    );
    say(
        out,
        format!(
            "  proofwork{root_flag} try {} --submitter you --artifact {}",
            on_disk(&plan.objective_path),
            on_disk(&artifact)
        ),
    );
    Ok(0)
}

/// `incentives --sweep NAME=LO..HI[:STEPS] ... [--out FILE] [--format csv|jsonl]`
///
/// The same evaluation `cmd_incentives` runs, once per grid point, as a table.
/// Nothing is re-derived here: a disagreement between a swept row and the
/// single-point report for the same parameters would be a bug in the sweep, and
/// keeping that true is worth more than any per-point formatting.
///
/// The table goes to `--out` or to standard output, and progress goes to
/// standard error, so `incentives --sweep .. > grid.csv` writes exactly the
/// table -- the same split `--robustness` already makes.
fn cmd_incentives_sweep(
    out: &mut dyn Write,
    params: &NodeParams,
    axes: &[sweep::Axis],
    robustness: bool,
    destination: Option<&str>,
    format: TableFormat,
) -> Result<i32, CliError> {
    // Sized before anything runs, so an operator who mistyped a step count
    // finds out now rather than after the first minute of silence.
    let points = sweep::grid(axes).map_err(|error| CliError::Usage(error.to_string()))?;
    eprintln!(
        "sweeping {} point(s) over {}",
        points.len(),
        axes.iter()
            .map(|axis| format!("{} ({} value(s))", axis.knob.name(), axis.values.len()))
            .collect::<Vec<_>>()
            .join(", ")
    );
    if robustness {
        // `--robustness` is hundreds of solver runs *per point*. Composing is
        // what the flag means, so it is allowed; being quiet about the cost
        // would not be.
        eprintln!(
            "  --robustness re-walks every parameter at every point: expect minutes per point"
        );
    }

    let mut rows = sweep::run(params, axes, |done, total| {
        // Every point, not every tenth: the grid is small enough that a line
        // per point is a progress bar, and a sweep that prints nothing for a
        // minute is indistinguishable from a hang.
        eprintln!("  [{}/{total}]", done.saturating_add(1));
    })
    .map_err(|error| CliError::Usage(error.to_string()))?;

    if robustness {
        // Zipped rather than indexed. `points` and `rows` line up because
        // `sweep::run` enumerates the same pure `grid(axes)`; if that ever
        // stops being true the column is simply absent rather than attached to
        // the wrong point, and a margin reported against the wrong parameters
        // is worse than no margin at all.
        for (assignment, row) in points.iter().zip(rows.iter_mut()) {
            let mut point = params.clone();
            for (axis, value) in axes.iter().zip(assignment) {
                axis.knob.apply(&mut point, *value);
            }
            // Four outcomes, spelled differently, because collapsing them
            // would make an empty cell mean "nothing binds here" and "we could
            // not tell" at once -- and the whole use of this column is deciding
            // which measurement to fund first.
            let binding = match point.validate() {
                // A point `validate` refuses has no margins to report; its row
                // already carries the reason in `error`. Blank rather than
                // absent, so every row still has the same columns.
                Err(_) => String::new(),
                Ok(()) => {
                    match proofwork::incentive::robustness::margins_reporting(&point, |_, _, _| {})
                    {
                        Ok(margins) => margins
                            .iter()
                            .find(|margin| margin.factor.is_some())
                            .map(|margin| margin.parameter.to_string())
                            // The same sentence the single-point report gives:
                            // either nothing breaks within the ladder, or the
                            // point already fails and there is no margin to
                            // measure from. `verdict` tells them apart.
                            .unwrap_or_else(|| String::from("none")),
                        Err(_) => String::from("unavailable"),
                    }
                }
            };
            row.cells
                .push((String::from("binding_constraint"), binding));
        }
    }

    let table = match format {
        TableFormat::Csv => sweep::to_csv(&rows),
        TableFormat::Jsonl => sweep::to_jsonl(&rows),
    };
    match destination {
        Some(path) => {
            fs::write(path, &table).map_err(|source| CliError::Io {
                context: format!("writing {path}"),
                source,
            })?;
            let passing = rows.iter().filter(|row| row.passes()).count();
            say(
                out,
                format!(
                    "{} row(s) written to {path}  ({passing} pass, {} do not)",
                    rows.len(),
                    rows.len().saturating_sub(passing)
                ),
            );
        }
        None => {
            for line in table.lines() {
                say(out, line);
            }
        }
    }

    // Exit 1 when no point holds, matching the single-point command's meaning
    // of "the incentives do not hold". A sweep whose whole point is to find
    // where the mechanism breaks would be useless if any failing row failed
    // the command, so the bar is that *something* in the grid works.
    Ok(if rows.iter().any(sweep::Row::passes) {
        0
    } else {
        1
    })
}

// ---------------------------------------------------------------------------
// The local store
// ---------------------------------------------------------------------------

/// Decide how to read and write this invocation's log.
///
/// The ledger deliberately refuses to guess ([`Ledger::open_with`]); this is
/// where the guessing is allowed to happen, because it is a user-experience
/// decision rather than an integrity one. The rule:
///
/// * a log whose first line is sealed needs the key, and says so if it is
///   missing rather than reporting the file as corrupt;
/// * a log that is already plaintext stays plaintext, even if a key exists --
///   converting somebody's log as a side effect of an unrelated command would
///   be indefensible, and `store encrypt` is the command that does it on
///   purpose;
/// * a log that does not exist yet is created sealed **if a key is there**, so
///   `keygen` followed by ordinary use encrypts without further ceremony.
fn resolve_codec(options: &Options) -> Result<Codec, CliError> {
    let sealed_on_disk = first_line_is_sealed(&options.log)?;
    let key_path = options.key_path();
    let exists = key_path.exists();

    match (sealed_on_disk, exists) {
        (Some(true), false) => Err(CliError::AtRest(AtRestError::NoKeyFile { path: key_path })),
        (Some(true), true) | (None, true) => {
            let passphrase = options.passphrase()?;
            let cipher = Cipher::read_key_file(&key_path, passphrase.as_deref())
                .map_err(CliError::AtRest)?;
            Ok(Codec::Sealed(Box::new(cipher)))
        }
        // Plaintext log, or no log and no key: unchanged behaviour.
        (Some(false), _) | (None, false) => Ok(Codec::Plain),
    }
}

/// `Some(true)` sealed, `Some(false)` plaintext, `None` for an absent or empty log.
fn first_line_is_sealed(path: &str) -> Result<Option<bool>, CliError> {
    if !Path::new(path).exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(path).map_err(|source| CliError::Io {
        context: format!("reading {path}"),
        source,
    })?;
    Ok(text
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(proofwork::store::atrest::is_sealed_line))
}

fn cmd_keygen(out: &mut dyn Write, options: &Options, wrap: bool) -> Result<i32, CliError> {
    let path = options.key_path();
    let passphrase = options.passphrase()?;
    if wrap && passphrase.is_none() {
        return Err(CliError::Usage(String::from(
            "keygen --passphrase needs a passphrase: set $PROOFWORK_PASSPHRASE or \
             pass --passphrase-file PATH. There is no prompt, because reading one \
             without echoing it needs terminal control this binary does not link",
        )));
    }
    let cipher = Cipher::generate(&mut rand_core::OsRng);
    cipher
        .write_key_file(
            &path,
            if wrap { passphrase.as_deref() } else { None },
            &mut rand_core::OsRng,
        )
        .map_err(CliError::AtRest)?;

    say(out, format!("key written to {}", path.display()));
    if wrap {
        say(out, "  wrapped with a passphrase (argon2id)");
    }
    if !proofwork::store::atrest::private_permissions_supported() {
        say(
            out,
            "  warning: this platform cannot restrict the key to its owner",
        );
    }
    // The one thing an operator has to be told, once, loudly.
    let store = options.store();
    if path.starts_with(store.root()) {
        say(out, "");
        say(
            out,
            "  WARNING: this key is INSIDE the data directory. Anything that copies",
        );
        say(
            out,
            "  that directory copies the key with it, which is not encryption at all.",
        );
        say(
            out,
            "  `proofwork sync` refuses to copy it; other tools will not.",
        );
    }
    say(out, "");
    say(
        out,
        "Back this file up somewhere the data is not. Lose it and the log is",
    );
    say(
        out,
        "unreadable -- there is no recovery path and that is the design.",
    );
    Ok(0)
}

fn cmd_store(
    out: &mut dyn Write,
    options: &Options,
    action: &StoreAction,
) -> Result<i32, CliError> {
    let store = options.store();
    match action {
        StoreAction::Status => {
            let usage = quota::usage(&store).map_err(CliError::Store)?;
            say(out, format!("store   {}", store.root().display()));
            say(out, format!("log     {}", options.log));
            say(
                out,
                format!(
                    "sealed  {}",
                    match first_line_is_sealed(&options.log)? {
                        Some(true) => "yes",
                        Some(false) => "no -- run `proofwork store encrypt`",
                        None => "n/a (log is empty)",
                    }
                ),
            );
            let key = options.key_path();
            say(
                out,
                format!(
                    "key     {} ({})",
                    key.display(),
                    if key.exists() { "present" } else { "absent" }
                ),
            );
            say(
                out,
                format!("usage   {}", quota::describe(&usage, store.limit())),
            );
            // What encryption covers, and what it does not. Reported here
            // rather than left to a document, because the asymmetry -- a sealed
            // log beside a plainly-named blob store -- is a decision the
            // operator should be able to check against their own disk. See
            // `store::exposure` for the decision itself.
            let survey = exposure::survey(&store).map_err(CliError::Store)?;
            say(out, format!("at rest {}", survey.describe()));

            // Keys first, then a bounded number of the rest.
            //
            // A tripwire that prints seven hundred lines is a tripwire nobody
            // reads, and pointing this at a working directory produces exactly
            // that. The count and the exit code carry the alarm; the list is
            // there to start the investigation, not to finish it. Keys are
            // never elided -- a key inside the store means everything beside it
            // is readable, and that finding must not be the one that scrolled
            // past.
            const SHOWN: usize = 20;
            let findings = survey.findings.len();
            let (keys, rest): (Vec<_>, Vec<_>) = survey
                .findings
                .iter()
                .partition(|(_, what)| matches!(what, exposure::Exposure::Key));
            for (path, _) in &keys {
                say(
                    out,
                    format!("        KEY INSIDE THE STORE: {}", path.display()),
                );
            }
            for (path, _) in rest.iter().take(SHOWN) {
                say(
                    out,
                    format!("        unaccounted plaintext: {}", path.display()),
                );
            }
            if rest.len() > SHOWN {
                say(
                    out,
                    format!(
                        "        ... and {} more unaccounted file(s)",
                        rest.len() - SHOWN
                    ),
                );
            }
            if findings > 0 {
                say(
                    out,
                    "        Each is readable on any disk holding this directory.",
                );
                if survey.holds_a_key() {
                    say(
                        out,
                        "        A key here makes everything beside it readable too, which",
                    );
                    say(
                        out,
                        "        is not encryption at all. Move it out of the store.",
                    );
                }
            }
            if let Some(limit) = store.limit() {
                if usage.over(limit) {
                    say(out, "        OVER LIMIT -- run `proofwork store gc`");
                    return Ok(1);
                }
            }
            // Exit 1 for a finding: a script that runs `store status` in a
            // health check has to be able to notice one, and printing a warning
            // that exits 0 is how a warning becomes invisible.
            if findings > 0 {
                return Ok(1);
            }
            Ok(0)
        }
        StoreAction::Gc => {
            if store.limit().is_none() {
                return Err(CliError::Usage(String::from(
                    "store gc needs a limit: pass --max-size, for example --max-size 20GB",
                )));
            }
            let eviction = quota::reclaim(&store, 0).map_err(CliError::Store)?;
            if eviction.is_empty() {
                say(out, "nothing to reclaim");
            } else {
                for (path, bytes) in &eviction.removed {
                    say(
                        out,
                        format!(
                            "evicted {} ({})",
                            path.display(),
                            proofwork::store::format_size(*bytes)
                        ),
                    );
                }
                say(
                    out,
                    format!(
                        "freed {} -- {}",
                        proofwork::store::format_size(eviction.freed),
                        quota::describe(&eviction.after, store.limit())
                    ),
                );
                say(
                    out,
                    "note: evicted content can no longer answer an availability challenge.",
                );
            }
            Ok(0)
        }
        StoreAction::Encrypt => cmd_encrypt(out, options),
        StoreAction::Rekey {
            new_passphrase_file,
        } => cmd_rekey(out, options, new_passphrase_file.as_deref()),
        StoreAction::Export { out: destination } => cmd_export(out, options, destination),
    }
}

/// Write a plaintext copy of the log somewhere, leaving the store alone.
///
/// # Why the inverse of `store encrypt` has to exist
///
/// The project's central claim is that anyone holding a copy of the log can
/// re-derive every settled result. `store encrypt` seals an operator's own copy,
/// and until this existed it was a one-way door: an operator who sealed their
/// store had no way to *produce* the readable log that claim depends on. `sync`
/// mirrors ciphertext by design, and `log` prints a summary rather than records.
/// The only route left was decrypting by hand, which is the improvisation this
/// whole module exists to remove.
///
/// It writes a copy rather than converting in place, because the need is to hand
/// somebody a log, not to stop encrypting. Converting is `store encrypt`'s
/// business, running the other way.
///
/// The output is plaintext, and refusing to overwrite is the one safety property
/// available: an export that silently replaced a file would be a way to lose data
/// by typo, and the destination is by definition somewhere the operator is about
/// to share.
fn cmd_export(out: &mut dyn Write, options: &Options, destination: &str) -> Result<i32, CliError> {
    if Path::new(destination).exists() {
        return Err(CliError::Refused(format!(
            "{destination} already exists; exporting over it would be a way to \
             lose a log to a typo. Choose another path or move that one aside"
        )));
    }
    let source =
        Ledger::open_with(&options.log, resolve_codec(options)?).map_err(CliError::Ledger)?;
    let problems = source.verify_chain();
    if !problems.is_empty() {
        // Exporting a broken log would hand somebody a copy that fails their
        // audit, and they have no way to tell whose fault that is.
        for problem in &problems {
            say(out, format!("  {problem}"));
        }
        return Err(CliError::Refused(String::from(
            "the log does not verify; fix that before handing out a copy",
        )));
    }

    {
        let mut plain = Ledger::open_with(destination, Codec::Plain).map_err(CliError::Ledger)?;
        for entry in source.entries() {
            plain
                .append(&entry.kind, entry.payload.clone(), &entry.ts)
                .map_err(CliError::Ledger)?;
        }
    }
    // Read it back before saying it worked. The point of the copy is that
    // somebody else can audit it, so it has to re-derive the same root here
    // first.
    let check = Ledger::open(destination).map_err(CliError::Ledger)?;
    if check.entries() != source.entries() || check.root() != source.root() {
        let _ = fs::remove_file(destination);
        return Err(CliError::Refused(String::from(
            "the exported copy does not re-derive the original; nothing was written",
        )));
    }

    say(
        out,
        format!(
            "exported {} entries to {destination}; root {}",
            check.len(),
            check.root().unwrap_or_default()
        ),
    );
    if source.is_sealed() {
        say(out, "");
        say(
            out,
            "This copy is PLAINTEXT. That is the point -- it is what a reader",
        );
        say(
            out,
            "audits -- but it is now a readable copy of a store you chose to",
        );
        say(
            out,
            "encrypt. Put it where you meant to, and not beside the key.",
        );
    }
    Ok(0)
}

/// Convert a plaintext log to a sealed one.
///
/// Written to a new file, verified by reading it back, and only then swapped in.
/// The plaintext original is renamed aside rather than deleted: this command
/// must not be able to destroy somebody's only copy, so the last step is left to
/// the operator and is stated loudly rather than done quietly.
fn cmd_encrypt(out: &mut dyn Write, options: &Options) -> Result<i32, CliError> {
    match first_line_is_sealed(&options.log)? {
        Some(true) => {
            say(out, "already sealed; nothing to do");
            return Ok(0);
        }
        None => {
            say(out, "log is empty or absent; nothing to convert");
            say(out, "new entries will be sealed if a key is present");
            return Ok(0);
        }
        Some(false) => {}
    }
    let key_path = options.key_path();
    if !key_path.exists() {
        return Err(CliError::AtRest(AtRestError::NoKeyFile { path: key_path }));
    }
    let passphrase = options.passphrase()?;
    let cipher =
        Cipher::read_key_file(&key_path, passphrase.as_deref()).map_err(CliError::AtRest)?;

    let plain = Ledger::open(&options.log).map_err(CliError::Ledger)?;
    let problems = plain.verify_chain();
    if !problems.is_empty() {
        // Converting a broken log would bake the breakage into ciphertext and
        // make it far harder to diagnose afterwards.
        for problem in &problems {
            say(out, format!("  {problem}"));
        }
        return Err(CliError::Refused(String::from(
            "the log does not verify; fix it before sealing it",
        )));
    }

    let sealed_path = format!("{}.sealing", options.log);
    let _ = fs::remove_file(&sealed_path);
    {
        let mut sealed = Ledger::open_with(
            &sealed_path,
            Codec::Sealed(Box::new(
                Cipher::read_key_file(&key_path, passphrase.as_deref())
                    .map_err(CliError::AtRest)?,
            )),
        )
        .map_err(CliError::Ledger)?;
        for entry in plain.entries() {
            sealed
                .append(&entry.kind, entry.payload.clone(), &entry.ts)
                .map_err(CliError::Ledger)?;
        }
    }

    // Read it back before anything is moved. An encryption step that cannot be
    // reversed is one that has to be proved right before it is trusted.
    let check = Ledger::open_with(&sealed_path, Codec::Sealed(Box::new(cipher)))
        .map_err(CliError::Ledger)?;
    if check.entries() != plain.entries() || check.root() != plain.root() {
        let _ = fs::remove_file(&sealed_path);
        return Err(CliError::Refused(String::from(
            "the sealed copy does not re-derive the original; nothing was changed",
        )));
    }

    let backup = format!("{}{}", options.log, mirror::PLAINTEXT_BACKUP_SUFFIX);
    fs::rename(&options.log, &backup).map_err(|source| CliError::Io {
        context: format!("moving {} aside", options.log),
        source,
    })?;
    fs::rename(&sealed_path, &options.log).map_err(|source| CliError::Io {
        context: format!("installing {}", options.log),
        source,
    })?;

    say(
        out,
        format!(
            "sealed {} entries; root unchanged at {}",
            check.len(),
            check.root().unwrap_or_default()
        ),
    );
    say(out, "");
    say(
        out,
        format!("The PLAINTEXT original is still on disk at {backup}"),
    );
    say(
        out,
        "Delete it yourself once you have confirmed the sealed log reads back.",
    );
    say(
        out,
        "It is left in place because this command must not be able to",
    );
    say(out, "destroy your only copy.");
    Ok(0)
}

/// A sibling path, `path` with `suffix` glued on.
///
/// Through `OsString` rather than `format!("{}", path.display())`, which is
/// lossy on a path that is not valid UTF-8, and rather than
/// `Path::with_extension`, which would turn `key.pw` into `key.previous`
/// instead of `key.pw.previous`.
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Take the cipher back out of a codec this function just built.
///
/// The `Plain` arm cannot arise -- the codec was constructed as `Sealed` a few
/// lines above every call site -- but it is reported rather than unwrapped,
/// because "cannot arise" is an argument about today's code.
fn reclaim_cipher(codec: Codec) -> Result<Cipher, CliError> {
    match codec {
        Codec::Sealed(cipher) => Ok(*cipher),
        Codec::Plain => Err(CliError::Refused(String::from(
            "internal: the staged log came back without its key; nothing was changed",
        ))),
    }
}

/// Rotate the at-rest key, re-sealing the log under a fresh one.
///
/// # Why this is a command rather than a runbook
///
/// Without it, rotating a key means decrypting the log by hand, generating a
/// key, re-encrypting, and swapping the files -- four steps, each destructive,
/// with the plaintext of the entire log sitting on disk in the middle. An
/// operator who suspects their key has leaked is exactly the operator who should
/// not be improvising that at 2am. The whole point of the sequence below is that
/// **no step leaves the store unreadable**, and the plaintext never lands.
///
/// # The order of operations, and what a crash at each point leaves behind
///
/// 1. The new key is generated *in memory*. Nothing on disk has changed.
/// 2. The log is re-sealed into `<log>.rekeying`. A crash here leaves a file
///    nobody holds the key for -- garbage, and removed by the next run.
/// 3. That file is reopened and required to re-derive the original entries and
///    the original root. This is the proof, and it happens before anything is
///    moved.
/// 4. `<key>` is renamed to `<key>.previous`, and the new key written in its
///    place. A failure here puts the old key back.
/// 5. `<log>.rekeying` is renamed over `<log>`. A failure here puts the old key
///    back too, so the untouched log still opens.
///
/// # The old key is kept; the old ciphertext is not
///
/// The reverse of what [`cmd_encrypt`] does, and for a reason. `store encrypt`
/// keeps the plaintext original because it is the only copy of the data. Here
/// the new file has already been proved to hold the same entries under the same
/// root, so keeping the old ciphertext would only mean leaving a copy readable
/// by the key the operator is trying to retire.
///
/// The *key* is kept, at `<key>.previous`, because copies of this store made
/// before now -- a `proofwork sync` mirror, a backup, an external drive -- are
/// still sealed under it, and this command cannot see them.
fn cmd_rekey(
    out: &mut dyn Write,
    options: &Options,
    new_passphrase_file: Option<&str>,
) -> Result<i32, CliError> {
    let key_path = options.key_path();
    if !key_path.exists() {
        return Err(CliError::AtRest(AtRestError::NoKeyFile { path: key_path }));
    }
    let previous_path = sibling(&key_path, ".previous");
    if previous_path.exists() {
        // Never clobbered: an earlier rotation put it there, and something
        // somewhere may still be sealed under it.
        return Err(CliError::Refused(format!(
            "{} already exists -- an earlier rotation left it there. Move it \
             somewhere safe (copies of this store made before that rotation \
             still need it) and run this again",
            previous_path.display()
        )));
    }

    let sealed_on_disk = first_line_is_sealed(&options.log)?;
    if sealed_on_disk == Some(false) {
        return Err(CliError::Refused(format!(
            "{} is in plaintext, so no at-rest key is protecting it and there is \
             nothing to rotate; run `proofwork store encrypt` first",
            options.log
        )));
    }
    let has_log = sealed_on_disk == Some(true);

    let old_passphrase = options.passphrase()?;
    let old =
        Cipher::read_key_file(&key_path, old_passphrase.as_deref()).map_err(CliError::AtRest)?;
    let old_was_wrapped = Cipher::key_file_is_wrapped(&key_path).unwrap_or(false);
    let new_passphrase = match new_passphrase_file {
        Some(path) => Some(read_passphrase_file(path)?),
        None => None,
    };

    let mut new = Cipher::generate(&mut rand_core::OsRng);
    let staged = sibling(Path::new(&options.log), ".rekeying");
    let mut resealed = 0usize;
    let mut root = String::new();

    if has_log {
        let current = Ledger::open_with(&options.log, Codec::Sealed(Box::new(old)))
            .map_err(CliError::Ledger)?;
        let problems = current.verify_chain();
        if !problems.is_empty() {
            // Rotating a broken log would re-seal the breakage under a key
            // whose predecessor is about to be set aside, which turns a
            // diagnosable problem into an archaeological one.
            for problem in &problems {
                say(out, format!("  {problem}"));
            }
            return Err(CliError::Refused(String::from(
                "the log does not verify under the current key; fix that before rotating",
            )));
        }

        let _ = fs::remove_file(&staged);
        let written = {
            let mut next = Ledger::open_with(&staged, Codec::Sealed(Box::new(new)))
                .map_err(CliError::Ledger)?;
            for entry in current.entries() {
                next.append(&entry.kind, entry.payload.clone(), &entry.ts)
                    .map_err(CliError::Ledger)?;
            }
            next.into_codec()
        };

        // Read it back, with the handle that wrote it already dropped, and
        // demand the same entries under the same root. A rotation that cannot
        // be proved reversible before the swap is one nobody should run.
        let check = Ledger::open_with(&staged, written).map_err(CliError::Ledger)?;
        if check.entries() != current.entries() || check.root() != current.root() {
            let _ = fs::remove_file(&staged);
            return Err(CliError::Refused(String::from(
                "the re-sealed copy does not re-derive the original; nothing was changed",
            )));
        }
        resealed = check.len();
        root = check.root().unwrap_or_default();
        new = reclaim_cipher(check.into_codec())?;
    }

    // From here the disk changes. Every failure below puts back what it moved.
    fs::rename(&key_path, &previous_path).map_err(|source| CliError::Io {
        context: format!("moving {} aside", key_path.display()),
        source,
    })?;
    if let Err(error) =
        new.write_key_file(&key_path, new_passphrase.as_deref(), &mut rand_core::OsRng)
    {
        let _ = fs::rename(&previous_path, &key_path);
        let _ = fs::remove_file(&staged);
        return Err(CliError::AtRest(error));
    }
    if has_log {
        if let Err(source) = fs::rename(&staged, &options.log) {
            let _ = fs::remove_file(&key_path);
            let _ = fs::rename(&previous_path, &key_path);
            return Err(CliError::Io {
                context: format!("installing {}", options.log),
                source,
            });
        }
    }

    say(
        out,
        format!("rotated the at-rest key at {}", key_path.display()),
    );
    if has_log {
        say(
            out,
            format!("re-sealed {resealed} entries; root unchanged at {root}"),
        );
    } else {
        say(out, "the log is empty, so only the key changed");
    }
    if new_passphrase.is_some() {
        say(out, "  the new key is wrapped with a passphrase (argon2id)");
    } else if old_was_wrapped {
        say(
            out,
            "  the new key is NOT passphrase-wrapped, and the old one was;",
        );
        say(
            out,
            "  pass --new-passphrase-file PATH if that was not deliberate",
        );
    }
    if !proofwork::store::atrest::private_permissions_supported() {
        say(
            out,
            "  warning: this platform cannot restrict the key to its owner",
        );
    }
    say(out, "");
    say(
        out,
        format!(
            "The OLD key is still on disk at {}",
            previous_path.display()
        ),
    );
    say(
        out,
        "Nothing in this store needs it now. Copies made before now do: a mirror",
    );
    say(
        out,
        "from `proofwork sync`, a backup, an external drive. Re-seal or destroy",
    );
    say(
        out,
        "those, then delete it -- while the old key and old ciphertext both exist",
    );
    say(out, "somewhere, this rotation has bought nothing.");

    let plaintext_backup = format!("{}{}", options.log, mirror::PLAINTEXT_BACKUP_SUFFIX);
    if Path::new(&plaintext_backup).exists() {
        say(out, "");
        say(
            out,
            format!("WARNING: {plaintext_backup} is a PLAINTEXT copy left by"),
        );
        say(
            out,
            "`store encrypt`. Rotating a key does nothing for a copy that was",
        );
        say(out, "never sealed by one.");
    }
    Ok(0)
}

fn cmd_sync(
    out: &mut dyn Write,
    options: &Options,
    destination: &str,
    mirror_options: mirror::Options,
) -> Result<i32, CliError> {
    let store = options.store();
    let report =
        mirror::mirror(&store, Path::new(destination), mirror_options).map_err(CliError::Store)?;
    if mirror_options.dry_run {
        say(out, "dry run -- nothing was written");
    }
    for path in &report.copied {
        say(out, format!("copied {}", path.display()));
    }
    for path in &report.pruned {
        say(out, format!("pruned {}", path.display()));
    }
    for line in report.summary().lines() {
        say(out, line);
    }
    Ok(0)
}

fn cmd_log(out: &mut dyn Write, options: &Options) -> Result<i32, CliError> {
    let node = open_node(options)?;
    for entry in ledger_of(&node).entries() {
        say(
            out,
            format!(
                "{:>4}  {:<11} {}  {}",
                entry.seq,
                entry.kind,
                short(&entry.hash),
                summarize(&entry.kind, &entry.payload)
            ),
        );
    }
    Ok(0)
}

/// Inspect and maintain the content-addressed store of pinned verifier code.
///
/// Exit code 0 throughout, including for `need` with unmet pins. Missing code is
/// `Unavailable` — this node cannot check something — and reporting it as a
/// failure would make a script treat "I have not fetched the checker yet" as "the
/// log is wrong". `audit` is where a log that does not re-derive is an error.
fn cmd_blob(out: &mut dyn Write, options: &Options, action: &BlobAction) -> Result<i32, CliError> {
    let node = open_node(options)?;
    let store = node.registry().blobs();
    match action {
        BlobAction::List => {
            let held = store.addresses();
            say(
                out,
                format!("{} blob(s) in {}", held.len(), store.dir().display()),
            );
            let pinned = node.pinned_code();
            for address in held {
                // Whether anything in *this* log still wants it, which is what
                // `gc` would act on.
                let mark = if pinned.contains(&address) {
                    "pinned"
                } else {
                    "unreferenced"
                };
                say(out, format!("  {} {mark}", short_address(&address)));
            }
        }
        BlobAction::Need => {
            let needs = node.missing_code();
            if needs.is_empty() {
                say(
                    out,
                    "every pinned verifier in this log is available locally",
                );
            } else {
                say(
                    out,
                    format!(
                        "{} pin(s) unavailable; verdicts against them will be \
                             'unavailable' until a peer serves them",
                        needs.len()
                    ),
                );
                for address in &needs {
                    say(out, format!("  {}", short_address(address)));
                }
            }
        }
        BlobAction::Publish => {
            let published = node.publish_local_code();
            say(
                out,
                format!(
                    "{published} pinned blob(s) servable from {}",
                    store.dir().display()
                ),
            );
        }
        BlobAction::Collect => {
            let dropped = store.retain(&node.pinned_code());
            say(out, format!("dropped {dropped} unreferenced blob(s)"));
        }
        BlobAction::Serve { identity, listen } => {
            return cmd_blob_serve(out, &node, store, identity, listen)
        }
        BlobAction::Fetch {
            identity,
            peers,
            seconds,
        } => return cmd_blob_fetch(out, &node, store, identity, peers, *seconds),
    }
    Ok(0)
}

/// Seed this node's blobs to strangers.
///
/// `blob need` has always told an operator that a missing pin stays missing
/// "until a peer serves them", and nothing in this binary could *be* that peer:
/// `swarm::tcp` is a complete, encrypted, end-to-end tested transfer that no
/// shipped command called. A subsystem with no entry point is not a feature.
///
/// The endpoint is printed rather than written anywhere, in the shape
/// `proofwork-p2p` already reads for `--bootstrap`, because a fetcher needs the
/// 255 KB McEliece key as well as the address and there is nowhere in an
/// append-only log for a quarter-megabyte hint that changes.
fn cmd_blob_serve(
    out: &mut dyn Write,
    node: &Node,
    store: &proofwork::blobs::BlobStore,
    identity_path: &str,
    listen: &str,
) -> Result<i32, CliError> {
    let identity = std::sync::Arc::new(load_transport_identity(identity_path)?);
    let published = node.publish_local_code();
    let listener = proofwork::swarm::tcp::serve(
        listen,
        std::sync::Arc::clone(&identity),
        store.clone(),
        proofwork::swarm::Limits::default(),
    )
    .map_err(|error| CliError::Usage(format!("blob serve: cannot listen on {listen}: {error}")))?;

    say(out, format!("seeding on {}", listener.addr()));
    say(
        out,
        format!(
            "  {} blob(s) servable ({published} pinned file(s) published from the bundle)",
            store.len()
        ),
    );
    say(out, "");
    say(
        out,
        "A fetcher needs this node's transport key as well as its",
    );
    say(out, "address. Hand them a file shaped like this:");
    say(out, "");
    say(
        out,
        Value::object([
            ("addr", Value::string(listener.addr().to_string())),
            (
                "public",
                Value::string(hex_of(identity.public_key().as_slice())),
            ),
        ])
        .canonical_string(),
    );
    say(out, "");
    say(out, "Ctrl-C to stop.");
    // Parked deliberately rather than looped: the listener owns its threads, and
    // there is nothing for this one to do but hold it alive.
    loop {
        std::thread::park();
    }
}

/// Fetch every pin this log names and this node lacks.
fn cmd_blob_fetch(
    out: &mut dyn Write,
    node: &Node,
    store: &proofwork::blobs::BlobStore,
    identity_path: &str,
    peers: &[String],
    seconds: u64,
) -> Result<i32, CliError> {
    let missing = node.missing_code();
    if missing.is_empty() {
        say(
            out,
            "every pinned verifier in this log is available locally; nothing to fetch",
        );
        return Ok(0);
    }
    let identity = std::sync::Arc::new(load_transport_identity(identity_path)?);
    let mut endpoints = Vec::with_capacity(peers.len());
    for path in peers {
        endpoints.push(load_endpoint(path)?);
    }
    if endpoints.is_empty() {
        return Err(CliError::Usage(String::from(
            "blob fetch: no peers. Pass --peer <file> with the {addr, public} a \
             seeder printed; an address alone cannot complete an authenticated dial.",
        )));
    }

    say(
        out,
        format!(
            "fetching {} missing pin(s) from {} peer(s)",
            missing.len(),
            endpoints.len()
        ),
    );
    let deadline = std::time::Duration::from_secs(seconds);
    let mut got = 0usize;
    let mut failed: Vec<String> = Vec::new();
    for address in &missing {
        match proofwork::swarm::tcp::fetch(
            address,
            &endpoints,
            std::sync::Arc::clone(&identity),
            store,
            proofwork::swarm::Limits::default(),
            deadline,
        ) {
            Ok(bytes) => {
                // Written through the store, which re-hashes: a seed that
                // served the wrong bytes fails here rather than becoming a
                // pinned blob whose address does not match its content.
                match store.put(address, &bytes) {
                    Ok(_) => {
                        got += 1;
                        say(out, format!("  ok   {}", short_address(address)));
                    }
                    Err(error) => {
                        failed.push(address.clone());
                        say(out, format!("  bad  {}: {error}", short_address(address)));
                    }
                }
            }
            Err(error) => {
                failed.push(address.clone());
                say(out, format!("  miss {}: {error}", short_address(address)));
            }
        }
    }
    say(
        out,
        format!("{got} fetched, {} still missing", failed.len()),
    );
    // Exit 1 on an incomplete fetch, so a script that runs this before `audit`
    // stops rather than going on to report `unavailable` verdicts as though the
    // pins had never been wanted.
    Ok(i32::from(!failed.is_empty()))
}

/// Load a transport identity, creating one if the file does not exist.
///
/// Same `{public, secret}` shape `proofwork-p2p` reads, so one file serves
/// both. Generating on absence costs ~243 ms of Classic McEliece keygen and is
/// what makes `blob serve` a single command rather than a setup ritual.
fn load_transport_identity(
    path: &str,
) -> Result<proofwork::p2p::handshake::PeerIdentity, CliError> {
    use proofwork::p2p::handshake::PeerIdentity;
    let file = std::path::Path::new(path);
    if !file.exists() {
        let identity = PeerIdentity::generate();
        let body = Value::object([
            ("public", Value::string(hex_of(identity.public_key()))),
            ("secret", Value::string(hex_of(identity.secret_key()))),
        ]);
        // The secret is in here, so it gets the same 0600 treatment as a
        // submitter identity rather than whatever the umask happens to be.
        write_private_file(file, &body.canonical_string())
            .map_err(|error| CliError::Usage(format!("{path}: {error}")))?;
        return Ok(identity);
    }
    let text =
        std::fs::read_to_string(file).map_err(|e| CliError::Usage(format!("{path}: {e}")))?;
    let value = Value::from_json(&text).map_err(|e| CliError::Usage(format!("{path}: {e}")))?;
    let field = |name: &str| -> Result<Vec<u8>, CliError> {
        let hex = value
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::Usage(format!("{path}: {name} missing")))?;
        decode_hex(hex).map_err(|e| CliError::Usage(format!("{path}: {name}: {e}")))
    };
    PeerIdentity::from_bytes(&field("public")?, &field("secret")?)
        .map_err(|error| CliError::Usage(format!("{path}: {error}")))
}

/// Load one `{addr, public}` endpoint file.
fn load_endpoint(path: &str) -> Result<proofwork::p2p::discovery::Endpoint, CliError> {
    let text =
        std::fs::read_to_string(path).map_err(|e| CliError::Usage(format!("{path}: {e}")))?;
    let value = Value::from_json(&text).map_err(|e| CliError::Usage(format!("{path}: {e}")))?;
    let addr = value
        .get("addr")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Usage(format!("{path}: addr missing")))?;
    // A hostname is accepted as well as a literal -- see
    // `p2p::discovery::dialable` for why a name is safe to take on trust.
    let addr = proofwork::p2p::discovery::dialable(addr).ok_or_else(|| {
        CliError::Usage(format!(
            "{path}: addr {addr:?} is neither an address nor a name that resolves"
        ))
    })?;
    let hex = value
        .get("public")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::Usage(format!("{path}: public missing")))?;
    let bytes = decode_hex(hex).map_err(|e| CliError::Usage(format!("{path}: public: {e}")))?;
    let peer = proofwork::p2p::handshake::PeerPublic::from_bytes(&bytes)
        .map_err(|error| CliError::Usage(format!("{path}: public: {error}")))?;
    Ok(proofwork::p2p::discovery::Endpoint::new(addr, peer))
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A content address abbreviated the way [`short`] abbreviates a record hash, so
/// the two read alike in a terminal. Full addresses are 64 characters and the
/// prefix identifies a blob among the handful a node holds.
fn short_address(address: &str) -> String {
    match address.get(..12) {
        Some(head) => format!("{head}…"),
        None => address.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Reading the log
// ---------------------------------------------------------------------------

/// Every claim in the log, keyed by claim id -- the map attribution walks.
///
/// A payload that will not decode is an error rather than a skipped row.
/// Dropping a claim silently would change who gets paid, and a payout table that
/// is quietly wrong is worse than one that refuses to print.
fn claim_index(ledger: &Ledger) -> Result<BTreeMap<String, Claim>, CliError> {
    let mut claims: BTreeMap<String, Claim> = BTreeMap::new();
    for entry in ledger.entries_of_kind("claim") {
        let claim = Claim::from_value(&entry.payload).map_err(|error| CliError::LogPayload {
            seq: entry.seq,
            reason: error.to_string(),
        })?;
        claims.insert(claim.id(), claim);
    }
    Ok(claims)
}

/// `(claim_id, reward)` for every settlement, in log order.
///
/// A reward that is negative or larger than `u64` is refused rather than
/// truncated: Python wrote this log with unbounded integers, and a settlement
/// this build cannot represent must be reported, not rounded into one it can.
fn settlements_of(ledger: &Ledger) -> Result<Vec<(String, u64)>, CliError> {
    let mut out: Vec<(String, u64)> = Vec::new();
    for entry in ledger.entries_of_kind("settlement") {
        let bad = |reason: &str| CliError::LogPayload {
            seq: entry.seq,
            reason: reason.to_string(),
        };
        let claim_id = entry
            .payload
            .get("claim_id")
            .and_then(Value::as_str)
            .ok_or_else(|| bad("settlement has no claim_id"))?;
        let reward = entry
            .payload
            .get("reward")
            .and_then(Value::as_u64)
            .ok_or_else(|| bad("settlement reward is not a representable unit count"))?;
        out.push((claim_id.to_string(), reward));
    }
    Ok(out)
}

/// One-line summary of a log entry, by kind.
///
/// Total on purpose: an unreadable payload yields a blank summary rather than an
/// error. `log` is the command you reach for *because* something is wrong with
/// the log, so it must never be the command that refuses to run.
fn summarize(kind: &str, payload: &Value) -> String {
    let text = |key: &str| payload.get(key).and_then(Value::as_str).unwrap_or("");
    match kind {
        "objective" => truncate_chars(text("statement"), STATEMENT_WIDTH),
        "claim" | "commitment" => format!("by {}", text("submitter")),
        // Identity first and truncated, because it is the part that is a name
        // rather than a hint: two records for one identity are the same peer
        // moving, and reading the log has to make that obvious at a glance.
        "peer" => {
            let seq = payload
                .get("seq")
                .and_then(Value::as_i128)
                .map(|value| value.to_string())
                .unwrap_or_else(|| String::from("?"));
            format!(
                "{} at {} (seq {seq})",
                truncate_chars(text("identity"), 8),
                text("addr")
            )
        }
        "verdict" => {
            let verdict = payload.get("verdict");
            let status = verdict
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("?");
            let detail = verdict
                .and_then(|value| value.get("detail"))
                .and_then(Value::as_str)
                .unwrap_or("");
            format!("{status}: {}", truncate_chars(detail, DETAIL_WIDTH))
        }
        "settlement" => {
            let reward = payload
                .get("reward")
                .and_then(Value::as_i128)
                .map(|units| units.to_string())
                .unwrap_or_else(|| String::from("?"));
            format!("{} <- {reward}", text("submitter"))
        }
        "batch" => {
            let epoch = payload
                .get("epoch")
                .and_then(Value::as_i128)
                .map(|epoch| epoch.to_string())
                .unwrap_or_else(|| String::from("?"));
            let claims = match payload.get("claims") {
                Some(Value::Array(items)) => items.len(),
                _ => 0,
            };
            format!("epoch {epoch}: {claims} claim(s)")
        }
        _ => String::new(),
    }
}

/// First `limit` **characters**, mirroring Python's `str` slicing.
///
/// Byte slicing would panic on a multi-byte boundary, which a statement in any
/// language but English can supply.
fn truncate_chars(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

// ---------------------------------------------------------------------------
// Attribution table
// ---------------------------------------------------------------------------

/// Render the payout table as lines.
///
/// Split out from the command so the arithmetic and the column widths can be
/// tested without a log on disk.
fn render_attribution(
    params: &FlowParams,
    payouts: &BTreeMap<String, u64>,
) -> Result<Vec<String>, CliError> {
    let mut lines: Vec<String> = Vec::new();
    if payouts.is_empty() {
        lines.push(String::from("no settlements yet"));
        return Ok(lines);
    }

    let total = total_units(payouts)?;
    // Character count, not byte length: a submitter name with an accent in it
    // must not shift the column. Rust pads `{:<width$}` by characters too, so
    // the two agree.
    let width = payouts
        .keys()
        .map(|who| who.chars().count())
        .max()
        .unwrap_or(0);

    lines.push(format!(
        "delta {}/{}  max_depth {}",
        params.delta_num(),
        params.delta_den(),
        params.max_depth()
    ));
    lines.push(String::new());

    // Largest payout first. Ties break on name, which the reference
    // implementation leaves to dict insertion order -- a detail no second
    // implementation could reproduce. Sorting the tie makes the table
    // deterministic across implementations, which is the property that matters
    // for output anyone is meant to re-derive.
    let mut rows: Vec<(&String, u64)> = payouts.iter().map(|(who, units)| (who, *units)).collect();
    rows.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));

    for (who, units) in rows {
        lines.push(format!(
            "  {:<width$}  {:>10}  {:>5.1}%",
            who,
            units,
            percent(units, total),
            width = width
        ));
    }
    lines.push(format!(
        "  {:<width$}  {}",
        "",
        "-".repeat(10),
        width = width
    ));
    lines.push(format!(
        "  {:<width$}  {:>10}",
        "total",
        total,
        width = width
    ));
    Ok(lines)
}

/// Sum the payouts in `u128`.
///
/// This is the overflow the Python port never had to think about. Each payout
/// fits in `u64` because the ledger's unit of account does, but their *sum* is
/// bounded by nothing: a long-lived log with large pools reaches `u64::MAX`
/// honestly. Widening to `u128` makes the total exact, and the addition is still
/// checked, because a wrapped total would understate what the network paid --
/// which is the one number an auditor is here to read.
fn total_units(payouts: &BTreeMap<String, u64>) -> Result<u128, CliError> {
    let mut total: u128 = 0;
    for units in payouts.values() {
        total = total
            .checked_add(u128::from(*units))
            .ok_or_else(|| CliError::Overflow(String::from("attribution total")))?;
    }
    Ok(total)
}

/// Share of the total, as a percentage for display only.
///
/// The float appears exactly here, on the way to a terminal, and never enters a
/// record: [`Value`] has no float variant, so it could not if it tried. A zero
/// total pays nobody, and reporting `0.0` beats the `NaN` that dividing by it
/// would otherwise print.
fn percent(units: u64, total: u128) -> f64 {
    if total == 0 {
        return 0.0;
    }
    100.0 * (units as f64) / (total as f64)
}

// ---------------------------------------------------------------------------
// Timestamps
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Nonces
// ---------------------------------------------------------------------------

/// 16 bytes of operating-system entropy, hex encoded.
///
/// The equivalent of `secrets.token_hex(16)`. The nonce is what stops a
/// guessable artifact -- `{"n": 27}` -- from being brute-forced out of a
/// published commitment before it is revealed, so a *predictable* nonce silently
/// removes the hiding property while leaving every command it appears in looking
/// like it worked.
///
/// That is why there is no fallback. If the kernel entropy source cannot be
/// read, this refuses and tells the user to pass `--nonce`, rather than deriving
/// something clock-shaped that would be guessable by anyone who knows roughly
/// when the commitment was made.
fn random_nonce() -> Result<String, CliError> {
    const SOURCE: &str = "/dev/urandom";
    let complain = |error: io::Error| {
        CliError::Entropy(format!(
            "no entropy for a nonce ({SOURCE}: {error}); pass --nonce explicitly"
        ))
    };
    let mut source = File::open(SOURCE).map_err(complain)?;
    let mut bytes = [0u8; NONCE_BYTES];
    source.read_exact(&mut bytes).map_err(complain)?;
    Ok(hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn run(argv: Vec<String>, out: &mut dyn Write) -> Result<i32, CliError> {
    let invocation = parse(argv)?;
    let options = &invocation.options;
    match &invocation.command {
        Command::Help => {
            print_help(out);
            Ok(0)
        }
        Command::Post { objective } => cmd_post(out, options, objective),
        Command::Commit {
            objective_id,
            submitter,
            artifact,
            nonce,
            identity,
        } => cmd_commit(
            out,
            options,
            objective_id,
            Submitter {
                declared: submitter,
                identity: identity.as_deref(),
            },
            artifact,
            nonce.as_deref(),
        ),
        Command::Reveal {
            objective_id,
            submitter,
            artifact,
            nonce,
            cites,
            identity,
        } => cmd_reveal(
            out,
            options,
            objective_id,
            Submitter {
                declared: submitter,
                identity: identity.as_deref(),
            },
            artifact,
            nonce,
            cites,
        ),
        Command::Settle => cmd_settle(out, options),
        Command::Checkpoint {
            root_key,
            out: path,
        } => cmd_checkpoint(out, options, root_key, path.as_deref()),
        Command::Drain { queue, dry_run } => cmd_drain(out, options, queue, *dry_run),
        Command::Audit { rerun } => cmd_audit(out, options, *rerun),
        Command::Verify {
            checkpoint,
            root_key,
            audit,
            rerun,
        } => cmd_verify(
            out,
            options,
            checkpoint,
            root_key.as_deref(),
            *audit,
            *rerun,
        ),
        Command::Prove {
            seq,
            height,
            out: path,
        } => cmd_prove(out, options, *seq, *height, path.as_deref()),
        Command::Check {
            proof,
            root,
            checkpoint,
            root_key,
        } => cmd_check(
            out,
            proof,
            root.as_deref(),
            checkpoint.as_deref(),
            root_key.as_deref(),
        ),
        Command::Availability { action } => cmd_availability(out, options, action),
        Command::Attribute { params } => cmd_attribute(out, options, params),
        Command::Blob { action } => cmd_blob(out, options, action),
        Command::Try {
            objective,
            submitter,
            artifact,
            nonce,
            identity,
            cites,
            settle,
        } => cmd_try(
            out,
            options,
            Round {
                objective,
                who: Submitter {
                    declared: submitter,
                    identity: identity.as_deref(),
                },
                artifact_path: artifact,
                nonce: nonce.as_deref(),
                cites,
                settle: *settle,
            },
        ),
        Command::Scaffold { request, force } => cmd_scaffold(out, options, request, *force),
        Command::Incentives {
            params,
            robustness,
            sweep,
            out: destination,
            format,
        } => {
            if sweep.is_empty() {
                cmd_incentives(out, params, *robustness)
            } else {
                cmd_incentives_sweep(
                    out,
                    params,
                    sweep,
                    *robustness,
                    destination.as_deref(),
                    *format,
                )
            }
        }
        Command::Canon { input } => cmd_canon(out, input),
        Command::Decode { kind, record } => cmd_decode(out, kind, record),
        Command::Identity { out: path } => cmd_identity(out, path),
        Command::Peer {
            identity,
            transport,
            addr,
            seq,
        } => cmd_peer(out, options, identity, transport, addr, *seq),
        Command::Keygen { wrap } => cmd_keygen(out, options, *wrap),
        Command::Store { action } => cmd_store(out, options, action),
        Command::Sync {
            destination,
            options: mirror_options,
        } => cmd_sync(out, options, destination, *mirror_options),
        Command::Log => cmd_log(out, options),
    }
}

/// Collect arguments without the panic [`std::env::args`] raises on an argument
/// that is not valid UTF-8.
fn arguments() -> Result<Vec<String>, CliError> {
    let mut argv: Vec<String> = Vec::new();
    for (position, raw) in env::args_os().enumerate() {
        if position == 0 {
            continue;
        }
        match raw.into_string() {
            Ok(argument) => argv.push(argument),
            Err(_) => return Err(CliError::NotUnicode(position)),
        }
    }
    Ok(argv)
}

fn main() {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    let code = match arguments().and_then(|argv| run(argv, &mut out)) {
        Ok(code) => code,
        Err(error) => {
            let _ = writeln!(io::stderr(), "{}", error.report());
            error.code()
        }
    };

    // `process::exit` runs no destructors, so the buffered output is flushed
    // here rather than left to one.
    let _ = out.flush();
    process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    fn payouts(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs
            .iter()
            .map(|(who, units)| ((*who).to_string(), *units))
            .collect()
    }

    /// A scratch directory no other test will pick.
    ///
    /// The previous seed was `Instant::now().elapsed()`, which measures the gap
    /// between those two calls: a handful of nanoseconds, and **four distinct
    /// values in two hundred** on this machine. So directories that were meant
    /// to be unique collided -- across tests sharing a tag, and across runs,
    /// because the value barely depends on when it is taken.
    ///
    /// That is worse than a tidiness problem. A test that finds another test's
    /// files fails for a reason that has nothing to do with what it asserts,
    /// and a suite that fails intermittently is one whose failures stop being
    /// read. `tests/storage.rs` already had the right pattern; this is it.
    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "proofwork-cli-{tag}-{}-{nanos}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("scratch dir");
        path
    }

    /// A scratch bundle: an objective whose pinned checker really is on disk,
    /// plus `Options` pointing at both. The pin is computed from the bytes
    /// written, so the fixture cannot drift out of agreement with itself.
    fn bundle_with_objective() -> (std::path::PathBuf, Options, Value) {
        use proofwork::canonical::digest_bytes;
        let dir = scratch_dir("bundle");
        let source = b"def check(artifact):\n    return artifact.get('n') == 42\n";
        std::fs::write(dir.join("c.py"), source).expect("write checker");
        let pin = digest_bytes(source)
            .strip_prefix("sha256:")
            .expect("prefixed")
            .to_string();
        let objective = Value::object([
            ("goal", Value::string("GOAL-x")),
            ("statement", Value::string("find it")),
            (
                "verifier",
                Value::object([
                    ("kind", Value::string("certificate")),
                    ("checker", Value::string("c.py")),
                    ("checker_sha256", Value::string(pin)),
                    ("entrypoint", Value::string("check")),
                ]),
            ),
            ("reward", Value::Int(1000)),
            ("funder", Value::string("treasury")),
            ("created_at", Value::string("2026-07-28T00:00:00+00:00")),
        ]);
        let options = Options {
            log: dir.join("log.jsonl").display().to_string(),
            root: dir.display().to_string(),
            data: None,
            key_file: None,
            passphrase_file: None,
            max_size: None,
        };
        (dir, options, objective)
    }

    fn post_to_string(options: &Options, objective: &Value, dir: &std::path::Path) -> String {
        let path = dir.join("objective.json");
        std::fs::write(&path, objective.canonical_string()).expect("write objective");
        let mut out: Vec<u8> = Vec::new();
        cmd_post(&mut out, options, &path.display().to_string()).expect("post succeeds");
        String::from_utf8(out).expect("utf-8")
    }

    #[test]
    fn post_warns_when_a_pin_does_not_resolve_but_still_accepts_it() {
        // A wrong pin cannot be refused: posting an objective whose checker a
        // peer will serve is how content-addressed distribution works, and
        // record sync admits objectives from nodes that never had the bundle.
        // But silence is worse than either -- the id covers the pin, so a typo
        // does not fail, it mints a *different* objective whose every claim is
        // InvalidSpec forever. The operator is the only one who can tell the
        // two apart, so they have to be told.
        let (dir, options, objective) = bundle_with_objective();

        // Resolvable: no warning, or the noise makes the real one invisible.
        let clean = post_to_string(&options, &objective, &dir);
        assert!(clean.contains("objective sha256:"), "{clean}");
        assert!(
            !clean.contains("warning"),
            "a resolvable pin warned: {clean}"
        );

        // Same objective, one hex digit changed.
        let mut broken = objective.clone();
        if let Value::Object(map) = &mut broken {
            if let Some(Value::Object(verifier)) = map.get_mut("verifier") {
                verifier.insert("checker_sha256".to_string(), Value::string("00".repeat(32)));
            }
        }
        let warned = post_to_string(&options, &broken, &dir);
        assert!(
            warned.contains("warning"),
            "a dead pin did not warn: {warned}"
        );
        assert!(warned.contains("can never settle"), "{warned}");
        // And it is a *different* objective, which is the whole hazard.
        let id_of = |text: &str| {
            text.lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .expect("id on the first line")
                .to_string()
        };
        assert_ne!(id_of(&clean), id_of(&warned));

        std::fs::remove_dir_all(&dir).ok();
    }

    // -- key rotation ------------------------------------------------------

    /// A scratch store with a sealed log holding one objective, plus the
    /// `Options` pointing at it. The key deliberately lives *outside* the data
    /// directory, which is the layout the docs ask for.
    fn sealed_store(tag: &str) -> (std::path::PathBuf, Options) {
        let dir = scratch_dir(tag);
        std::fs::create_dir_all(dir.join("data")).expect("scratch dir");
        let options = Options {
            log: dir.join("data/log.jsonl").display().to_string(),
            root: dir.display().to_string(),
            data: Some(dir.join("data").display().to_string()),
            key_file: Some(dir.join("key").display().to_string()),
            passphrase_file: None,
            max_size: None,
        };
        let mut sink: Vec<u8> = Vec::new();
        cmd_keygen(&mut sink, &options, false).expect("keygen");
        (dir, options)
    }

    /// Append one entry to `options`'s log, through whatever codec applies.
    fn append_entry(options: &Options, i: i128) {
        let codec = resolve_codec(options).expect("codec");
        let mut ledger = Ledger::open_with(&options.log, codec).expect("opens");
        ledger
            .append(
                "note",
                Value::object([("i", Value::Int(i))]),
                "2026-07-28T00:00:00+00:00",
            )
            .expect("appends");
    }

    fn root_of(options: &Options) -> Option<String> {
        let codec = resolve_codec(options).expect("codec");
        Ledger::open_with(&options.log, codec)
            .expect("opens")
            .root()
    }

    #[test]
    fn rekey_reseals_the_log_under_a_new_key_and_changes_no_identity() {
        // The whole promise: after a rotation the same entries are there under
        // the same root, the bytes on disk are different, and the key that used
        // to open them no longer does.
        let (dir, options) = sealed_store("reseal");
        append_entry(&options, 1);
        append_entry(&options, 2);

        let before_root = root_of(&options).expect("a root");
        let before_bytes = std::fs::read(&options.log).expect("reads");
        let before_key = std::fs::read(options.key_path()).expect("reads");

        let mut out: Vec<u8> = Vec::new();
        assert_eq!(cmd_rekey(&mut out, &options, None).expect("rotates"), 0);
        let said = String::from_utf8(out).expect("utf-8");

        assert_eq!(root_of(&options), Some(before_root.clone()));
        assert!(
            said.contains(&before_root),
            "the unchanged root is the thing to report: {said}"
        );
        let after_bytes = std::fs::read(&options.log).expect("reads");
        assert_ne!(
            before_bytes, after_bytes,
            "the log was not actually re-sealed"
        );
        let after_key = std::fs::read(options.key_path()).expect("reads");
        assert_ne!(before_key, after_key, "the key did not change");

        // The old key is kept, and it opens nothing here any more.
        let previous = sibling(&options.key_path(), ".previous");
        assert_eq!(std::fs::read(&previous).expect("reads"), before_key);
        let stale = Cipher::read_key_file(&previous, None).expect("still a key file");
        assert!(
            Ledger::open_with(&options.log, Codec::Sealed(Box::new(stale))).is_err(),
            "the retired key still opens the log"
        );

        // And no staging file survives a success.
        assert!(!sibling(Path::new(&options.log), ".rekeying").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rekey_can_add_a_passphrase_and_take_one_away() {
        // Rotating *because a secret leaked* means the new passphrase cannot be
        // the old one, so the two are separate flags. Both directions have to
        // work, and dropping a passphrase has to be said out loud.
        let (dir, options) = sealed_store("passphrase");
        append_entry(&options, 7);
        let phrase = dir.join("phrase");
        std::fs::write(&phrase, "correct horse\n").expect("writes");

        let mut out: Vec<u8> = Vec::new();
        cmd_rekey(&mut out, &options, Some(&phrase.display().to_string())).expect("wraps");
        assert!(Cipher::key_file_is_wrapped(&options.key_path()).expect("reads"));
        assert!(String::from_utf8(out).expect("utf-8").contains("argon2id"));

        // The log now needs the passphrase, and opens with it.
        assert!(Cipher::read_key_file(&options.key_path(), None).is_err());
        let wrapped = Options {
            passphrase_file: Some(phrase.display().to_string()),
            ..options.clone()
        };
        assert!(root_of(&wrapped).is_some());

        // Back the other way, which is a downgrade and says so.
        std::fs::remove_file(sibling(&options.key_path(), ".previous")).expect("clears");
        let mut out: Vec<u8> = Vec::new();
        cmd_rekey(&mut out, &wrapped, None).expect("unwraps");
        let said = String::from_utf8(out).expect("utf-8");
        assert!(said.contains("NOT passphrase-wrapped"), "{said}");
        assert!(!Cipher::key_file_is_wrapped(&options.key_path()).expect("reads"));
        assert!(root_of(&options).is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rekey_never_clobbers_a_key_an_older_copy_might_still_need() {
        // `<key>.previous` is not scratch space. Something the operator made
        // before the last rotation -- a mirror, a backup -- may be the only
        // thing that key still opens, and this command cannot see it.
        let (dir, options) = sealed_store("previous");
        append_entry(&options, 1);
        let mut sink: Vec<u8> = Vec::new();
        cmd_rekey(&mut sink, &options, None).expect("first rotation");

        let previous = sibling(&options.key_path(), ".previous");
        let kept = std::fs::read(&previous).expect("reads");
        let key = std::fs::read(options.key_path()).expect("reads");
        let log = std::fs::read(&options.log).expect("reads");

        let error = cmd_rekey(&mut sink, &options, None).expect_err("refuses");
        assert!(matches!(error, CliError::Refused(_)), "got {error:?}");
        assert_eq!(std::fs::read(&previous).expect("reads"), kept);
        assert_eq!(std::fs::read(options.key_path()).expect("reads"), key);
        assert_eq!(std::fs::read(&options.log).expect("reads"), log);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rekey_refuses_a_plaintext_log_rather_than_encrypting_it_sideways() {
        // `store encrypt` is the command that converts a log, on purpose and
        // with its own warnings. Rotating a key must not become a second, quiet
        // way to do it.
        let (dir, options) = sealed_store("plaintext");
        std::fs::write(&options.log, "").expect("truncates");
        append_entry(
            &Options {
                key_file: Some(dir.join("absent").display().to_string()),
                ..options.clone()
            },
            1,
        );

        let mut sink: Vec<u8> = Vec::new();
        let error = cmd_rekey(&mut sink, &options, None).expect_err("refuses");
        assert!(
            matches!(&error, CliError::Refused(why) if why.contains("store encrypt")),
            "got {error:?}"
        );
        assert!(!sibling(&options.key_path(), ".previous").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rekey_rotates_the_key_of_a_store_with_nothing_in_it_yet() {
        // Otherwise there is no way to rotate at all before the first record:
        // `keygen` refuses to overwrite, which is exactly the right answer for
        // `keygen` and leaves this case with no command.
        let (dir, options) = sealed_store("empty");
        let before = std::fs::read(options.key_path()).expect("reads");

        let mut out: Vec<u8> = Vec::new();
        assert_eq!(cmd_rekey(&mut out, &options, None).expect("rotates"), 0);
        assert!(String::from_utf8(out).expect("utf-8").contains("empty"));
        assert_ne!(std::fs::read(options.key_path()).expect("reads"), before);
        assert_eq!(
            std::fs::read(sibling(&options.key_path(), ".previous")).expect("reads"),
            before
        );

        // And the store still works: a record written now opens back.
        append_entry(&options, 3);
        assert!(root_of(&options).is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rekey_says_a_plaintext_backup_is_still_plaintext() {
        // `store encrypt` leaves one behind by design. An operator rotating a
        // key is trying to make old bytes unreadable, and a copy that was never
        // sealed does not care which key is current.
        let (dir, options) = sealed_store("leftover");
        append_entry(&options, 1);
        let leftover = format!("{}{}", options.log, mirror::PLAINTEXT_BACKUP_SUFFIX);
        std::fs::write(&leftover, "{\"seq\":0}\n").expect("writes");

        let mut out: Vec<u8> = Vec::new();
        cmd_rekey(&mut out, &options, None).expect("rotates");
        let said = String::from_utf8(out).expect("utf-8");
        assert!(said.contains("PLAINTEXT"), "{said}");
        assert!(said.contains(&leftover), "{said}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rekey_without_a_key_names_the_missing_file() {
        let (dir, options) = sealed_store("nokey");
        std::fs::remove_file(options.key_path()).expect("removes");
        let mut sink: Vec<u8> = Vec::new();
        let error = cmd_rekey(&mut sink, &options, None).expect_err("refuses");
        assert!(
            matches!(error, CliError::AtRest(AtRestError::NoKeyFile { .. })),
            "got {error:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn status_reports_the_encryption_boundary_and_exits_1_on_a_surprise() {
        // The decision in `store::exposure` is only worth anything if an
        // operator can check it against their own disk, and a warning that
        // exits 0 is a warning a health check cannot notice.
        let (dir, options) = sealed_store("boundary");
        append_entry(&options, 1);
        let store_options = Options {
            data: Some(dir.join("data").display().to_string()),
            ..options.clone()
        };

        let mut out: Vec<u8> = Vec::new();
        assert_eq!(
            cmd_store(&mut out, &store_options, &StoreAction::Status).expect("status"),
            0
        );
        let clean = String::from_utf8(out).expect("utf-8");
        assert!(clean.contains("at rest log sealed"), "{clean}");
        assert!(!clean.contains("UNACCOUNTED"), "{clean}");

        // A future feature writing plaintext state into the data directory.
        std::fs::write(dir.join("data/inference-receipts.json"), b"{}").expect("writes");
        let mut out: Vec<u8> = Vec::new();
        assert_eq!(
            cmd_store(&mut out, &store_options, &StoreAction::Status).expect("status"),
            1,
            "an unaccounted plaintext artifact did not change the exit code"
        );
        let flagged = String::from_utf8(out).expect("utf-8");
        assert!(flagged.contains("UNACCOUNTED"), "{flagged}");
        assert!(flagged.contains("inference-receipts.json"), "{flagged}");
        // No key inside, so the key-specific advice stays quiet.
        assert!(!flagged.contains("not encryption at all"), "{flagged}");

        // A key dropped inside is the sharpest case and says so.
        std::fs::copy(options.key_path(), dir.join("data/notes.txt")).expect("copies");
        let mut out: Vec<u8> = Vec::new();
        assert_eq!(
            cmd_store(&mut out, &store_options, &StoreAction::Status).expect("status"),
            1
        );
        let keyed = String::from_utf8(out).expect("utf-8");
        assert!(keyed.contains("KEY INSIDE THE STORE"), "{keyed}");
        assert!(keyed.contains("not encryption at all"), "{keyed}");

        // Many findings are summarised, and the key is still the first thing
        // said. Pointed at a working directory this printed seven hundred
        // lines, which is a tripwire nobody reads -- and the key finding, the
        // one that means everything beside it is readable, was somewhere in the
        // middle of them.
        for n in 0..60 {
            std::fs::write(dir.join(format!("data/stray-{n}.json")), b"{}").expect("writes");
        }
        let mut out: Vec<u8> = Vec::new();
        assert_eq!(
            cmd_store(&mut out, &store_options, &StoreAction::Status).expect("status"),
            1
        );
        let many = String::from_utf8(out).expect("utf-8");
        let listed = many.matches("unaccounted plaintext:").count();
        assert!(listed <= 20, "{listed} findings listed in full");
        assert!(many.contains("more unaccounted file(s)"), "{many}");
        let key_line = many.find("KEY INSIDE THE STORE").expect("key reported");
        let first_plaintext = many.find("unaccounted plaintext:").expect("some listed");
        assert!(
            key_line < first_plaintext,
            "the key finding was not said first"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn export_hands_out_a_plaintext_log_that_re_derives_the_same_root() {
        // The inverse of `store encrypt`, and the reason it exists: sealing a
        // store must not be a one-way door out of "anyone with a copy of the log
        // can re-derive every settled result".
        let (dir, options) = sealed_store("export");
        append_entry(&options, 1);
        append_entry(&options, 2);
        let sealed_root = root_of(&options).expect("a root");
        let destination = dir.join("public.jsonl").display().to_string();

        let mut out: Vec<u8> = Vec::new();
        assert_eq!(
            cmd_export(&mut out, &options, &destination).expect("exports"),
            0
        );
        let said = String::from_utf8(out).expect("utf-8");
        assert!(
            said.contains("PLAINTEXT"),
            "an unwarned plaintext copy: {said}"
        );

        // Plaintext, opens with no key at all, same root.
        let text = std::fs::read_to_string(&destination).expect("reads");
        assert!(!text.contains("pwenc1:"), "the export is still sealed");
        let copy = Ledger::open(&destination).expect("opens with no key");
        assert_eq!(copy.root(), Some(sealed_root));
        assert!(copy.verify_chain().is_empty());

        // And the store it came from is untouched -- still sealed.
        assert_eq!(
            first_line_is_sealed(&options.log).expect("reads"),
            Some(true)
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn export_refuses_to_write_over_an_existing_file() {
        // The destination is by definition somewhere the operator is about to
        // share, and a silent overwrite is a way to lose a log to a typo.
        let (dir, options) = sealed_store("clobber");
        append_entry(&options, 1);
        let destination = dir.join("taken").display().to_string();
        std::fs::write(&destination, "important\n").expect("writes");

        let mut sink: Vec<u8> = Vec::new();
        let error = cmd_export(&mut sink, &options, &destination).expect_err("refuses");
        assert!(matches!(error, CliError::Refused(_)), "got {error:?}");
        assert_eq!(
            std::fs::read_to_string(&destination).expect("reads"),
            "important\n"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn scratch_directories_are_actually_distinct() {
        // The bug this replaced: `Instant::now().elapsed()` measures the gap
        // between those two calls and produced four distinct values in two
        // hundred, so directories meant to be unique collided and tests found
        // each other's files. A suite that fails intermittently is one whose
        // failures stop being read.
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let dir = scratch_dir("distinct");
            assert!(
                seen.insert(dir.clone()),
                "{} was handed out twice",
                dir.display()
            );
            std::fs::remove_dir_all(&dir).ok();
        }
        // And two tags never share one, whatever the clock does.
        let (a, b) = (scratch_dir("alpha"), scratch_dir("beta"));
        assert_ne!(a, b);
        std::fs::remove_dir_all(&a).ok();
        std::fs::remove_dir_all(&b).ok();
    }

    #[test]
    fn a_sibling_path_appends_rather_than_replacing_an_extension() {
        // `Path::with_extension` would turn `key.pw` into `key.previous`, which
        // is a different file from the one meant and possibly somebody else's.
        assert_eq!(
            sibling(Path::new("key"), ".previous"),
            PathBuf::from("key.previous")
        );
        assert_eq!(
            sibling(Path::new("/a/b/key.pw"), ".previous"),
            PathBuf::from("/a/b/key.pw.previous")
        );
    }

    // -- argument parsing --------------------------------------------------

    #[test]
    fn store_actions_parse_including_rekeys_own_passphrase_flag() {
        assert_eq!(
            parse(argv(&["store"])).expect("parses").command,
            Command::Store {
                action: StoreAction::Status
            }
        );
        assert_eq!(
            parse(argv(&["store", "rekey"])).expect("parses").command,
            Command::Store {
                action: StoreAction::Rekey {
                    new_passphrase_file: None
                }
            }
        );
        assert_eq!(
            parse(argv(&["store", "rekey", "--new-passphrase-file", "/tmp/p"]))
                .expect("parses")
                .command,
            Command::Store {
                action: StoreAction::Rekey {
                    new_passphrase_file: Some(String::from("/tmp/p"))
                }
            }
        );
        // The old key's passphrase is a *global* flag and stays one, so both can
        // be given at once -- which is what changing a passphrase needs.
        let parsed = parse(argv(&[
            "--passphrase-file",
            "/tmp/old",
            "store",
            "rekey",
            "--new-passphrase-file",
            "/tmp/new",
        ]))
        .expect("parses");
        assert_eq!(parsed.options.passphrase_file.as_deref(), Some("/tmp/old"));
        assert!(matches!(
            parsed.command,
            Command::Store {
                action: StoreAction::Rekey { .. }
            }
        ));
        assert_eq!(
            parse(argv(&["store", "export", "--out", "/tmp/x.jsonl"]))
                .expect("parses")
                .command,
            Command::Store {
                action: StoreAction::Export {
                    out: String::from("/tmp/x.jsonl")
                }
            }
        );
        assert_eq!(
            parse(argv(&["store", "export", "/tmp/x.jsonl"]))
                .expect("a bare path works too")
                .command,
            Command::Store {
                action: StoreAction::Export {
                    out: String::from("/tmp/x.jsonl")
                }
            }
        );
        assert!(matches!(
            parse(argv(&["store", "export"])).expect_err("needs a destination"),
            CliError::Usage(_)
        ));
        assert!(matches!(
            parse(argv(&["store", "rekey", "--wat"])).expect_err("unknown option"),
            CliError::Usage(_)
        ));
        assert!(matches!(
            parse(argv(&["store", "rotate"])).expect_err("unknown action"),
            CliError::Usage(_)
        ));
    }

    #[test]
    fn global_options_precede_the_command() {
        let parsed =
            parse(argv(&["--log", "/tmp/x.jsonl", "--root", "/srv", "log"])).expect("this parses");
        assert_eq!(parsed.options.log, "/tmp/x.jsonl");
        assert_eq!(parsed.options.root, "/srv");
        assert_eq!(parsed.command, Command::Log);
    }

    #[test]
    fn inline_values_are_accepted() {
        let parsed = parse(argv(&["--log=/tmp/y.jsonl", "log"])).expect("this parses");
        assert_eq!(parsed.options.log, "/tmp/y.jsonl");
    }

    #[test]
    fn a_positional_containing_an_equals_sign_is_untouched() {
        let expanded = expand_inline_values(argv(&["post", "a=b.json"]));
        assert_eq!(expanded, argv(&["post", "a=b.json"]));
    }

    #[test]
    fn a_flag_may_not_swallow_the_next_flag_as_its_value() {
        let error = parse(argv(&[
            "commit",
            "OID",
            "--submitter",
            "--artifact",
            "a.json",
        ]))
        .expect_err("a missing value is a usage error");
        assert!(matches!(error, CliError::Usage(_)), "got {error:?}");
    }

    #[test]
    fn an_empty_nonce_asks_for_a_generated_one() {
        let parsed = parse(argv(&[
            "commit",
            "OID",
            "--submitter",
            "alice",
            "--artifact",
            "a.json",
            "--nonce",
            "",
        ]))
        .expect("this parses");
        match parsed.command {
            Command::Commit { nonce, .. } => assert_eq!(nonce, None),
            other => panic!("expected commit, got {other:?}"),
        }
    }

    #[test]
    fn cites_consumes_until_the_next_flag() {
        let parsed = parse(argv(&[
            "reveal",
            "OID",
            "--cites",
            "a",
            "b",
            "c",
            "--submitter",
            "alice",
            "--artifact",
            "a.json",
            "--nonce",
            "n1",
        ]))
        .expect("this parses");
        match parsed.command {
            Command::Reveal {
                cites,
                objective_id,
                ..
            } => {
                assert_eq!(cites, argv(&["a", "b", "c"]));
                assert_eq!(objective_id, "OID");
            }
            other => panic!("expected reveal, got {other:?}"),
        }
    }

    #[test]
    fn cites_may_be_empty() {
        let parsed = parse(argv(&[
            "reveal",
            "OID",
            "--submitter",
            "a",
            "--artifact",
            "f",
            "--nonce",
            "n",
            "--cites",
        ]))
        .expect("this parses");
        match parsed.command {
            Command::Reveal { cites, .. } => assert!(cites.is_empty()),
            other => panic!("expected reveal, got {other:?}"),
        }
    }

    #[test]
    fn a_reveal_without_a_nonce_is_refused() {
        let error = parse(argv(&[
            "reveal",
            "OID",
            "--submitter",
            "a",
            "--artifact",
            "f",
        ]))
        .expect_err("there is nothing to generate on reveal");
        assert!(matches!(error, CliError::Usage(_)), "got {error:?}");
    }

    #[test]
    fn audit_defaults_to_rerunning_verifiers() {
        assert_eq!(
            parse(argv(&["audit"])).expect("parses").command,
            Command::Audit { rerun: true }
        );
        assert_eq!(
            parse(argv(&["audit", "--no-rerun"]))
                .expect("parses")
                .command,
            Command::Audit { rerun: false }
        );
    }

    #[test]
    fn prove_and_check_parse_their_own_arguments() {
        assert_eq!(
            parse(argv(&["prove", "7"])).expect("parses").command,
            Command::Prove {
                seq: 7,
                height: None,
                out: None
            }
        );
        assert_eq!(
            parse(argv(&[
                "prove",
                "7",
                "--height",
                "20",
                "--out",
                "/tmp/p.json"
            ]))
            .expect("parses")
            .command,
            Command::Prove {
                seq: 7,
                height: Some(20),
                out: Some(String::from("/tmp/p.json"))
            }
        );
        assert!(matches!(
            parse(argv(&["prove", "seven"])).expect_err("not a number"),
            CliError::Usage(_)
        ));
        assert!(matches!(
            parse(argv(&["prove", "-1"])).expect_err("not a flag either"),
            CliError::Usage(_)
        ));
        assert_eq!(
            parse(argv(&["check", "p.json", "--merkle-root", "sha256:aa"]))
                .expect("parses")
                .command,
            Command::Check {
                proof: String::from("p.json"),
                root: Some(String::from("sha256:aa")),
                checkpoint: None,
                root_key: None
            }
        );
        // Neither is unanswerable and both is ambiguous. Ranking them would
        // silently drop one of two roots the caller believed in.
        assert!(matches!(
            parse(argv(&["check", "p.json"])).expect_err("needs a root"),
            CliError::Usage(_)
        ));
        assert!(matches!(
            parse(argv(&[
                "check",
                "p.json",
                "--merkle-root",
                "sha256:aa",
                "--from",
                "c.json"
            ]))
            .expect_err("not both"),
            CliError::Usage(_)
        ));
    }

    /// The whole point, run end to end: a holder proves, a stranger checks.
    ///
    /// `cmd_check` gets no `Options` at all, which is the property under test
    /// as much as the arithmetic is -- a light client has no log, and a check
    /// that quietly needed one would be no lighter than `verify`.
    #[test]
    fn a_proof_emitted_by_the_cli_checks_against_the_checkpoint_the_cli_signed() {
        use proofwork::canonical::digest_bytes;
        let dir = scratch_dir("prove");
        let options = Options {
            log: dir.join("log.jsonl").display().to_string(),
            root: dir.display().to_string(),
            data: None,
            key_file: None,
            passphrase_file: None,
            max_size: None,
        };
        {
            let mut ledger = Ledger::open(&options.log).expect("open");
            for i in 0..7 {
                ledger
                    .append("note", Value::Int(i128::from(i)), "t")
                    .expect("append");
            }
        }

        // A signing key in the shape `proofwork-p2p` writes.
        let key = proofwork::checkpoint::RootKey::generate();
        let key_path = dir.join("key.json");
        std::fs::write(
            &key_path,
            Value::object([
                ("public", Value::string(hex_of(&key.public_key()))),
                ("secret", Value::string(hex_of(&key.to_secret_bytes()[..]))),
            ])
            .canonical_string(),
        )
        .expect("write key");
        let checkpoint = dir.join("checkpoint.json");
        let mut sink: Vec<u8> = Vec::new();
        assert_eq!(
            cmd_checkpoint(
                &mut sink,
                &options,
                &key_path.display().to_string(),
                Some(&checkpoint.display().to_string()),
            )
            .expect("checkpoint"),
            0
        );
        let published = dir.join("root-key.pub");
        std::fs::write(&published, hex_of(&key.public_key())).expect("write pubkey");

        let proof_path = dir.join("proof.json");
        let mut sink: Vec<u8> = Vec::new();
        assert_eq!(
            cmd_prove(
                &mut sink,
                &options,
                4,
                None,
                Some(&proof_path.display().to_string()),
            )
            .expect("prove"),
            0
        );

        let mut sink: Vec<u8> = Vec::new();
        assert_eq!(
            cmd_check(
                &mut sink,
                &proof_path.display().to_string(),
                None,
                Some(&checkpoint.display().to_string()),
                Some(&published.display().to_string()),
            )
            .expect("check"),
            0
        );
        let report = String::from_utf8(sink).expect("utf-8");
        assert!(report.starts_with("proof ok:"), "{report}");
        assert!(!report.contains("warning"), "a key was pinned: {report}");

        // Now the failure, and it must be exit 1 rather than an error: the
        // reader checked, and the answer was no.
        let mut sink: Vec<u8> = Vec::new();
        assert_eq!(
            cmd_check(
                &mut sink,
                &proof_path.display().to_string(),
                Some(&digest_bytes(b"not the root")),
                None,
                None,
            )
            .expect("check runs"),
            1
        );
        assert!(
            String::from_utf8(sink)
                .expect("utf-8")
                .contains("does not reach root"),
            "the reader should be told which check failed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A proof against a taller log than the reader's checkpoint is the
    /// everyday failure -- the log grew. It must not read as fraud.
    #[test]
    fn a_proof_from_a_grown_log_is_refused_with_the_remedy_named() {
        let dir = scratch_dir("prove-stale");
        let options = Options {
            log: dir.join("log.jsonl").display().to_string(),
            root: dir.display().to_string(),
            data: None,
            key_file: None,
            passphrase_file: None,
            max_size: None,
        };
        {
            let mut ledger = Ledger::open(&options.log).expect("open");
            for i in 0..5 {
                ledger
                    .append("note", Value::Int(i128::from(i)), "t")
                    .expect("append");
            }
        }
        let key = proofwork::checkpoint::RootKey::generate();
        let key_path = dir.join("key.json");
        std::fs::write(
            &key_path,
            Value::object([("secret", Value::string(hex_of(&key.to_secret_bytes()[..])))])
                .canonical_string(),
        )
        .expect("write key");
        let checkpoint = dir.join("checkpoint.json");
        let mut sink: Vec<u8> = Vec::new();
        cmd_checkpoint(
            &mut sink,
            &options,
            &key_path.display().to_string(),
            Some(&checkpoint.display().to_string()),
        )
        .expect("checkpoint");

        // The log grows past what the reader has signed.
        {
            let mut ledger = Ledger::open(&options.log).expect("reopen");
            for i in 5..9 {
                ledger
                    .append("note", Value::Int(i128::from(i)), "t")
                    .expect("append");
            }
        }
        let published = dir.join("root-key.pub");
        std::fs::write(&published, hex_of(&key.public_key())).expect("write pubkey");

        let tall = dir.join("tall.json");
        let mut sink: Vec<u8> = Vec::new();
        cmd_prove(
            &mut sink,
            &options,
            2,
            None,
            Some(&tall.display().to_string()),
        )
        .expect("prove");
        let mut sink: Vec<u8> = Vec::new();
        assert_eq!(
            cmd_check(
                &mut sink,
                &tall.display().to_string(),
                None,
                Some(&checkpoint.display().to_string()),
                Some(&published.display().to_string()),
            )
            .expect("check runs"),
            1
        );
        let report = String::from_utf8(sink).expect("utf-8");
        assert!(report.contains("the checkpoint pins 5"), "{report}");
        assert!(report.contains("--height 5"), "name the fix: {report}");

        // And running the remedy the message names actually works.
        let short = dir.join("short.json");
        let mut sink: Vec<u8> = Vec::new();
        cmd_prove(
            &mut sink,
            &options,
            2,
            Some(5),
            Some(&short.display().to_string()),
        )
        .expect("prove at height");
        let mut sink: Vec<u8> = Vec::new();
        assert_eq!(
            cmd_check(
                &mut sink,
                &short.display().to_string(),
                None,
                Some(&checkpoint.display().to_string()),
                Some(&published.display().to_string()),
            )
            .expect("check runs"),
            0
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attribute_defaults_match_flow_params() {
        let parsed = parse(argv(&["attribute"])).expect("parses");
        assert_eq!(
            parsed.command,
            Command::Attribute {
                params: FlowParams::default()
            }
        );
    }

    #[test]
    fn incentives_defaults_to_the_reference_network() {
        let parsed = parse(argv(&["incentives"])).expect("parses");
        assert_eq!(
            parsed.command,
            Command::Incentives {
                params: Box::new(NodeParams::reference()),
                robustness: false,
                sweep: Vec::new(),
                out: None,
                format: TableFormat::Csv,
            }
        );
        // Opt-in, because a margin table is hundreds of full solver runs.
        assert_eq!(
            parse(argv(&["incentives", "--robustness"]))
                .expect("parses")
                .command,
            Command::Incentives {
                params: Box::new(NodeParams::reference()),
                robustness: true,
                sweep: Vec::new(),
                out: None,
                format: TableFormat::Csv,
            }
        );
    }

    /// The flags are `commit`'s and `reveal`'s, deliberately: a flag that meant
    /// something different here would cost more than the convenience is worth.
    #[test]
    fn try_takes_the_same_flags_as_the_two_commands_it_wraps() {
        let parsed = parse(argv(&[
            "try",
            "examples/collatz/objective.json",
            "--submitter",
            "alice",
            "--artifact",
            "a.json",
            "--nonce",
            "abc",
            "--cites",
            "sha256:aa",
            "sha256:bb",
            "--settle",
        ]))
        .expect("parses");
        match parsed.command {
            Command::Try {
                objective,
                submitter,
                artifact,
                nonce,
                cites,
                settle,
                ..
            } => {
                assert_eq!(objective, "examples/collatz/objective.json");
                assert_eq!(submitter, "alice");
                assert_eq!(artifact, "a.json");
                assert_eq!(nonce.as_deref(), Some("abc"));
                assert_eq!(cites, vec!["sha256:aa", "sha256:bb"]);
                assert!(settle);
            }
            other => panic!("expected a try command, got {other:?}"),
        }
    }

    /// An id and a file are different things and must not be confused: a file
    /// named after a digest is a file, and an id is never posted.
    #[test]
    fn try_tells_an_objective_id_from_a_file_by_its_prefix() {
        for objective in ["sha256:aabb", "examples/collatz/objective.json", "sha256"] {
            let parsed = parse(argv(&[
                "try",
                objective,
                "--submitter",
                "alice",
                "--artifact",
                "a.json",
            ]))
            .expect("parses");
            match parsed.command {
                Command::Try { objective: got, .. } => assert_eq!(got, objective),
                other => panic!("expected a try command, got {other:?}"),
            }
        }
    }

    #[test]
    fn try_needs_an_objective_an_artifact_and_somebody_to_submit_as() {
        assert!(parse(argv(&["try"])).is_err());
        assert!(parse(argv(&["try", "obj.json"])).is_err());
        assert!(parse(argv(&["try", "obj.json", "--artifact", "a.json"])).is_err());
        assert!(parse(argv(&["try", "obj.json", "--submitter", "alice"])).is_err());
        assert!(parse(argv(&[
            "try",
            "obj.json",
            "--submitter",
            "alice",
            "--artifact",
            "a.json"
        ]))
        .is_ok());
        // An identity file decides the submitter, so the name is optional --
        // the same rule `commit` follows, for the same reason.
        assert!(parse(argv(&[
            "try",
            "obj.json",
            "--identity",
            "k.json",
            "--artifact",
            "a.json"
        ]))
        .is_ok());
    }

    /// `--settle` is opt-in, and an empty `--nonce` generates one, exactly as
    /// `commit` does.
    #[test]
    fn try_defaults_match_the_commands_it_wraps() {
        let parsed = parse(argv(&[
            "try",
            "obj.json",
            "--submitter",
            "alice",
            "--artifact",
            "a.json",
            "--nonce",
            "",
        ]))
        .expect("parses");
        match parsed.command {
            Command::Try {
                nonce,
                settle,
                cites,
                ..
            } => {
                assert_eq!(nonce, None);
                assert!(!settle);
                assert!(cites.is_empty());
            }
            other => panic!("expected a try command, got {other:?}"),
        }
    }

    #[test]
    fn scaffold_needs_a_name_and_a_kind() {
        assert!(parse(argv(&["scaffold"])).is_err());
        assert!(parse(argv(&["scaffold", "widget"])).is_err());
        assert!(parse(argv(&["scaffold", "widget", "--kind", "nonsense"])).is_err());
        assert!(parse(argv(&["scaffold", "widget", "--kind", "certificate"])).is_ok());
    }

    /// A pin resolves against `--root`. An `--out` that leaves it makes an
    /// objective that verifies on the author's machine and nowhere else, so it
    /// is refused before any directory is created.
    #[test]
    fn scaffold_refuses_an_out_that_escapes_the_bundle_root() {
        for out in ["/tmp", "../elsewhere"] {
            assert!(
                parse(argv(&[
                    "scaffold", "widget", "--kind", "lean", "--out", out
                ]))
                .is_err(),
                "{out} was accepted"
            );
        }
    }

    #[test]
    fn scaffold_carries_the_flags_it_was_given() {
        let parsed = parse(argv(&[
            "scaffold",
            "widget",
            "--kind",
            "evaluator",
            "--out",
            "challenges",
            "--reward",
            "5000",
            "--funder",
            "treasury",
        ]))
        .expect("parses");
        match parsed.command {
            Command::Scaffold { request, force } => {
                assert_eq!(request.name, "widget");
                assert_eq!(request.kind, scaffold::Kind::Evaluator);
                assert_eq!(request.parent, "challenges");
                assert_eq!(request.reward, 5000);
                assert_eq!(request.funder, "treasury");
                // Overwriting is opt-in: the obvious mistake is scaffolding
                // over an objective already in the log.
                assert!(!force);
            }
            other => panic!("expected a scaffold command, got {other:?}"),
        }
    }

    #[test]
    fn a_sweep_axis_becomes_a_grid_and_leaves_the_base_alone() {
        let parsed = parse(argv(&[
            "incentives",
            "--nodes",
            "40",
            "--sweep",
            "canary-rate=1/20..1/5:5",
        ]))
        .expect("parses");
        match parsed.command {
            Command::Incentives { params, sweep, .. } => {
                // The un-swept flags still describe the base point: a sweep
                // narrows what varies, it does not discard the rest.
                assert_eq!(params.nodes, 40);
                assert_eq!(sweep.len(), 1);
                assert_eq!(sweep[0].values.len(), 5);
            }
            other => panic!("expected an incentives command, got {other:?}"),
        }
    }

    #[test]
    fn sweeping_one_parameter_twice_is_refused_rather_than_resolved() {
        let error = parse(argv(&[
            "incentives",
            "--sweep",
            "stake=1000..2000:2",
            "--sweep",
            "stake=3000..4000:2",
        ]))
        .expect_err("two ranges for one column");
        assert!(format!("{error}").contains("swept twice"), "{error}");
    }

    /// `--out` and `--format` describe a table. Without `--sweep` there is no
    /// table, and silently ignoring them would leave an operator waiting for a
    /// file that was never written.
    #[test]
    fn table_flags_without_a_sweep_are_refused() {
        assert!(parse(argv(&["incentives", "--out", "grid.csv"])).is_err());
        assert!(parse(argv(&["incentives", "--format", "jsonl"])).is_err());
        assert!(parse(argv(&[
            "incentives",
            "--sweep",
            "stake=1000..2000:2",
            "--format",
            "jsonl"
        ]))
        .is_ok());
    }

    /// A base point an axis is about to overwrite must not be rejected up
    /// front: `--sweep threshold=1..3` over a base whose threshold exceeds its
    /// committee is a perfectly ordinary request.
    #[test]
    fn a_sweep_defers_validation_to_the_points_it_actually_evaluates() {
        assert!(parse(argv(&["incentives", "--threshold", "99"])).is_err());
        assert!(parse(argv(&[
            "incentives",
            "--threshold",
            "99",
            "--sweep",
            "threshold=1..3:3"
        ]))
        .is_ok());
    }

    #[test]
    fn incentives_overrides_one_field_and_inherits_the_rest() {
        // The property that makes the command usable: an analyst changes the
        // number they care about without restating twenty others, and does not
        // silently get a different network for the ones they left out.
        let parsed =
            parse(argv(&["incentives", "--canary-rate", "0", "--nodes", "40"])).expect("parses");
        match parsed.command {
            Command::Incentives { params, .. } => {
                assert_eq!(params.canary_rate, Rat::ZERO);
                assert_eq!(params.nodes, 40);
                assert_eq!(params.stake, NodeParams::reference().stake);
                assert_eq!(params.fee, NodeParams::reference().fee);
            }
            other => panic!("expected an incentives command, got {other:?}"),
        }
    }

    #[test]
    fn rates_are_exact_fractions_and_decimals_are_refused() {
        // Accepting "0.01" would mean parsing a float and throwing it away at
        // the first threshold comparison, which is the one thing the harness
        // exists to avoid.
        assert_eq!(
            parse_rate("1/100", "--canary-rate").expect("parses"),
            Rat::rate(1, 100).expect("a valid rate")
        );
        assert_eq!(parse_rate("0", "--fee").expect("parses"), Rat::ZERO);
        assert_eq!(parse_rate("1", "--fee").expect("parses"), Rat::ONE);
        assert!(parse_rate("0.01", "--fee").is_err());
        assert!(parse_rate("3/2", "--fee").is_err(), "above one");
        assert!(parse_rate("1/0", "--fee").is_err(), "no answer");
        assert!(parse_rate("-1/2", "--fee").is_err());
        assert!(parse_rate("", "--fee").is_err());
    }

    #[test]
    fn an_impossible_committee_is_refused_before_any_report_is_printed() {
        let error = parse(argv(&["incentives", "--threshold", "99"]))
            .expect_err("a threshold above the committee is not a t-of-n");
        assert!(matches!(error, CliError::Params(_)), "got {error:?}");
        // Cross-field, too: shrinking the network below the committee it
        // inherited is caught here rather than deep inside a payoff function.
        let error = parse(argv(&["incentives", "--nodes", "7"]))
            .expect_err("a committee cannot be larger than the network");
        assert!(matches!(error, CliError::Params(_)), "got {error:?}");
    }

    #[test]
    fn parse_u64_rejects_negatives_and_junk() {
        assert!(parse_u64("-1", "--delta-num").is_err());
        assert!(parse_u64("1.5", "--delta-num").is_err());
        assert!(parse_u64("", "--delta-num").is_err());
        assert_eq!(parse_u64("4", "--delta-den").expect("4 parses"), 4);
        assert!(parse_u32("-1", "--max-depth").is_err());
        assert_eq!(parse_u32("6", "--max-depth").expect("6 parses"), 6);
    }

    #[test]
    fn a_delta_above_one_is_refused_before_any_payout_is_printed() {
        let error = parse(argv(&["attribute", "--delta-num", "5", "--delta-den", "4"]))
            .expect_err("delta must lie in [0, 1]");
        assert!(matches!(error, CliError::Flow(_)), "got {error:?}");
    }

    #[test]
    fn a_zero_denominator_is_refused() {
        let error = parse(argv(&["attribute", "--delta-den", "0"]))
            .expect_err("a zero denominator has no answer");
        assert!(matches!(error, CliError::Flow(_)), "got {error:?}");
    }

    #[test]
    fn unknown_commands_and_empty_lines_are_usage_errors() {
        assert!(matches!(
            parse(argv(&[])).expect_err("no command"),
            CliError::Usage(_)
        ));
        assert!(matches!(
            parse(argv(&["conjure"])).expect_err("no such command"),
            CliError::Usage(_)
        ));
        assert!(matches!(
            parse(argv(&["settle", "extra"])).expect_err("settle takes no arguments"),
            CliError::Usage(_)
        ));
        assert!(matches!(
            parse(argv(&["log", "extra"])).expect_err("log takes no arguments"),
            CliError::Usage(_)
        ));
    }

    #[test]
    fn help_is_reachable_three_ways() {
        for spelling in [vec!["help"], vec!["--help"], vec!["-h"]] {
            let parsed = parse(argv(&spelling)).expect("parses");
            assert_eq!(parsed.command, Command::Help, "for {spelling:?}");
        }
    }

    #[test]
    fn a_bare_dash_is_a_value_not_a_flag() {
        assert!(!is_flag("-"));
        assert!(is_flag("-h"));
        assert!(is_flag("--log"));
        assert!(!is_flag("sha256:abc"));
        assert!(!is_flag(""));
    }

    // -- arithmetic --------------------------------------------------------

    #[test]
    fn totals_are_summed_in_u128_and_do_not_wrap() {
        let table = payouts(&[("alice", u64::MAX), ("bob", u64::MAX)]);
        let total = total_units(&table).expect("u128 holds two u64 maxima");
        assert_eq!(total, u128::from(u64::MAX) * 2);
        // The point of the widening: this is the number a u64 sum would have
        // reported instead.
        assert_ne!(total, u128::from(u64::MAX.wrapping_add(u64::MAX)));
    }

    #[test]
    fn a_zero_total_prints_zero_rather_than_nan() {
        let value = percent(0, 0);
        assert!(value.is_finite());
        assert_eq!(value, 0.0);
    }

    #[test]
    fn percentages_are_shares_of_the_total() {
        assert_eq!(percent(1, 4), 25.0);
        assert_eq!(percent(3, 4), 75.0);
    }

    #[test]
    fn an_all_zero_payout_table_still_renders() {
        // Reachable: `flow` credits a submitter zero units when the claim passes
        // everything upstream, and a settlement of zero pays nobody anything.
        let table = payouts(&[("alice", 0), ("bob", 0)]);
        let lines = render_attribution(&FlowParams::default(), &table).expect("renders");
        assert!(lines.iter().any(|line| line.contains("0.0%")));
        assert!(lines.iter().any(|line| line.contains("total")));
    }

    // -- table rendering ---------------------------------------------------

    #[test]
    fn an_empty_table_says_so() {
        let lines = render_attribution(&FlowParams::default(), &BTreeMap::new()).expect("renders");
        assert_eq!(lines, vec![String::from("no settlements yet")]);
    }

    #[test]
    fn rows_are_ordered_by_units_then_name() {
        let table = payouts(&[("carol", 10), ("alice", 30), ("bob", 10)]);
        let lines = render_attribution(&FlowParams::default(), &table).expect("renders");
        let names: Vec<&str> = lines
            .iter()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|word| ["alice", "bob", "carol"].contains(word))
            .collect();
        assert_eq!(names, vec!["alice", "bob", "carol"]);
    }

    #[test]
    fn the_total_row_agrees_with_the_rows_above_it() {
        let table = payouts(&[("alice", 750), ("bob", 250)]);
        let lines = render_attribution(&FlowParams::default(), &table).expect("renders");
        let last = lines.last().expect("a total row");
        assert!(last.contains("total"), "got {last:?}");
        assert!(last.contains("1000"), "got {last:?}");
        assert!(lines.iter().any(|line| line.contains("75.0%")));
        assert!(lines.iter().any(|line| line.contains("25.0%")));
    }

    #[test]
    fn the_header_reports_the_parameters_in_force() {
        let params = FlowParams::new(1, 3, 2).expect("1/3 is a valid delta");
        let lines = render_attribution(&params, &payouts(&[("alice", 1)])).expect("renders");
        assert_eq!(
            lines.first().map(String::as_str),
            Some("delta 1/3  max_depth 2")
        );
    }

    #[test]
    fn columns_are_padded_by_characters_not_bytes() {
        let table = payouts(&[("zoé", 1), ("al", 1)]);
        let lines = render_attribution(&FlowParams::default(), &table).expect("renders");
        let rows: Vec<&String> = lines.iter().filter(|line| line.contains('%')).collect();
        assert_eq!(rows.len(), 2);
        // Same character count on both rows, even though "zoé" is four bytes.
        let widths: Vec<usize> = rows.iter().map(|line| line.chars().count()).collect();
        assert_eq!(widths.first(), widths.last(), "rows: {rows:?}");
    }

    // -- log summaries -----------------------------------------------------

    #[test]
    fn summaries_never_panic_on_a_malformed_payload() {
        let empty = Value::Object(BTreeMap::new());
        for kind in [
            "objective",
            "claim",
            "commitment",
            "verdict",
            "settlement",
            "frontier",
            "peer",
            "nonsense",
        ] {
            let _ = summarize(kind, &empty);
        }
        // Not even an object.
        assert_eq!(summarize("objective", &Value::Null), "");
        assert_eq!(summarize("settlement", &Value::Int(7)), " <- ?");
    }

    #[test]
    fn summaries_read_the_fields_the_reference_implementation_reads() {
        let objective = proofwork::obj! { "statement" => Value::string("Exhibit a cap set") };
        assert_eq!(summarize("objective", &objective), "Exhibit a cap set");

        let claim = proofwork::obj! { "submitter" => Value::string("alice") };
        assert_eq!(summarize("claim", &claim), "by alice");
        assert_eq!(summarize("commitment", &claim), "by alice");

        // The identity is truncated and the address is not: two records for one
        // identity are the same peer moving, and a reader has to see that at a
        // glance rather than by comparing two 64-character keys.
        let peer = proofwork::obj! {
            "identity" => Value::string("ab".repeat(32)),
            "addr" => Value::string("10.0.0.9:9000"),
            "seq" => Value::Int(2),
        };
        assert_eq!(
            summarize("peer", &peer),
            "abababab at 10.0.0.9:9000 (seq 2)"
        );

        let verdict = proofwork::obj! {
            "verdict" => proofwork::obj! {
                "status" => Value::string("accept"),
                "detail" => Value::string("certificate checks out"),
            },
        };
        assert_eq!(
            summarize("verdict", &verdict),
            "accept: certificate checks out"
        );

        let settlement = proofwork::obj! {
            "submitter" => Value::string("bob"),
            "reward" => Value::Int(250_000),
        };
        assert_eq!(summarize("settlement", &settlement), "bob <- 250000");
    }

    #[test]
    fn truncation_counts_characters_and_cannot_split_one() {
        let statement = "é".repeat(80);
        let cut = truncate_chars(&statement, STATEMENT_WIDTH);
        assert_eq!(cut.chars().count(), STATEMENT_WIDTH);
        // Byte slicing at 60 would have landed mid-character and panicked.
        assert_eq!(cut.len(), STATEMENT_WIDTH * 2);
        assert_eq!(truncate_chars("short", STATEMENT_WIDTH), "short");
    }

    #[test]
    fn a_long_verdict_detail_is_cut_to_forty_characters() {
        let verdict = proofwork::obj! {
            "verdict" => proofwork::obj! {
                "status" => Value::string("reject"),
                "detail" => Value::string("x".repeat(100)),
            },
        };
        assert_eq!(
            summarize("verdict", &verdict),
            format!("reject: {}", "x".repeat(DETAIL_WIDTH))
        );
    }

    // -- nonces ------------------------------------------------------------

    #[test]
    fn hex_encoding_is_lowercase_and_zero_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xff]), "000fff");
        assert_eq!(hex(&[]), "");
    }

    #[test]
    fn a_generated_nonce_is_thirty_two_hex_characters() {
        // `secrets.token_hex(16)` produces exactly this shape.
        match random_nonce() {
            Ok(nonce) => {
                assert_eq!(nonce.chars().count(), NONCE_BYTES * 2);
                assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
            }
            // A machine with no /dev/urandom must say so rather than invent
            // entropy; that refusal is the tested behaviour too.
            Err(error) => assert!(matches!(error, CliError::Entropy(_)), "got {error:?}"),
        }
    }

    #[test]
    fn two_generated_nonces_differ() {
        if let (Ok(first), Ok(second)) = (random_nonce(), random_nonce()) {
            assert_ne!(first, second, "a nonce that repeats is not a nonce");
        }
    }

    // -- error reporting ---------------------------------------------------

    #[test]
    fn rule_violations_are_reported_as_refusals() {
        let error = CliError::Refused(String::from("objective is already settled"));
        assert_eq!(error.report(), "refused: objective is already settled");
        assert_eq!(error.code(), 2);
    }

    #[test]
    fn other_failures_are_reported_as_errors() {
        let error = CliError::LogPayload {
            seq: 4,
            reason: String::from("settlement has no claim_id"),
        };
        assert_eq!(
            error.report(),
            "error: log entry 4: settlement has no claim_id"
        );
    }
}
