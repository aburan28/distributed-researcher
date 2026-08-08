//! End-to-end node behaviour: what may be posted, what settles, what mints
//! nothing, and what an auditor is told when the answer changes.
//!
//! Ported from the reference implementation's `test_node.py`, `test_frontier.py`,
//! `test_verifiers.py` and `test_examples.py`. Every case here goes through the
//! public API only -- `Node`, `Ledger`, `VerifierRegistry`, the record types --
//! because that is exactly the surface a third party has when they re-derive the
//! network's history from a copy of the log. A rule that can only be checked
//! from inside the crate is a rule nobody outside can audit.
//!
//! The properties these tests exist to defend, in the order the file walks them:
//!
//! 1. **Commit-then-reveal binds work to a worker.** A reveal with no prior
//!    commitment, a commitment replayed under another name, and a wrong nonce
//!    are all refused. Without that, whoever *sees* an artifact first collects
//!    on it and the solver gets nothing.
//! 2. **Only a settling verdict moves value.** `Unavailable` is an
//!    infrastructure fact about one node, never a refutation, and it leaves a
//!    funded objective open. If a missing toolchain could reach `Reject`, taking
//!    verifiers offline would fail every honest submission in the network.
//! 3. **Novelty is necessary and never sufficient.** A duplicate artifact
//!    verifies fine and mints zero.
//! 4. **Content addressing makes editing an objective self-defeating**, not
//!    merely detectable: the edited record hashes differently, so it is a
//!    *different* objective and the chain flags the swap.
//! 5. **The ratchet makes publishing safe.** Copying the frontier moves it zero
//!    and pays zero, an improvement must cite what it improved on, and the pool
//!    is exhausted exactly at the target no matter how the curve is chopped up.
//! 6. **The audit re-derives everything.** A settled claim that can no longer be
//!    re-verified, a settled claim that now fails, an overspent pool, and a
//!    frontier that moved backwards are all reported. Saying "log verified" when
//!    nothing was actually checked would be a lie of omission.
//!
//! Pinned checkers are written to a temp directory by the test itself and pinned
//! by a hash the test computes, so nothing here depends on a fixture file that
//! could drift out of sync with its hash. The `examples/` cases are the
//! exception and the point: they run the *shipped* Python checkers through the
//! real subprocess verifier, so they prove the harness works end to end and that
//! a shipped example is not a broken claim.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use proofwork::canonical::Value;
use proofwork::frontier::{Direction, Ratchet, RatchetError};
use proofwork::ledger::Ledger;
use proofwork::node::{Node, Outcome, RuleViolation};
use proofwork::partition::epoch_seconds;
use proofwork::records::{commitment_hash, Claim, Commitment, Objective};
use proofwork::time::format_iso8601_utc;
use proofwork::verifiers::{Status, VerifierRegistry};

/// Frozen timestamp. Nothing in the rules depends on wall-clock time, and a
/// fixed stamp keeps record ids reproducible across runs.
const TS: &str = "2026-07-28T00:00:00+00:00";

/// [`TS`] as seconds since the Unix epoch, and the origin every [`stamp`] is
/// measured from.
const BASE: i64 = 1_785_196_800;

/// One epoch, as an offset. Read from the crate rather than restated here: a
/// `PROOFWORK_EPOCH_SECONDS` override that this file did not follow would put
/// commit and reveal back in the same epoch and fail every submission.
fn epoch() -> i64 {
    epoch_seconds() as i64
}

/// [`TS`] plus `offset` seconds.
fn stamp(offset: i64) -> String {
    format_iso8601_utc(BASE + offset)
}

/// A Lean binary name guaranteed not to exist, so `lean` verification is
/// deterministically `Unavailable` without touching (or depending on) whatever
/// toolchain the host happens to have installed.
const NO_LEAN: &str = "proofwork-rules-definitely-no-such-lean-binary";

/// The repository root, which is the objective bundle root the shipped
/// `examples/*/objective.json` files pin their checkers against.
const REPO_ROOT: &str = env!("CARGO_MANIFEST_DIR");

const CHECKER: &str = r#"
def check(artifact):
    return artifact.get("n") == 42
"#;

/// The same checker after someone swaps it out from under a funded objective.
const CHECKER_EDITED: &str = r#"
def check(artifact):
    return artifact.get("n") == 43
"#;

/// A checker whose answer depends on state the objective does not pin. It passes
/// today and fails tomorrow at the same hash: pinning source is necessary and
/// not sufficient, because a verifier must also be *pure*. Reads a file relative
/// to itself, so the pin still resolves and only the behaviour changes.
const IMPURE_CHECKER: &str = r#"
import os

def check(artifact):
    with open(os.path.join(os.path.dirname(__file__), "threshold.txt")) as handle:
        return artifact.get("n") == int(handle.read().strip())
"#;

const EVALUATOR: &str = r#"
def score(artifact):
    return artifact.get("score", 0)
"#;

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> TempDir {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "proofwork-rules-{label}-{}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("scratch directory is creatable");
        TempDir { path }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Best effort: a failed cleanup must not turn a passing test red, and
        // must not mask a panic already unwinding through here.
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    proofwork::hex::encode(&hasher.finalize())
}

/// Write pinned source into the bundle root and return the hash the objective
/// will declare. Computing it here rather than hard-coding it is what keeps the
/// pin honest: an edit to the source above cannot silently stop being checked.
fn write_pinned(dir: &TempDir, name: &str, source: &str) -> String {
    fs::write(dir.file(name), source).expect("pinned source is writable");
    sha256_hex(source.as_bytes())
}

/// A node whose Lean toolchain is guaranteed absent, so `lean` verdicts here are
/// a property of the submitted text and nothing else.
fn node_at(dir: &TempDir) -> Node {
    let ledger = Ledger::open(dir.file("log.jsonl")).expect("a missing file is an empty log");
    Node::with_registry(
        ledger,
        VerifierRegistry::new(&dir.path).with_lean_binary(NO_LEAN),
    )
}

fn certificate_verifier(checker: &str, sha: &str) -> Value {
    Value::object([
        ("kind", Value::string("certificate")),
        ("checker", Value::string(checker)),
        ("checker_sha256", Value::string(sha)),
        ("entrypoint", Value::string("check")),
    ])
}

/// The `test_node.py` fixture: a certificate objective worth 1000, whose pinned
/// checker accepts exactly `{"n": 42}`.
fn certificate_env(label: &str, source: &str) -> (TempDir, Node, Objective) {
    let dir = TempDir::new(label);
    let sha = write_pinned(&dir, "c.py", source);
    let mut node = node_at(&dir);
    let objective = Objective::new(
        "G",
        "find n = 42",
        certificate_verifier("c.py", &sha),
        1000,
        "treasury",
        TS,
        None,
        None,
    )
    .expect("valid objective");
    node.post_objective(&objective, TS).expect("post");
    (dir, node, objective)
}

/// The `test_frontier.py` fixture: a progressive objective over a pinned
/// evaluator, pool 1_000_000, curve from 0 to 100.
fn ratchet_env(label: &str) -> (TempDir, Node, Objective) {
    let dir = TempDir::new(label);
    let sha = write_pinned(&dir, "e.py", EVALUATOR);
    let mut node = node_at(&dir);
    let objective = Objective::new(
        "G",
        "maximize the score",
        Value::object([
            ("kind", Value::string("evaluator")),
            ("evaluator", Value::string("e.py")),
            ("evaluator_sha256", Value::string(sha.as_str())),
            ("entrypoint", Value::string("score")),
            ("threshold", Value::Int(0)),
            ("direction", Value::string("maximize")),
        ]),
        1_000_000,
        "treasury",
        TS,
        None,
        Some(Value::object([
            ("baseline", Value::Int(0)),
            ("target", Value::Int(100)),
            ("reward", Value::Int(1_000_000)),
            ("direction", Value::string("maximize")),
        ])),
    )
    .expect("valid objective");
    node.post_objective(&objective, TS).expect("post");
    (dir, node, objective)
}

fn n(value: i128) -> Value {
    Value::object([("n", Value::Int(value))])
}

/// An artifact or spec with no fields. `Value` has no float variant and no
/// convenience empty constructor, so this is spelled once.
fn empty() -> Value {
    Value::Object(BTreeMap::new())
}

fn scored(value: i128) -> Value {
    Value::object([("score", Value::Int(value))])
}

fn proof(text: &str) -> Value {
    Value::object([("proof", Value::string(text))])
}

/// Commit, reveal, then close the batch -- what an honest submitter and an
/// honest operator do between them.
///
/// Three epochs, and they do not collapse into one. A reveal must land in a
/// strictly later epoch than its own commitment, or the sequencer -- who sees
/// reveals first -- could open a commitment of its own in the same breath; and
/// a batch settles only once its epoch is over, because settlement order is a
/// function of the whole set of claims in the epoch and that set is not known
/// until then. The step is taken off the ledger length so successive
/// submissions occupy successive epochs: an epoch whose batch has already been
/// paid refuses further reveals, which is the rule rather than an artifact of
/// this helper.
///
/// Returns the claim's *final* outcome, so a caller can still ask "what did
/// this submission earn" in one line. A verdict that never reaches the batch --
/// unavailable, rejected -- is returned as it stands.
fn submit(
    node: &mut Node,
    objective: &Objective,
    submitter: &str,
    artifact: Value,
    nonce: &str,
    cites: Vec<String>,
) -> Result<Outcome, RuleViolation> {
    let step = node.ledger().len() as i64 * 4 * epoch();
    commit_at(node, objective, submitter, &artifact, nonce, &stamp(step));
    let outcome = reveal_at(
        node,
        objective,
        submitter,
        artifact,
        nonce,
        cites,
        &stamp(step + epoch()),
    )?;
    if !outcome.is_pending() {
        return Ok(outcome);
    }
    let settled = node.settle_at(&stamp(step + 2 * epoch()))?;
    Ok(settled
        .into_iter()
        .find(|candidate| candidate.claim_id == outcome.claim_id)
        .unwrap_or(outcome))
}

/// Commit at a chosen instant, for the tests that need the two halves apart.
fn commit_at(
    node: &mut Node,
    objective: &Objective,
    submitter: &str,
    artifact: &Value,
    nonce: &str,
    ts: &str,
) {
    let hash = commitment_hash(&objective.id(), submitter, artifact, nonce);
    node.commit(&Commitment::new(objective.id(), submitter, hash, ts), ts)
        .expect("commit");
}

/// Reveal without committing first -- what an artifact thief does.
fn reveal_only(
    node: &mut Node,
    objective: &Objective,
    submitter: &str,
    artifact: Value,
    nonce: &str,
    cites: Vec<String>,
) -> Result<Outcome, RuleViolation> {
    reveal_at(node, objective, submitter, artifact, nonce, cites, TS)
}

/// Reveal at a chosen instant. `created_at` on the claim stays [`TS`]: the
/// commitment binds the artifact and the nonce, not when the claim record says
/// it was written, and holding it fixed keeps claim ids reproducible.
#[allow(clippy::too_many_arguments)]
fn reveal_at(
    node: &mut Node,
    objective: &Objective,
    submitter: &str,
    artifact: Value,
    nonce: &str,
    cites: Vec<String>,
    ts: &str,
) -> Result<Outcome, RuleViolation> {
    let claim = Claim::new(objective.id(), submitter, artifact, nonce, TS, cites)
        .expect("structurally valid claim");
    node.reveal(&claim, ts)
}

fn settlements_for(node: &Node, objective_id: &str) -> Vec<Value> {
    node.ledger()
        .entries_of_kind("settlement")
        .into_iter()
        .filter(|entry| {
            entry.payload.get("objective_id").and_then(Value::as_str) == Some(objective_id)
        })
        .map(|entry| entry.payload.clone())
        .collect()
}

fn field<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

fn assert_clean(problems: &[String]) {
    assert!(
        problems.is_empty(),
        "expected an honest log, got {problems:?}"
    );
}

fn assert_reports(problems: &[String], needle: &str) {
    assert!(
        problems.iter().any(|p| p.contains(needle)),
        "no problem mentioned {needle:?}: {problems:?}"
    );
}

// ---------------------------------------------------------------------------
// Settlement
// ---------------------------------------------------------------------------

#[test]
fn an_accepted_claim_settles_for_the_whole_pool() {
    let (_dir, mut node, objective) = certificate_env("accept", CHECKER);
    let outcome = submit(&mut node, &objective, "alice", n(42), "n1", vec![]).expect("reveal");

    assert_eq!(outcome.verdict.status, Status::Accept);
    assert!(outcome.settled);
    assert_eq!(outcome.reward, 1000);

    let settlement = node.settlement_of(&objective.id()).expect("a settlement");
    assert_eq!(field(&settlement, "submitter"), Some("alice"));
    assert_eq!(
        settlement.get("reward").and_then(Value::as_u64),
        Some(1000),
        "the log records the amount, not just the fact"
    );
}

#[test]
fn a_rejected_claim_does_not_settle() {
    // A rejection is a real verdict about the artifact, so it is recorded -- but
    // it moves nothing and leaves the objective open for a correct answer.
    let (_dir, mut node, objective) = certificate_env("reject", CHECKER);
    let outcome = submit(&mut node, &objective, "mallory", n(41), "n1", vec![]).expect("reveal");

    assert_eq!(outcome.verdict.status, Status::Reject);
    assert!(!outcome.settled);
    assert_eq!(outcome.reward, 0);
    assert!(node.settlement_of(&objective.id()).is_none());
    assert_eq!(
        node.ledger().entries_of_kind("verdict").len(),
        1,
        "the failed attempt leaves the same evidence trail as a winning one"
    );
}

#[test]
fn an_objective_settles_only_once() {
    let (_dir, mut node, objective) = certificate_env("once", CHECKER);
    submit(&mut node, &objective, "alice", n(42), "a", vec![]).expect("reveal");
    assert_eq!(settlements_for(&node, &objective.id()).len(), 1);
}

// ---------------------------------------------------------------------------
// Commit / reveal
// ---------------------------------------------------------------------------

#[test]
fn a_reveal_without_a_commitment_is_refused() {
    // Otherwise an observer copies a revealed artifact out of the mempool and
    // submits it as their own: the solver does the work, someone else collects.
    let (_dir, mut node, objective) = certificate_env("no-commit", CHECKER);
    let error = reveal_only(&mut node, &objective, "eve", n(42), "n1", vec![])
        .expect_err("must be refused");

    assert!(matches!(error, RuleViolation::NoMatchingCommitment));
    assert!(error.to_string().contains("commitment"), "{error}");
    assert!(
        node.ledger().entries_of_kind("claim").is_empty(),
        "a refusal is not a fact about anybody's work, so it records nothing"
    );
}

#[test]
fn a_commitment_does_not_transfer_between_submitters() {
    // Eve saw alice's commitment go by. The submitter is bound into the hash, so
    // she cannot open it under her own name.
    let (_dir, mut node, objective) = certificate_env("transfer", CHECKER);
    let artifact = n(42);
    let hash = commitment_hash(&objective.id(), "alice", &artifact, "n1");
    node.commit(&Commitment::new(objective.id(), "alice", hash, TS), TS)
        .expect("commit");

    let error = reveal_only(&mut node, &objective, "eve", artifact, "n1", vec![])
        .expect_err("must be refused");
    assert!(matches!(error, RuleViolation::NoMatchingCommitment));
}

#[test]
fn a_wrong_nonce_does_not_match_the_commitment() {
    // The nonce is what stops a guessable artifact -- `{"n": 42}` is the whole
    // search space here -- from being brute-forced out of a commitment before it
    // is revealed. A claim that cannot reproduce the exact preimage is not the
    // claim that was committed to.
    let (_dir, mut node, objective) = certificate_env("nonce", CHECKER);
    let artifact = n(42);
    let hash = commitment_hash(&objective.id(), "alice", &artifact, "right");
    node.commit(&Commitment::new(objective.id(), "alice", hash, TS), TS)
        .expect("commit");

    let error = reveal_only(&mut node, &objective, "alice", artifact, "wrong", vec![])
        .expect_err("must be refused");
    assert!(matches!(error, RuleViolation::NoMatchingCommitment));
}

#[test]
fn a_duplicate_artifact_verifies_but_mints_nothing() {
    // Novelty is necessary, never sufficient. Both parties commit while the
    // objective is open (the realistic race); alice reveals first and settles,
    // and bob's identical artifact then verifies for a payout of zero.
    let (_dir, mut node, objective) = certificate_env("duplicate", CHECKER);
    let artifact = n(42);
    for (who, nonce) in [("alice", "a"), ("bob", "b")] {
        commit_at(&mut node, &objective, who, &artifact, nonce, &stamp(0));
    }

    // Alice reveals into epoch 1 and its batch pays her when epoch 2 opens.
    // Bob reveals into epoch 2 -- a later epoch, deliberately, so that "who was
    // first" is settled by the batches rather than by the beacon ordering
    // inside one of them, which is what a same-epoch race would test instead.
    let first = reveal_at(
        &mut node,
        &objective,
        "alice",
        artifact.clone(),
        "a",
        vec![],
        &stamp(epoch()),
    )
    .expect("reveal");
    assert!(first.is_pending(), "{}", first.note);
    let first = node
        .settle_at(&stamp(2 * epoch()))
        .expect("close the batch")
        .into_iter()
        .find(|candidate| candidate.claim_id == first.claim_id)
        .expect("alice's claim is in the batch");
    assert!(first.settled);
    assert_eq!(first.reward, 1000);

    let second = reveal_at(
        &mut node,
        &objective,
        "bob",
        artifact,
        "b",
        vec![],
        &stamp(2 * epoch()),
    )
    .expect("reveal");
    let second = node
        .settle_at(&stamp(3 * epoch()))
        .expect("close the batch")
        .into_iter()
        .find(|candidate| candidate.claim_id == second.claim_id)
        .expect("bob's claim is in the batch");
    assert_eq!(
        second.verdict.status,
        Status::Accept,
        "the copy is a correct answer; that is not the same as a novel one"
    );
    assert!(!second.settled);
    assert_eq!(second.reward, 0);
    assert!(second.note.contains("duplicate"), "{}", second.note);

    assert_eq!(settlements_for(&node, &objective.id()).len(), 1);
    assert_clean(&node.audit(true));
}

#[test]
fn commitments_are_refused_once_an_objective_is_settled() {
    let (_dir, mut node, objective) = certificate_env("closed", CHECKER);
    submit(&mut node, &objective, "alice", n(42), "a", vec![]).expect("reveal");

    let hash = commitment_hash(&objective.id(), "bob", &n(42), "b");
    let error = node
        .commit(&Commitment::new(objective.id(), "bob", hash, TS), TS)
        .expect_err("must be refused");
    assert!(matches!(error, RuleViolation::AlreadySettled { .. }));
    assert!(error.to_string().contains("already settled"), "{error}");
}

#[test]
fn citations_must_point_at_accepted_claims() {
    // Citations point backwards only. Otherwise attribution flow can be aimed at
    // anything, including a claim invented for the purpose of receiving it.
    let (_dir, mut node, objective) = certificate_env("citations", CHECKER);
    let invented = format!("sha256:{}", "0".repeat(64));
    let error = submit(
        &mut node,
        &objective,
        "alice",
        n(42),
        "n1",
        vec![invented.clone()],
    )
    .expect_err("must be refused");

    assert!(matches!(&error, RuleViolation::UnknownCitation { claim_id } if claim_id == &invented));
    assert!(error.to_string().contains("citation"), "{error}");
}

// ---------------------------------------------------------------------------
// What may be posted at all
// ---------------------------------------------------------------------------

#[test]
fn an_objective_with_no_registered_verifier_is_refused() {
    // An objective whose verifier cannot run is an objective whose payout is
    // somebody's opinion, and admitting one is how a results market turns into a
    // popularity contest.
    let dir = TempDir::new("vibes");
    let mut node = node_at(&dir);
    let bad = Objective::new(
        "G",
        "vibes",
        Value::object([("kind", Value::string("looks_good_to_me"))]),
        1,
        "t",
        TS,
        None,
        None,
    )
    .expect("structurally valid objective");

    let error = node.post_objective(&bad, TS).expect_err("must be refused");
    assert!(matches!(error, RuleViolation::UnknownVerifierKind { .. }));
    assert!(error.to_string().contains("no verifier"), "{error}");
    assert!(node.ledger().is_empty(), "a refusal records nothing");
}

#[test]
fn objective_identity_includes_its_verifier() {
    // Editing an evaluator forks the objective rather than silently rescoring
    // work already done against it. There is no "change the rules mid-bounty"
    // operation to guard, because the edit produces a different objective.
    let build = |threshold: i128, ratchet: Option<Value>| {
        Objective::new(
            "G",
            "s",
            Value::object([
                ("kind", Value::string("evaluator")),
                ("threshold", Value::Int(threshold)),
            ]),
            1,
            "t",
            TS,
            None,
            ratchet,
        )
        .expect("structurally valid objective")
    };

    assert_ne!(
        build(10, None).id(),
        build(11, None).id(),
        "a moved threshold is a different question"
    );

    let ratchet = Value::object([
        ("baseline", Value::Int(0)),
        ("target", Value::Int(10)),
        ("reward", Value::Int(1)),
    ]);
    assert_ne!(
        build(10, None).id(),
        build(10, Some(ratchet)).id(),
        "the payout curve is part of what the objective promises"
    );
}

#[test]
fn a_ratchet_needs_a_score_producing_verifier() {
    // There is no curve to pay along if nothing produces a number.
    let dir = TempDir::new("ratchet-kind");
    let mut node = node_at(&dir);
    let objective = Objective::new(
        "G",
        "prove it",
        Value::object([
            ("kind", Value::string("lean")),
            ("statement", Value::string("theorem t : True")),
        ]),
        100,
        "t",
        TS,
        None,
        Some(Value::object([
            ("baseline", Value::Int(0)),
            ("target", Value::Int(10)),
            ("reward", Value::Int(100)),
        ])),
    )
    .expect("structurally valid objective");

    let error = node
        .post_objective(&objective, TS)
        .expect_err("must be refused");
    assert!(matches!(error, RuleViolation::RatchetNeedsEvaluator { .. }));
    assert!(error.to_string().contains("score-producing"), "{error}");
}

#[test]
fn ratchet_and_objective_rewards_must_agree() {
    // One pool, not two. An objective that advertises one number while paying
    // along a curve scaled to another is a lie the log would faithfully record.
    let dir = TempDir::new("two-pools");
    let sha = write_pinned(&dir, "e.py", EVALUATOR);
    let mut node = node_at(&dir);
    let objective = Objective::new(
        "G",
        "s",
        Value::object([
            ("kind", Value::string("evaluator")),
            ("evaluator", Value::string("e.py")),
            ("evaluator_sha256", Value::string(sha.as_str())),
            ("entrypoint", Value::string("score")),
            ("threshold", Value::Int(0)),
        ]),
        100,
        "t",
        TS,
        None,
        Some(Value::object([
            ("baseline", Value::Int(0)),
            ("target", Value::Int(10)),
            ("reward", Value::Int(999)),
        ])),
    )
    .expect("structurally valid objective");

    let error = node
        .post_objective(&objective, TS)
        .expect_err("must be refused");
    assert!(matches!(
        error,
        RuleViolation::RatchetRewardMismatch {
            ratchet: 999,
            objective: 100
        }
    ));
    assert!(error.to_string().contains("one pool"), "{error}");
}

// ---------------------------------------------------------------------------
// Unavailable never closes an objective
// ---------------------------------------------------------------------------

#[test]
fn an_absent_toolchain_leaves_the_objective_open() {
    // The failure mode this prevents: take verifiers offline and every honest
    // submission "fails". An absent Lean toolchain says nothing about the proof,
    // so it must not close a funded objective.
    let dir = TempDir::new("no-lean");
    let mut node = node_at(&dir);
    let objective = Objective::new(
        "G",
        "prove it",
        Value::object([
            ("kind", Value::string("lean")),
            ("statement", Value::string("theorem t : True")),
        ]),
        10,
        "t",
        TS,
        None,
        None,
    )
    .expect("valid objective");
    node.post_objective(&objective, TS).expect("post");

    let outcome = submit(
        &mut node,
        &objective,
        "alice",
        proof(":= by trivial"),
        "n1",
        vec![],
    )
    .expect("reveal");

    assert_eq!(outcome.verdict.status, Status::Unavailable);
    assert!(!outcome.verdict.settles());
    assert!(!outcome.settled);
    assert_eq!(outcome.reward, 0);
    assert!(node.settlement_of(&objective.id()).is_none());

    // Still open: a node that *can* run the check may still settle it.
    let hash = commitment_hash(&objective.id(), "bob", &proof(":= by trivial"), "n2");
    assert!(node
        .commit(&Commitment::new(objective.id(), "bob", hash, TS), TS)
        .is_ok());
}

#[test]
fn a_missing_pinned_checker_leaves_the_objective_open() {
    // Same rule, different infrastructure failure: a checker file this node
    // cannot read means this node cannot verify. It says nothing about the
    // artifact, so it is Unavailable and not a rejection.
    let dir = TempDir::new("no-checker");
    let mut node = node_at(&dir);
    let objective = Objective::new(
        "G",
        "find n = 42",
        certificate_verifier("nope.py", &"0".repeat(64)),
        1000,
        "treasury",
        TS,
        None,
        None,
    )
    .expect("valid objective");
    node.post_objective(&objective, TS).expect("post");

    let outcome = submit(&mut node, &objective, "alice", n(42), "n1", vec![]).expect("reveal");
    assert_eq!(outcome.verdict.status, Status::Unavailable);
    assert!(!outcome.settled);
    assert!(node.settlement_of(&objective.id()).is_none());
    assert_eq!(
        node.ledger().entries_of_kind("verdict").len(),
        1,
        "what happened is recorded even though nothing moved"
    );
}

// ---------------------------------------------------------------------------
// The audit
// ---------------------------------------------------------------------------

#[test]
fn audit_passes_on_an_honest_log() {
    let (_dir, mut node, objective) = certificate_env("honest", CHECKER);
    submit(&mut node, &objective, "alice", n(42), "n1", vec![]).expect("reveal");
    assert_clean(&node.audit(true));
}

#[test]
fn audit_catches_a_settled_claim_that_can_no_longer_be_re_verified() {
    // Someone swaps the checker after the fact, so its pinned hash no longer
    // matches and the ACCEPT cannot be re-derived. Reporting "log verified" here
    // would be a lie of omission -- nothing was actually checked.
    let (dir, mut node, objective) = certificate_env("swapped", CHECKER);
    submit(&mut node, &objective, "alice", n(42), "n1", vec![]).expect("reveal");
    assert_clean(&node.audit(true));

    fs::write(dir.file("c.py"), CHECKER_EDITED).expect("swap the checker");

    let problems = node.audit(true);
    assert_reports(&problems, "can no longer be re-verified");
}

#[test]
fn audit_flags_a_settled_claim_that_now_fails_verification() {
    // A verifier whose behaviour depends on unpinned external state passes today
    // and fails tomorrow at the same hash. Pinning source is necessary and not
    // sufficient: a verifier must also be pure. The audit is what surfaces it.
    let (dir, mut node, objective) = certificate_env("impure", IMPURE_CHECKER);
    fs::write(dir.file("threshold.txt"), "42").expect("write the unpinned state");

    let outcome = submit(&mut node, &objective, "alice", n(42), "n1", vec![]).expect("reveal");
    assert!(outcome.settled, "{:?}", outcome.verdict);
    assert_clean(&node.audit(true));

    fs::write(dir.file("threshold.txt"), "43").expect("move the goalposts");

    let problems = node.audit(true);
    assert_reports(&problems, "re-verification says reject");
}

#[test]
fn a_posted_objective_cannot_be_edited() {
    // Content addressing makes tampering with a funded objective self-defeating
    // rather than merely detectable: the edited record hashes differently, so it
    // is a *different* objective and the claims against the original no longer
    // resolve. The chain check reports the edit outright.
    let (dir, mut node, objective) = certificate_env("edit", CHECKER);
    submit(&mut node, &objective, "alice", n(42), "n1", vec![]).expect("reveal");
    drop(node); // one sequencer per log: finish with this handle before reopening

    let path = dir.file("log.jsonl");
    let original = fs::read_to_string(&path).expect("the log is readable");
    let edited: Vec<String> = original
        .lines()
        .map(|line| {
            if line.contains("\"kind\":\"objective\"") || line.contains("\"kind\": \"objective\"") {
                inflate_reward(line)
            } else {
                line.to_string()
            }
        })
        .collect();
    fs::write(&path, format!("{}\n", edited.join("\n"))).expect("the log is writable");

    let reopened = Node::new(
        Ledger::open(&path).expect("the edited log still parses"),
        &dir.path,
    );
    let problems = reopened.audit(false);
    assert_reports(&problems, "hash mismatch");
}

/// Rewrite an objective entry's reward, the way a dishonest operator would.
///
/// Both whitespace spellings are handled because nothing hashes the separators:
/// this crate writes canonical (compact) JSON and the reference implementation
/// writes `json.dumps` defaults, and the test must not depend on which one wrote
/// the file it is tampering with.
fn inflate_reward(line: &str) -> String {
    for spelling in ["\"reward\":1000", "\"reward\": 1000"] {
        if let Some(at) = line.find(spelling) {
            let mut edited = String::from(&line[..at]);
            edited.push_str("\"reward\":1000000000");
            edited.push_str(&line[at + spelling.len()..]);
            return edited;
        }
    }
    panic!("the objective entry does not carry a reward of 1000: {line}");
}

// ---------------------------------------------------------------------------
// The ratchet: the mechanism that makes publishing safe
// ---------------------------------------------------------------------------

#[test]
fn the_first_improvement_advances_the_frontier() {
    let (_dir, mut node, objective) = ratchet_env("first");
    let outcome = submit(&mut node, &objective, "alice", scored(40), "n1", vec![]).expect("reveal");

    assert!(outcome.settled, "{:?}", outcome.verdict);
    assert_eq!(outcome.reward, 400_000, "40% of the curve, 40% of the pool");
    let frontier = node.frontier_of(&objective.id()).expect("a frontier");
    assert_eq!(frontier.holder, "alice");
    assert_eq!(frontier.score, 40);
    assert_eq!(frontier.paid_cumulative, 400_000);
}

#[test]
fn a_second_improvement_pays_only_the_delta() {
    let (_dir, mut node, objective) = ratchet_env("delta");
    let first = submit(&mut node, &objective, "alice", scored(40), "n1", vec![]).expect("reveal");
    let second = submit(
        &mut node,
        &objective,
        "bob",
        scored(65),
        "n2",
        vec![first.claim_id.clone()],
    )
    .expect("reveal");

    assert_eq!(
        second.reward, 250_000,
        "distance moved, not distance reached"
    );
    let frontier = node.frontier_of(&objective.id()).expect("a frontier");
    assert_eq!(frontier.holder, "bob");
    assert_eq!(frontier.paid_cumulative, 650_000);
}

#[test]
fn an_improvement_must_cite_the_frontier() {
    // Mechanical attribution: you improved on the public frontier, so you cite
    // it, and citation flow pays its holder without anyone exercising judgement.
    // This is what makes "standing on shoulders" a submission rule rather than
    // an etiquette anyone can ignore.
    let (_dir, mut node, objective) = ratchet_env("must-cite");
    submit(&mut node, &objective, "alice", scored(40), "n1", vec![]).expect("reveal");

    let error = submit(&mut node, &objective, "bob", scored(65), "n2", vec![])
        .expect_err("must be refused");
    assert!(matches!(
        error,
        RuleViolation::MissingFrontierCitation { .. }
    ));
    assert!(
        error.to_string().contains("must cite the frontier"),
        "{error}"
    );
}

#[test]
fn copying_the_frontier_earns_nothing() {
    // The reason publishing is safe: a copied artifact moves the frontier zero
    // and pays zero, so hoarding buys nothing. Note this is *not* a rejection --
    // the artifact verified fine. It simply moved nothing.
    let (_dir, mut node, objective) = ratchet_env("copy");
    let first = submit(&mut node, &objective, "alice", scored(40), "n1", vec![]).expect("reveal");
    let copied = submit(
        &mut node,
        &objective,
        "eve",
        scored(40),
        "n2",
        vec![first.claim_id.clone()],
    )
    .expect("reveal");

    assert_eq!(copied.verdict.status, Status::Accept);
    assert!(!copied.settled);
    assert_eq!(copied.reward, 0);
    assert!(copied.note.contains("does not improve"), "{}", copied.note);
    assert_eq!(
        node.frontier_of(&objective.id())
            .expect("a frontier")
            .holder,
        "alice"
    );
}

#[test]
fn a_worse_result_does_not_take_the_frontier() {
    let (_dir, mut node, objective) = ratchet_env("worse");
    let first = submit(&mut node, &objective, "alice", scored(60), "n1", vec![]).expect("reveal");
    let worse = submit(
        &mut node,
        &objective,
        "bob",
        scored(30),
        "n2",
        vec![first.claim_id.clone()],
    )
    .expect("reveal");

    assert!(!worse.settled);
    assert_eq!(worse.reward, 0);
    let frontier = node.frontier_of(&objective.id()).expect("a frontier");
    assert_eq!(frontier.score, 60);
    assert_eq!(frontier.holder, "alice");
}

#[test]
fn the_pool_is_exactly_exhausted_at_the_target() {
    // Someone submitting many small improvements must not extract more than
    // someone submitting one large one. The payouts telescope.
    let (_dir, mut node, objective) = ratchet_env("exhaust");
    let mut previous: Option<String> = None;
    let mut total: u64 = 0;
    let mut last_note = String::new();

    for (who, score) in [("alice", 20), ("bob", 55), ("carol", 90), ("dave", 100)] {
        let cites: Vec<String> = previous.clone().into_iter().collect();
        let outcome = submit(
            &mut node,
            &objective,
            who,
            scored(score),
            &format!("n-{who}"),
            cites,
        )
        .expect("reveal");
        assert!(outcome.settled, "{who}: {:?}", outcome.verdict);
        total = total.checked_add(outcome.reward).expect("no overflow");
        last_note = outcome.note.clone();
        previous = Some(outcome.claim_id);
    }

    assert_eq!(total, 1_000_000, "the pool, exactly");
    assert!(last_note.contains("pool exhausted"), "{last_note}");
    assert_clean(&node.audit(true));
}

#[test]
fn a_progressive_objective_accepts_many_settlements() {
    // "Settled once" is the wrong invariant for an objective that pays along a
    // curve, and the audit knows it.
    let (_dir, mut node, objective) = ratchet_env("many");
    let first = submit(&mut node, &objective, "alice", scored(30), "n1", vec![]).expect("reveal");
    submit(
        &mut node,
        &objective,
        "bob",
        scored(70),
        "n2",
        vec![first.claim_id.clone()],
    )
    .expect("reveal");

    assert_eq!(settlements_for(&node, &objective.id()).len(), 2);
    assert_clean(&node.audit(true));
}

#[test]
fn audit_rejects_an_overspent_pool() {
    // The invariant that replaces "settled once" for a progressive objective:
    // the pool is never overspent, whatever the operator writes into the log.
    let (_dir, mut node, objective) = ratchet_env("overspent");
    submit(&mut node, &objective, "alice", scored(100), "n1", vec![]).expect("reveal");
    let claim_id = node
        .frontier_of(&objective.id())
        .expect("a frontier")
        .claim_id;

    node.ledger_mut()
        .append(
            "settlement",
            Value::object([
                ("objective_id", Value::string(objective.id())),
                ("claim_id", Value::string(claim_id)),
                ("submitter", Value::string("eve")),
                ("reward", Value::Int(5_000_000)),
            ]),
            TS,
        )
        .expect("a hostile log is still a log");

    assert_reports(&node.audit(false), "against a pool of");
}

#[test]
fn audit_rejects_a_frontier_that_moves_backwards() {
    // The other progressive invariant: the frontier is a ratchet. An entry that
    // hands the objective to a worse score is caught by replay, not by trusting
    // the operator's arithmetic.
    let (_dir, mut node, objective) = ratchet_env("backwards");
    let first = submit(&mut node, &objective, "alice", scored(60), "n1", vec![]).expect("reveal");

    node.ledger_mut()
        .append(
            "frontier",
            Value::object([
                ("objective_id", Value::string(objective.id())),
                ("claim_id", Value::string(first.claim_id)),
                ("holder", Value::string("eve")),
                ("score", Value::Int(5)),
                ("paid_cumulative", Value::Int(600_000)),
            ]),
            TS,
        )
        .expect("a hostile log is still a log");

    assert_reports(&node.audit(false), "without improving");
}

// ---------------------------------------------------------------------------
// Ratchet arithmetic, through the public API
// ---------------------------------------------------------------------------

fn maximize(baseline: i64, target: i64, reward: u64) -> Ratchet {
    Ratchet::new(baseline, target, reward, Direction::Maximize, 1).expect("valid ratchet")
}

#[test]
fn payouts_telescope_to_the_pool_however_the_curve_is_chopped() {
    // Someone submitting 100 one-point improvements must not extract more than
    // someone submitting a single 100-point improvement.
    let one_at_a_time: Vec<i64> = (1..=100).collect();
    for reward in [1u64, 7, 999, 1_000_000, 1_000_000_007] {
        for steps in [
            vec![5, 17, 40, 41, 88, 100],
            vec![50, 100],
            one_at_a_time.clone(),
        ] {
            let r = maximize(0, 100, reward);
            let mut total: u64 = 0;
            let mut previous: Option<i64> = None;
            for score in steps {
                total = total
                    .checked_add(r.payout(previous, score).expect("payout"))
                    .expect("the running total cannot exceed the pool");
                previous = Some(score);
            }
            assert_eq!(total, reward, "reward {reward}");
        }
    }
}

#[test]
fn the_curve_is_clamped_at_both_ends() {
    // Overshooting mints no progress the pool cannot fund, and work below the
    // baseline is not negative progress that could claw money back.
    let r = maximize(0, 10, 1000);
    assert_eq!(r.payout(None, 10).expect("payout"), 1000);
    assert_eq!(r.payout(None, 10_000).expect("payout"), 1000);
    assert_eq!(r.payout(Some(10), 10_000).expect("payout"), 0);

    let above = maximize(50, 100, 1000);
    assert_eq!(above.payout(None, 10).expect("payout"), 0);
    assert_eq!(above.payout(None, 50).expect("payout"), 0);
    assert_eq!(above.payout(None, 75).expect("payout"), 500);

    // A regression pays zero rather than clawing back: the log is append-only
    // and money already settled cannot be unsettled, so zero is the only floor.
    let back = maximize(0, 100, 1000);
    assert_eq!(back.payout(Some(80), 20).expect("payout"), 0);
    assert!(!back.improves(Some(80), 20));
}

#[test]
fn minimizing_pays_for_moving_down() {
    let r = Ratchet::new(100, 0, 1000, Direction::Minimize, 1).expect("valid ratchet");
    assert_eq!(r.payout(None, 50).expect("payout"), 500);
    assert_eq!(r.payout(Some(50), 25).expect("payout"), 250);
    assert!(!r.improves(Some(50), 75));
}

#[test]
fn min_improvement_blocks_epsilon_farming() {
    // A real tradeoff, not a free win: raising it also blocks genuine small
    // gains. What it buys is that a thousand one-unit resubmissions cannot
    // monopolise the citation graph.
    let r = Ratchet::new(0, 1000, 1000, Direction::Maximize, 10).expect("valid ratchet");
    assert!(!r.improves(Some(100), 105));
    assert!(r.improves(Some(100), 110));
}

#[test]
fn a_huge_pool_does_not_overflow_the_payout() {
    // `reward * progress` overflows u64 for realistic values -- this is the bug
    // class Python's bignums hid. The product is formed in u128 and the result
    // is checked, so the arithmetic either is exact or is refused.
    let r = maximize(0, 1_000_000, u64::MAX);
    assert_eq!(r.cumulative(1_000_000).expect("cumulative"), u64::MAX);
    let half = r.cumulative(500_000).expect("cumulative");
    assert_eq!(half, u64::MAX / 2);
    assert_eq!(
        r.payout(Some(500_000), 1_000_000).expect("payout"),
        u64::MAX - half
    );
}

#[test]
fn invalid_ratchets_are_refused() {
    // Two of the reference implementation's four cases are unrepresentable here
    // rather than checked: a negative reward cannot be built at all (`u64`), and
    // a direction outside the two known spellings only exists on the wire.
    assert_eq!(
        Ratchet::new(100, 10, 1, Direction::Maximize, 1),
        Err(RatchetError::TargetNotAboveBaseline {
            baseline: 100,
            target: 10
        }),
        "no distance to move means a division by a zero or negative span"
    );
    assert_eq!(
        Ratchet::new(0, 10, 1, Direction::Maximize, 0),
        Err(RatchetError::MinImprovementTooSmall),
        "a ratchet that accepts a zero-sized improvement pays for standing still"
    );

    let sideways = Ratchet::from_value(&Value::object([
        ("baseline", Value::Int(0)),
        ("target", Value::Int(10)),
        ("reward", Value::Int(1)),
        ("direction", Value::string("sideways")),
    ]));
    assert!(matches!(
        sideways,
        Err(RatchetError::UnknownDirection { .. })
    ));

    let negative = Ratchet::from_value(&Value::object([
        ("baseline", Value::Int(0)),
        ("target", Value::Int(10)),
        ("reward", Value::Int(-1)),
    ]));
    assert!(matches!(
        negative,
        Err(RatchetError::RewardOutOfRange { .. })
    ));
}

// ---------------------------------------------------------------------------
// Verifier statuses
// ---------------------------------------------------------------------------

fn registry(root: impl Into<PathBuf>) -> VerifierRegistry {
    VerifierRegistry::new(root).with_lean_binary(NO_LEAN)
}

fn lean_spec() -> Value {
    Value::object([
        ("kind", Value::string("lean")),
        ("statement", Value::string("theorem t : True")),
    ])
}

#[test]
fn only_accept_and_reject_settle() {
    // Everything else in the verifier module is in service of keeping this
    // predicate honest. If an infrastructure failure could reach Reject, an
    // attacker who can break verifiers can fail every honest submission.
    assert!(Status::Accept.settles());
    assert!(Status::Reject.settles());
    assert!(!Status::Unavailable.settles());
    assert!(!Status::InvalidSpec.settles());
}

#[test]
fn lean_rejects_sorry_without_needing_a_toolchain() {
    // Checked before Lean runs: `sorry` compiles and proves nothing. The screen
    // is a fact about the submitted text, not about this node, so rejecting on a
    // machine with no Lean installed is sound.
    let dir = TempDir::new("sorry");
    let verdict = registry(&dir.path).run(&lean_spec(), &proof(":= by sorry"));
    assert_eq!(verdict.status, Status::Reject);
    assert!(verdict.detail.contains("sorry"), "{}", verdict.detail);
}

#[test]
fn lean_rejects_the_other_escape_hatches() {
    // Each of these produces a file the kernel accepts while proving nothing, or
    // proves it by a route outside the kernel. `native_decide` trusts the
    // compiler and runtime instead of the kernel, which is a different trust
    // assumption than the one the objective advertised.
    let dir = TempDir::new("hatches");
    let registry = registry(&dir.path);
    for text in [
        ":= by admit",
        ":= by native_decide",
        "axiom cheat : True",
        "@[implemented_by cheat] def f := 1",
    ] {
        let verdict = registry.run(&lean_spec(), &proof(text));
        assert_eq!(verdict.status, Status::Reject, "{text}: {}", verdict.detail);
    }
}

#[test]
fn lean_allows_native_decide_when_the_objective_opts_in() {
    let dir = TempDir::new("opt-in");
    let spec = Value::object([
        ("kind", Value::string("lean")),
        ("statement", Value::string("theorem t : True")),
        ("allow_native_decide", Value::Bool(true)),
    ]);
    let verdict = registry(&dir.path).run(&spec, &proof(":= by native_decide"));
    // It passes the pre-screen; with no toolchain here the verdict is then
    // Unavailable, which is the point -- it is no longer a Reject.
    assert_ne!(verdict.status, Status::Reject);
    assert!(!verdict.settles());
}

#[test]
fn a_missing_lean_toolchain_is_unavailable_not_a_rejection() {
    let dir = TempDir::new("no-toolchain");
    let verdict = registry(&dir.path).run(&lean_spec(), &proof(":= by trivial"));
    assert_eq!(verdict.status, Status::Unavailable);
    assert!(!verdict.settles());
}

#[test]
fn lean_needs_a_statement_from_the_objective() {
    // The statement comes from the objective, never the submitter -- otherwise a
    // submitter proves an easier theorem and collects.
    let dir = TempDir::new("no-statement");
    let verdict = registry(&dir.path).run(
        &Value::object([("kind", Value::string("lean"))]),
        &proof(":= by trivial"),
    );
    assert_eq!(verdict.status, Status::InvalidSpec);
    assert!(!verdict.settles());
}

#[test]
fn replay_refuses_machine_dependent_reproducible_fields() {
    // A cost claim denominated in seconds is a claim about somebody's hardware
    // and cannot be settled by re-execution: two honest nodes disagree about it
    // by construction. Refused as a spec defect, before anything is run.
    let dir = TempDir::new("machine-dependent");
    let registry = registry(&dir.path);
    for name in [
        "wall_clock_seconds",
        "peak_memory",
        "elapsed",
        "flops",
        "rss_bytes",
        "timestamp",
    ] {
        let spec = Value::object([
            ("kind", Value::string("replay")),
            ("command", Value::array([Value::string("true")])),
            ("reproducible_fields", Value::array([Value::string(name)])),
        ]);
        let verdict = registry.run(&spec, &Value::object([("results", empty())]));
        assert_eq!(verdict.status, Status::InvalidSpec, "{name}");
        assert!(!verdict.settles(), "{name}");
    }
}

#[test]
fn an_edited_checker_invalidates_the_spec_rather_than_silently_rescoring() {
    // The hash is part of the objective's identity. Editing a checker forks the
    // objective; it does not rescore work already submitted against the old one.
    // A tampered checker is never executed.
    let dir = TempDir::new("edited-pin");
    let sha = write_pinned(&dir, "c.py", CHECKER);
    fs::write(dir.file("c.py"), CHECKER_EDITED).expect("swap the checker");

    let verdict = registry(&dir.path).run(&certificate_verifier("c.py", &sha), &n(43));
    assert_eq!(verdict.status, Status::InvalidSpec);
    assert!(!verdict.settles());
}

#[test]
fn a_pinned_path_cannot_escape_the_objective_root() {
    let dir = TempDir::new("escape");
    let verdict = registry(&dir.path).run(
        &certificate_verifier("../outside.py", &"0".repeat(64)),
        &empty(),
    );
    assert!(
        matches!(verdict.status, Status::InvalidSpec | Status::Unavailable),
        "{:?}",
        verdict
    );
    assert!(!verdict.settles());
}

#[test]
fn an_unknown_verifier_kind_is_unavailable_and_a_kindless_spec_is_invalid() {
    // Unknown kind is Unavailable, not InvalidSpec: another node, or a later
    // version of this crate, may well know that verifier. Saying "your objective
    // is broken" because *we* are old would be wrong. A spec with no kind at all
    // cannot be routed by anybody, so that one really is broken.
    let dir = TempDir::new("dispatch");
    let registry = registry(&dir.path);
    let empty = empty();
    assert_eq!(
        registry
            .run(
                &Value::object([("kind", Value::string("haruspicy"))]),
                &empty
            )
            .status,
        Status::Unavailable
    );
    assert_eq!(registry.run(&empty, &empty).status, Status::InvalidSpec);
}

// ---------------------------------------------------------------------------
// The shipped examples
// ---------------------------------------------------------------------------
//
// A broken example is a broken claim. These run the real Python checkers
// through the subprocess verifier against the repository as the objective
// bundle root, so they also prove the harness -- pin resolution, stdin framing,
// result parsing -- actually works.

fn example_path(name: &str, file: &str) -> PathBuf {
    Path::new(REPO_ROOT).join("examples").join(name).join(file)
}

fn load_value(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    Value::from_json(&text)
        .unwrap_or_else(|error| panic!("{} is not canonical JSON: {error}", path.display()))
}

fn example_objective(name: &str) -> Objective {
    Objective::from_value(&load_value(&example_path(name, "objective.json")))
        .unwrap_or_else(|error| panic!("examples/{name}/objective.json is malformed: {error}"))
}

#[test]
fn the_shipped_artifacts_verify() {
    let registry = VerifierRegistry::new(REPO_ROOT);
    for name in ["collatz", "capset"] {
        let objective = example_objective(name);
        let artifact = load_value(&example_path(name, "artifact.json"));
        let verdict = registry.run(&objective.verifier, &artifact);
        assert_eq!(verdict.status, Status::Accept, "{name}: {}", verdict.detail);
    }
}

#[test]
fn bogus_artifacts_are_rejected() {
    // The capset case is the important one: three collinear points are not a cap
    // set, and the evaluator must score it zero rather than crash. An invalid
    // submission is a bad artifact, not a broken verifier, and the distinction
    // decides whether the objective can be attacked by submitting garbage.
    let registry = VerifierRegistry::new(REPO_ROOT);
    let collinear = Value::object([(
        "points",
        Value::array([
            Value::array([Value::Int(0), Value::Int(0), Value::Int(0), Value::Int(0)]),
            Value::array([Value::Int(1), Value::Int(1), Value::Int(1), Value::Int(1)]),
            Value::array([Value::Int(2), Value::Int(2), Value::Int(2), Value::Int(2)]),
        ]),
    )]);

    for (name, bogus) in [("collatz", n(27)), ("capset", collinear)] {
        let objective = example_objective(name);
        let verdict = registry.run(&objective.verifier, &bogus);
        assert_eq!(verdict.status, Status::Reject, "{name}: {}", verdict.detail);
    }
}

#[test]
fn every_shipped_objective_pin_resolves() {
    // Whatever the artifact does, the *spec* itself must be well formed: a stale
    // pinned hash would surface as InvalidSpec, which is how a shipped example
    // rots without anybody noticing.
    let registry = VerifierRegistry::new(REPO_ROOT).with_lean_binary(NO_LEAN);
    let empty = empty();
    for name in ["collatz", "capset", "lean", "capset_progressive"] {
        let objective = example_objective(name);
        let verdict = registry.run(&objective.verifier, &empty);
        assert_ne!(
            verdict.status,
            Status::InvalidSpec,
            "{name}: {}",
            verdict.detail
        );
    }
}

#[test]
fn the_shipped_progressive_example_runs_end_to_end() {
    // The whole system in one test: a real objective, real pinned Python, three
    // real improvements, each citing the frontier it beat, paying exactly the
    // distance moved and exhausting the pool at the target -- then re-derived
    // from the log by an auditor who trusts none of it.
    let dir = TempDir::new("capset-progressive");
    let ledger = Ledger::open(dir.file("log.jsonl")).expect("empty log");
    let mut node = Node::new(ledger, REPO_ROOT);
    let objective = example_objective("capset_progressive");
    node.post_objective(&objective, TS).expect("post");

    let mut previous: Option<String> = None;
    let mut total: u64 = 0;
    let mut last = String::new();
    // Pool 1_100_000 over a span of 11 (baseline 9, target 20): 3/11, then 4/11,
    // then the last 4/11.
    for (who, file, score, expected) in [
        ("alice", "artifact-12.json", 12, 300_000u64),
        ("bob", "artifact-16.json", 16, 400_000),
        ("carol", "artifact-20.json", 20, 400_000),
    ] {
        let artifact = load_value(&example_path("capset_progressive", file));
        let cites: Vec<String> = previous.clone().into_iter().collect();
        let outcome = submit(&mut node, &objective, who, artifact, file, cites).expect("reveal");
        assert!(outcome.settled, "{who}: {:?}", outcome.verdict);
        assert_eq!(outcome.verdict.score(), Some(score), "{who}");
        assert_eq!(outcome.reward, expected, "{who}");
        total = total.checked_add(outcome.reward).expect("no overflow");
        last = outcome.note.clone();
        previous = Some(outcome.claim_id);
    }

    assert_eq!(total, 1_100_000, "the pool, exactly");
    assert!(last.contains("pool exhausted"), "{last}");
    assert_eq!(
        node.frontier_of(&objective.id())
            .expect("a frontier")
            .holder,
        "carol"
    );
    assert_clean(&node.audit(true));
}

// -- submitter identity ----------------------------------------------------

/// A key-shaped submitter is unforgeable; a nickname is unchanged.
///
/// `submitter` was a free string, so a name was worth nothing and citation
/// flow was paying whatever anyone typed. These are the four cases that
/// matter, and the last two are the ones an attacker actually tries.
#[test]
fn a_key_shaped_submitter_cannot_be_worn_by_anyone_else() {
    use proofwork::crypto::identity::Identity;
    use proofwork::records::{signed_submitter, Commitment};

    let alice = Identity::from_secret_bytes([7u8; 32]);
    let mallory = Identity::from_secret_bytes([9u8; 32]);
    let ts = "2026-07-28T00:00:00+00:00";

    // The name *is* the key, so no registry is consulted to know that.
    assert!(signed_submitter(&alice.submitter_id()).is_some());
    assert!(signed_submitter("alice").is_none());

    let unsigned = Commitment::new("sha256:obj", alice.submitter_id(), "sha256:h", ts);

    // 1. Wearing alice's name with no signature at all.
    assert!(
        unsigned.verify_signature().is_err(),
        "a key-shaped name was accepted unsigned"
    );

    // 2. Alice signing for herself.
    let signed = unsigned.clone().signed_with(&alice);
    signed.verify_signature().expect("alice's own signature");

    // 3. Mallory signing a record that claims to be alice. The signature is
    //    real -- it is just not hers, which is the whole attack.
    let mut forged = signed.clone();
    forged.signature = Some(mallory.sign_value(&forged.signing_payload()).to_hex());
    assert!(
        forged.verify_signature().is_err(),
        "mallory signed as alice and it was accepted"
    );

    // 4. Stealing alice's signature and attaching it to a different record.
    let mut moved = Commitment::new("sha256:other", alice.submitter_id(), "sha256:h", ts);
    moved.signature = signed.signature.clone();
    assert!(
        moved.verify_signature().is_err(),
        "a signature was replayed onto a different record"
    );

    // A nickname stays exactly as permissive as it was -- Stage 0 keeps
    // working, which is what makes this deployable without a migration.
    let nickname = Commitment::new("sha256:obj", "alice", "sha256:h", ts);
    nickname
        .verify_signature()
        .expect("nicknames are unchanged");
}

/// The rules engine refuses a forged identity before writing anything.
#[test]
fn the_node_refuses_an_unsigned_key_shaped_submitter() {
    use proofwork::crypto::identity::Identity;
    use proofwork::records::Commitment;

    let alice = Identity::from_secret_bytes([11u8; 32]);
    let ts = TS;
    let (_dir, mut node, objective) = certificate_env("identity-node", CHECKER);
    let objective_id = objective.id();

    let forged = Commitment::new(&objective_id, alice.submitter_id(), "sha256:h", ts);
    let before = node.ledger().len();
    let refused = node.commit(&forged, ts);
    assert!(
        refused.is_err(),
        "an unsigned key-shaped submitter committed"
    );
    assert_eq!(
        node.ledger().len(),
        before,
        "a refused commitment wrote to the log"
    );
    let message = refused.unwrap_err().to_string();
    assert!(message.contains("must carry a signature"), "{message}");

    // Signed by the key it names: admitted.
    let honest =
        Commitment::new(&objective_id, alice.submitter_id(), "sha256:h", ts).signed_with(&alice);
    node.commit(&honest, ts)
        .expect("a signed commitment is fine");
}

/// Signing changes the record's id, so a signature cannot be stripped from a
/// claim somebody already cited.
#[test]
fn a_signature_is_covered_by_the_record_id() {
    use proofwork::canonical::Value;
    use proofwork::crypto::identity::Identity;
    use proofwork::records::Claim;

    let alice = Identity::from_secret_bytes([13u8; 32]);
    let unsigned = Claim::new(
        "sha256:obj",
        alice.submitter_id(),
        Value::object([("n", Value::Int(1))]),
        "nonce",
        "2026-07-28T00:00:00+00:00",
        Vec::new(),
    )
    .expect("valid claim");
    let signed = unsigned.clone().signed_with(&alice);

    assert_ne!(
        unsigned.id(),
        signed.id(),
        "stripping the signature left the id unchanged, so it could be removed \
         from a claim other people already cited"
    );
    // And the signature covers the payload without itself, which is the only
    // way it could be produced at all.
    assert_eq!(unsigned.signing_payload(), signed.signing_payload());
}

/// A funder can demand signed identities, and the demand is enforced on both
/// halves of a submission.
#[test]
fn an_objective_can_refuse_nickname_submitters() {
    use proofwork::crypto::identity::Identity;
    use proofwork::records::Commitment;

    let dir = TempDir::new("requires-signed");
    let sha = write_pinned(&dir, "c.py", CHECKER);
    let mut node = node_at(&dir);
    let objective = Objective::new(
        "G",
        "find n = 42",
        certificate_verifier("c.py", &sha),
        1000,
        "treasury",
        TS,
        None,
        None,
    )
    .expect("valid objective")
    .requiring_signed_submitters();
    let objective_id = objective.id();
    node.post_objective(&objective, TS).expect("post");

    // A nickname is refused, and the message names the fix rather than only
    // the rule -- a contributor who has never made an identity needs to be
    // told how, not told no.
    let nickname = Commitment::new(&objective_id, "alice", "sha256:h", TS);
    let refused = node.commit(&nickname, TS).expect_err("nickname refused");
    let message = refused.to_string();
    assert!(message.contains("only signed identities"), "{message}");
    assert!(message.contains("proofwork identity"), "{message}");

    // A signed identity goes through.
    let alice = Identity::from_secret_bytes([17u8; 32]);
    let signed =
        Commitment::new(&objective_id, alice.submitter_id(), "sha256:h", TS).signed_with(&alice);
    node.commit(&signed, TS)
        .expect("a signed submitter is fine");
}

/// The flag is off by default and omitted when off, so adding it moved no ids.
#[test]
fn requiring_signed_submitters_is_off_by_default_and_omitted() {
    let plain = Objective::new(
        "G",
        "s",
        certificate_verifier("c.py", &"ab".repeat(32)),
        1000,
        "treasury",
        TS,
        None,
        None,
    )
    .expect("valid");
    assert!(!plain.require_signed_submitter);
    assert!(plain.to_value().get("require_signed_submitter").is_none());

    // Setting it is a different objective, exactly as changing the verifier
    // is: the admission rules are part of what was funded.
    let strict = plain.clone().requiring_signed_submitters();
    assert_ne!(plain.id(), strict.id());
    assert_eq!(
        strict.to_value().get("require_signed_submitter"),
        Some(&proofwork::canonical::Value::Bool(true))
    );

    // And it round-trips.
    let decoded = Objective::from_value(&strict.to_value()).expect("decodes");
    assert!(decoded.require_signed_submitter);
    assert_eq!(decoded.id(), strict.id());

    // A non-boolean is refused rather than coerced: "yes" meaning true here
    // and false in the reference is a split over what is admissible.
    let mut body = match plain.to_value() {
        proofwork::canonical::Value::Object(map) => map,
        _ => unreachable!(),
    };
    body.insert(
        "require_signed_submitter".to_string(),
        proofwork::canonical::Value::string("yes"),
    );
    assert!(Objective::from_value(&proofwork::canonical::Value::Object(body)).is_err());
}
