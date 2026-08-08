#!/usr/bin/env bash
# `proofwork try` and `proofwork scaffold`, end to end against a real clock.
#
#   ./scripts/try-demo.sh
#
# Two commands, checked here rather than in a unit test for the same reason
# `demo.sh` is: the epoch boundary they wait on is derived from record
# timestamps against a real clock, and a fixture timestamp cannot exercise it.
# A unit test of `try` would have to either sleep a production epoch or set
# `PROOFWORK_EPOCH_SECONDS` process-wide, which every other test in the binary
# would then be racing.
#
# What this proves that the unit tests cannot:
#
#   1. `try` really does the five steps -- post, commit, wait, reveal, settle --
#      and the reveal it produces lands in a strictly later epoch than its own
#      commitment. Get that wrong and the reveal is refused; there is no way to
#      pass this script with a fixed sleep that guessed the boundary wrong.
#   2. On a progressive objective, `try` cites the frontier. That citation is
#      mandatory, not a choice, so a wrapper that omitted it would fail every
#      improvement -- which is most of what a progressive objective is for.
#   3. A `scaffold`ed objective posts, and a submission against its stub comes
#      back `reject` with the stub's own detail. `reject` and not
#      `invalid_spec`: the generated spec has to be *complete*, or the scaffold
#      has handed somebody a bounty that can never settle.
set -euo pipefail
cd "$(dirname "$0")/.."

LOG="${1:-/tmp/proofwork-try-demo.jsonl}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
rm -f "$LOG"
PW="${PROOFWORK_BIN:-./target/release/proofwork}"
[ -x "$PW" ] || { echo "building release binary..." >&2; cargo build --release; }
pw() { "$PW" --log "$LOG" --root . "$@"; }

# One-second epochs, so the same rules play out in a script that finishes.
# Changes no canonical bytes: nothing derived from this enters a record.
export PROOFWORK_EPOCH_SECONDS=1

rule() { printf '\n\033[1m== %s\033[0m\n' "$1"; }
fail() { printf '\033[31mFAIL: %s\033[0m\n' "$1" >&2; exit 1; }

rule "one round in one command: post, commit, wait out the epoch, reveal, settle"
OUT=$(pw try examples/collatz/objective.json \
        --submitter alice --artifact examples/collatz/artifact.json --settle)
echo "$OUT"
echo "$OUT" | grep -q '^  verdict  accept' || fail "try did not reach an accepting verdict"
echo "$OUT" | grep -q '^  settled  true' || fail "try --settle did not settle the claim"

rule "the round really crossed an epoch boundary"
# The rule `try` exists to respect: a reveal must land in a strictly later
# epoch than its commitment. Read back out of the log rather than trusted.
python3 - "$LOG" <<'PY'
import json, os, sys

length = int(os.environ.get("PROOFWORK_EPOCH_SECONDS", "600"))


def unix(ts):
    # `+00:00` only -- every stamp this CLI writes is UTC.
    from datetime import datetime
    return int(datetime.fromisoformat(ts).timestamp())


# Keyed by (objective, submitter): a claim does not name the commitment it
# opens -- binding it is what the commitment hash is for -- so this is the
# pairing an outside reader has.
committed, claims = {}, []
with open(sys.argv[1]) as handle:
    for line in handle:
        entry = json.loads(line)
        payload = entry.get("payload", {})
        if entry.get("kind") == "commitment":
            key = (payload["objective_id"], payload["submitter"])
            epoch = unix(payload["created_at"]) // length
            committed[key] = min(epoch, committed.get(key, epoch))
        elif entry.get("kind") == "claim":
            claims.append(payload)

if not claims:
    sys.exit("no claim was appended")
for claim in claims:
    key = (claim["objective_id"], claim["submitter"])
    revealed = unix(claim["created_at"]) // length
    if key not in committed:
        sys.exit(f"claim by {key[1]} opens no commitment")
    if revealed <= committed[key]:
        sys.exit(
            f"claim by {key[1]} revealed in epoch {revealed}, "
            f"not strictly after its commitment in {committed[key]}"
        )
print(f"  {len(claims)} reveal(s), each strictly later than its own commitment")
PY

rule "a progressive objective: try cites the frontier without being told to"
PROG=$(pw post examples/capset_progressive/objective.json | head -1 | awk '{print $2}')
pw try "$PROG" --submitter alice --artifact examples/capset_progressive/artifact-12.json --settle
IMPROVE=$(pw try "$PROG" --submitter bob \
            --artifact examples/capset_progressive/artifact-16.json --settle)
echo "$IMPROVE"
echo "$IMPROVE" | grep -q '^  citing the frontier ' \
  || fail "try did not cite the frontier on an improvement"
echo "$IMPROVE" | grep -q '^  settled  true' \
  || fail "the improvement did not settle"

rule "pointing try at the same file again is the local iteration loop"
# An objective's id is the hash of its own content, so "already posted" means
# byte-identical: `try` uses the objective already in the log rather than
# refusing, which is what makes re-running it after editing an artifact work.
AGAIN=$(pw try examples/capset_progressive/objective.json --submitter carol \
          --artifact examples/capset_progressive/artifact-20.json --settle)
echo "$AGAIN"
echo "$AGAIN" | grep -q '^  already posted; using it' \
  || fail "try re-posted an objective already in the log instead of reusing it"
echo "$AGAIN" | grep -q '^  verdict  accept' || fail "the re-run did not verify"

rule "scaffold a challenge of every kind, and post each one"
for KIND in certificate evaluator statistical replay lean; do
  "$PW" --root "$WORK" scaffold "demo_$KIND" --kind "$KIND" \
      --reward 100 --funder treasury >/dev/null
  # `--root` is where a pin resolves; the file path is read from the working
  # directory. Two different things, and this is the one place they differ.
  "$PW" --log "$WORK/log.jsonl" --root "$WORK" \
      post "$WORK/examples/demo_$KIND/objective.json" >/dev/null \
    || fail "the scaffolded $KIND objective does not post"
  printf '  %s posts clean\n' "$KIND"
done

rule "the scaffolded checker runs, and rejects -- it does not fail as a bad spec"
STUB=$("$PW" --log "$WORK/stub.jsonl" --root "$WORK" \
        try "$WORK/examples/demo_certificate/objective.json" \
        --submitter alice --artifact "$WORK/examples/demo_certificate/artifact.json" || true)
echo "$STUB"
echo "$STUB" | grep -q '^  verdict  reject' \
  || fail "the scaffolded stub did not return a real reject (a spec defect settles nothing)"

printf '\n\033[32mTRY-DEMO OK: one command runs a round, and a scaffolded challenge is postable.\033[0m\n'
