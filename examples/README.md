# Worked objectives and open bounties

Writing a new one starts with `proofwork scaffold <name> --kind <kind>`, which
writes an `objective.json` with the fields that kind's verifier actually reads,
a stub already pinned by its own hash, and a placeholder artifact — in the
shape everything below uses. It posts nothing: funding a statement is a
decision a person makes after reading it. The generated stub rejects
everything, which is the safe direction for logic nobody has finished writing.

Every objective here has its verifier pinned by hash, so re-computing the pin
(`sha256sum` on the named file) must match the record — CI checks that. What
differs is whether a worked artifact ships beside it, and what your machine
needs before the verifier can run.

**Rewards are notional.** Stage 0 has no token, no escrow, and no transfer
primitive; the numbers below are the unit of account the settlement rules
operate on, not money anyone is holding. See *What this is not* in the
top-level README.

| example | verifier | reward | status | needs | worked artifact |
|---|---|---|---|---|---|
| [`reversible-adder`](reversible-adder/) | evaluator (minimize) + ratchet | 1000000 | **worked, and open** | python3 | `artifact-cuccaro.json`, `artifact-truncated.json` |
| [`collatz`](collatz/) | certificate | 100000 | worked | python3 | `artifact.json` |
| [`capset`](capset/) | evaluator | 250000 | worked | python3 | `artifact.json` |
| [`capset_progressive`](capset_progressive/) | evaluator + ratchet | 1100000 | worked | python3 | `artifact-12/16/20.json` |
| [`ecdsa-fail`](ecdsa-fail/) | evaluator (minimize) + ratchet | 1000000 | worked | python3; optional external `ecdsafail` CLI | `artifacts/` |
| [`permutation`](permutation/) | statistical | 50000 | worked | python3 | `artifact.json` |
| [`ecdlp`](ecdlp/) | certificate | 250000 | **open bounty** | python3 | none — that is the point |
| [`lean`](lean/) | lean | 50000 | **open bounty** | a Lean 4 toolchain on PATH | none |
| [`first-blood`](first-blood/) | certificate | 100000 – 409600000 | **open bounty** ×5 | python3 | none |

- **worked** — a passing artifact is committed, so the whole loop
  (`post → commit → reveal → audit`) can be exercised end to end. Start here.
  `proofwork try <objective.json> --submitter you --artifact <artifact.json>`
  runs that loop in one command, waiting out the epoch between the commit and
  the reveal rather than making you sleep past it by hand. A real round takes a
  real epoch — 600s — so set `PROOFWORK_EPOCH_SECONDS` for a local trial, and
  only against a log used for nothing else.
- **`reversible-adder` is the one to read if you are judging the design.** It
  is the only example whose score is *derived by simulating the artifact*
  rather than read off a field the submitter filled in, which is what makes an
  objective safe to fund. Compare it against `ecdsa-fail`, which has the same
  shape and accepts declared numbers — one is a bounty, the other is a demo,
  and the difference is the whole thesis.
- **open bounty** — no known solution ships. Submitting requires actually
  solving the problem; scoring a candidate is still free.
- Without a Lean toolchain the `lean` objective verifies as `unavailable` on
  your node — which is correct behaviour, not a bug: it says your node cannot
  check, nothing about anyone's proof.
- The `first-blood` instances state that the discrete log was discarded at
  generation time; that claim is the operator's, and nothing in this
  repository lets you verify it. Judge the bounty accordingly.

The quickest way to see one run:

```sh
./scripts/demo.sh              # posts collatz + capset, full commit-reveal-audit
./scripts/ratchet-demo.sh      # capset_progressive: the progressive bounty
examples/ecdsa-fail/demo.sh    # the minimize-direction ratchet
```

## Objectives that accept only signed identities

Set `"require_signed_submitter": true` and the network refuses any submitter
that is not an ed25519 public key with a matching signature — so every claim on
that bounty is attributable to a key nobody else holds. The cost is real and is
the funder's to weigh: it turns away contributors who have not made an
identity, which is why it is per-objective and off by default. Contributors
make one with `proofwork identity --out alice.json` and submit with
`--identity alice.json`.
