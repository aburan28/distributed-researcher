# distributed-researcher

**A research network where verified results are the unit of account.**

Anyone contributes compute toward shared objectives, AI agents do the work, and
payment is settled by a checker that anyone can re-run. No trust in the operator,
no trust in the contributor, no trust in the model that produced the answer.

This repository contains **proofwork**, the protocol implementation: a Rust
library and CLI, a second and deliberately independent Rust implementation in
`reference/`, and the conformance vectors that bind them to the same answers.

Stage 0 — one operator, no token, no consensus. What it does provide is the
property that actually matters: *anyone can independently re-derive every result
the network has settled*, from nothing but a copy of the log.

```
$ ./scripts/interop.sh

== the reference implementation audits the primary log
log verified: chain intact, every settled claim re-verified

== the primary implementation audits the reference log
log verified: chain intact, every settled claim re-verified

== Merkle roots agree across implementations
  sha256:f0398c1ae67875b4ecc3c9c0d674f7b44b6876b77445a40e1d8ce7f6b331a168  (identical in both)

INTEROP OK: each implementation verifies the other.
```

That is the claim made concrete. "Anyone can re-derive every result" is worth
nothing if it means "anyone running my code"; two implementations written
separately, sharing no code and not even a cargo workspace, agreeing on every
id and every Merkle root, is what makes it real.

The second implementation earns its place by disagreeing. Building it caught
two bugs the primary's own test suite could not see: work assignment reading
four bytes of the HMAC where the format takes eight (two nodes would silently
overlap regions), and the genesis `prev` written as `""` rather than `null`
(every entry hash shifts, while the stored Merkle root still matches). Neither
would ever have raised an error.

## The one idea

> **Pay for verified outputs. Never pay for claimed effort.**

Almost every hard problem in decentralized compute — did the node really run the
job, did it use the right model, did it burn the FLOPs it billed — exists only
because the network is trying to buy *work*. Buy *artifacts* instead and most of
it dissolves. Nobody can fake a Lean proof the kernel rejects, a counterexample
that fails recomputation, or a program that scores badly on a fixed evaluator.
The check *is* the payment condition, so a contributor's hardware, honesty, and
diligence stop being things anyone has to verify.

The corollary is the whole engineering constraint: **the network can only work on
tasks whose outputs are cheap to check.** That is a specification for what to
build, not a limitation to route around.

## Quick start

```sh
cargo build --release
cargo install --path .        # puts `proofwork` and the other binaries on PATH
cargo test                    # the full suite, loopback only
./scripts/demo.sh             # objectives, commit-reveal, audit, attribution
./scripts/ratchet-demo.sh     # progressive bounty: publishing beats hoarding
./scripts/try-demo.sh         # one round in one command, and a scaffolded challenge
./scripts/interop.sh          # each implementation audits the other's log
./scripts/mcp-smoke.sh        # the MCP server, driven as a real process
./scripts/blob-demo.sh        # a node with only the log fetches its verifier and uses it
./scripts/p2p-demo.sh         # two daemons: an empty node syncs, then audits under both
proofwork incentives          # evaluate the node-operator game (~2s)
proofwork incentives --sweep canary-rate=1/20..1/5:5 --out grid.csv
                              # ...across a grid instead of at one point, one row per
                              # point, so a threshold is visible without re-reading
                              # a hundred reports by eye
proofwork incentives --robustness   # ...and how far each parameter can move before it
                                    # breaks. Seventeen parameters walked out along a
                                    # twelve-rung ladder in both directions, the whole
                                    # mechanism re-evaluated at every rung: ~6 minutes,
                                    # with progress on stderr so stdout stays the report.
```

On Linux, install [bubblewrap](https://github.com/containers/bubblewrap)
(`apt install bubblewrap`) so objective-authored verifier code runs inside an
OS jail, and set `PROOFWORK_REQUIRE_SANDBOX=1` on any node that verifies
objectives it did not write — without a jail mechanism the code runs
unconfined, and that variable turns "unconfined" into `Unavailable` instead.

### A log you can check right now

`launch/` holds a real settled log, the checkpoint signing it, and the public
key — so the claim above can be tested before you build anything of your own:

```sh
proofwork --log launch/proofwork.jsonl --root . audit
proofwork --log launch/proofwork.jsonl --root . verify \
    --from launch/checkpoint.json --root-key launch/root-key.pub --audit

# and the check that matters: the independent implementation re-deriving it
./reference/rust/target/release/proofwork-reference \
    --log launch/proofwork.jsonl --root . audit
```

Both print the same Merkle root. See [launch/README.md](launch/README.md) for
what is in it and the two caveats that come with a sample artifact.

Checking one entry does not need the log at all:

```sh
proofwork --log launch/proofwork.jsonl prove 12 --out proof.json
proofwork check proof.json --from launch/checkpoint.json \
    --root-key launch/root-key.pub
```

`check` opens no log — the proof and the signed root are the whole input, which
is what makes it something a light client can run. Five hashes here; fifteen for
a log of twenty thousand.

### Publish your log so others can check it

```sh
proofwork-serve --log proofwork.jsonl --root . --listen 0.0.0.0:8080
```

`GET /log` returns the log byte for byte; `GET /objectives` and
`GET /frontier/{id}` are conveniences over it. A contributor fetches it and
re-derives everything themselves with `proofwork verify --from`, which is the
whole point — they need not trust the server that served it.

Add `--queue ./queue` to accept `POST /submit`. Submissions are *queued*, never
appended: the operator's node admits them, re-checking every rule against the
whole log. That is `proofwork-p2p --queue ./queue` if a daemon is running — it
holds the ledger's single write lock, so nothing else can — or
`proofwork drain --queue ./queue` if one is not. See
[serving.md](docs/serving.md).

### Start a p2p node

There are two roles and they run different commands. Nearly everyone wants the
first.

**Joining — dial out, serve nobody.**

```sh
make p2p
```

Binds `127.0.0.1:9000` (nothing needs to dial you), writes
`.local/proofwork-p2p.jsonl`, and on first run creates
`.local/node.identity.json`, `.local/root.key`, and `.local/checkpoint.json`.
The first two are private keys; `.local/` is gitignored, keep it that way.

**One thing will stop this working, and it is not the network.** With no
explicit `BOOTSTRAP_ARGS`, the first run generates `.local/seed.json` for
`SEED_ADDR` with a **placeholder** public key — a real key, freshly minted, that
belongs to nobody. The address is only ever a dial hint; `p2p::handshake`
authenticates the *key*, so a placeholder authenticates nobody and every
handshake fails. Until you paste the seed's real key into `"public"`, the daemon
says so at startup:

```
bootstrap .local/seed.json: still carries the PLACEHOLDER key ...
```

That warning clears itself once the key is real — it is keyed on the peer id of
the generated key, not on a flag anyone has to remember to delete. Point
somewhere else instead if you prefer:

```sh
make p2p SEED_ADDR=203.0.113.9:9001      # regenerate the hint for another host
make p2p BOOTSTRAP_ARGS='--bootstrap peer.json'   # or supply the file outright
```

A bootstrap file is just `{"addr":"host:port","public":"<peer public-key hex>"}`.
`addr` may be a hostname, which survives a restart that moves an IP.

**Seeding — accept strangers.**

```sh
make seed
```

Binds `0.0.0.0` on `SEED_ADDR`'s port (the port is derived from `SEED_ADDR`, so
the two cannot disagree). Binding the wildcard is the counterintuitive part and
the one that matters on a cloud host: an instance's public address is NAT'd to
it and appears on no local interface, so `--listen <public ip>` cannot bind at
all. Publish the public address in the bootstrap file you hand out.

Two things `make seed` cannot do for you, both of which look identical to a
seed that is simply down:

- **Open the port inbound.** A security group that *drops* rather than refuses
  produces no error on either end — just silence until a timeout.
- **Distribute your real key.** Hand out the `"public"` field from your
  `--identity` file (`.local/node.identity.json`), not your own `.local/seed.json`,
  which holds a placeholder for somebody *else*.

**Is it actually connected?** Successful sessions are logged, not just failures:

```
2026-08-08T00:33:42+00:00 INFO  proofwork inbound session:  <peer id> ok, 12 entries now
2026-08-08T00:33:42+00:00 INFO  proofwork outbound session: <peer id> ok, 12 entries now
```

Silence with neither those nor an error means nothing has been dialled yet;
`outbound session: transport I/O: ...` on repeat means the address, the
firewall, or the key. Check them in that order — the key is the one with no
network symptom.

### Turning up the logs

`PROOFWORK_LOG` sets the level — `error`, `warn`, `info` (default), `debug`,
`trace`, or `off`. Everything goes to **stderr**, always, which is what makes it
safe to raise on `proofwork-mcp`, whose *stdout* is the JSON-RPC protocol.

`debug` adds every p2p protocol message, in both directions, with the peer it
was exchanged with:

```
$ PROOFWORK_LOG=debug make p2p
… DEBUG proofwork::p2p 59758322… -> Hello peer=083e078e… records=0
… DEBUG proofwork::p2p 59758322… <- Inventory records=1
… DEBUG proofwork::p2p 59758322… -> Want ids=1
… DEBUG proofwork::p2p 59758322… <- Records n=1
… DEBUG proofwork::p2p 59758322… -> code.Want addresses=1
… DEBUG proofwork::p2p 59758322… -> dht.Ask addresses=1
```

That is a whole anti-entropy round: records, then verifier code, then the DHT,
then populations — the order [p2p.md](docs/p2p.md) describes, now observable
rather than inferred. Counts and sizes, never contents: a record round moves
whole claims, and a population round would otherwise print other people's
candidate artifacts into your terminal.

Use separate `LOCAL_DIR`, `IDENTITY`, `ROOT_KEY`, and `CHECKPOINT` paths for each
node. `make mcp` uses `.local/proofwork-mcp.jsonl` by default, and `make p2p`
uses `.local/proofwork-p2p.jsonl`, so the two commands can run together without
contention over a single hash-linked ledger. Use `P2P_LOG` and `MCP_LOG` to
override these paths directly.

The root checkpoint key is ML-DSA-65 and is separate from the transport
identity.

Rust 1.89+ (verified in CI, and asserted by `rust-version`). No network access
needed at runtime.

## How it works

An **objective** is a funded question that comes with a runnable verifier, pinned
by hash:

This is [`examples/capset/objective.json`](examples/capset/objective.json)
verbatim — every value real, so it posts as it stands:

```json
{
  "goal": "GOAL-capset-lower-bounds",
  "statement": "Exhibit a cap set in F_3^4 of size at least 20 (no three distinct points collinear). Score is the set size; the maximum is known to be 20.",
  "verifier": {
    "kind": "evaluator",
    "evaluator": "examples/capset/evaluators/cap_set.py",
    "evaluator_sha256": "05ad14fa10bd3055a8f3b1962a6a909832887676558035e40e44c4bd0aa271c4",
    "entrypoint": "score",
    "threshold": 20,
    "direction": "maximize"
  },
  "reward": 250000,
  "funder": "treasury",
  "created_at": "2026-07-28T00:00:00+00:00"
}
```

The hash is the real one, and abbreviating it would not be a tidier example —
it would be a broken one. A wrong pin does not fail: the id covers the
verifier, so it mints a *different* objective, one whose every claim returns
`InvalidSpec` forever and whose reward is stranded. `post` warns when a pin
does not resolve locally but cannot refuse, because posting an objective whose
checker a peer will serve is exactly how content-addressed distribution works.
Key order does not matter here — the record is canonicalized before hashing —
but the bytes of every *value* do.

An objective's id **is** the hash of that whole record, verifier included. There
is no operation that changes the rules of a funded bounty — editing the evaluator
produces a different objective and the claims against the original stop
resolving. Mid-bounty rule changes aren't guarded against; they're
unrepresentable.

```sh
proofwork post   examples/capset/objective.json
proofwork commit <objective-id> --submitter bob --artifact solution.json --nonce s3cret
proofwork reveal <objective-id> --submitter bob --artifact solution.json --nonce s3cret
proofwork try    examples/capset/objective.json --submitter bob --artifact solution.json
                                                 # the three lines above in one, waiting out
                                                 # the epoch between commit and reveal
proofwork scaffold my-challenge --kind certificate  # the files a new objective starts from
proofwork audit
proofwork attribute
proofwork checkpoint --root-key key.json --out checkpoint.json   # sign it
proofwork prove 12 --out proof.json                              # one entry, provably
proofwork check proof.json --from checkpoint.json                # ... checked without the log
proofwork drain --queue ./queue                                  # admit what arrived over HTTP
```

### Four verifiers, four trust assumptions

| kind | checks | cost | trusts |
|---|---|---|---|
| `certificate` | recomputes an NP witness | ms | nothing |
| `evaluator` | scores a candidate against a pinned fitness function | 1 evaluation | evaluator is pinned and pure |
| `lean` | a proof assistant kernel accepts the proof | seconds | kernel soundness |
| `replay` | re-runs a pinned computation, compares declared fields | full re-run | bit-reproducibility |

Pinned verifier code runs as a **subprocess inside an OS jail** — bubblewrap on
Linux, a seatbelt profile on macOS — with its hash checked first: no network,
writes confined to a scratch directory, a wall-clock deadline. Not a VM
boundary; `docs/verification.md#sandboxing` names the gaps that remain. The
`lean` verifier rejects `sorry`, `admit`, new `axiom`s, and `native_decide`
before Lean ever runs, because each produces a file the kernel accepts while
proving nothing.

### Rules the code enforces

- **A verifier that cannot run returns `Unavailable` — never `Reject`.** A
  missing toolchain, a crashed checker, or a timeout is an infrastructure fact,
  not a fact about the artifact. Collapsing it into a rejection turns "my Lean
  install is broken" into "your proof is wrong", and hands an attacker a way to
  fail every honest submission by taking verifiers offline. Only `Accept` and
  `Reject` settle anything.
- **Floats are unrepresentable, not merely rejected.** `canonical::Value` has no
  float variant, so an object whose identity could differ between two honest
  nodes cannot be constructed. IEEE-754 doubles don't round-trip identically
  through every JSON implementation and don't reproduce bitwise across
  heterogeneous hardware.
- **Money arithmetic is checked.** `reward * progress` overflows `u64` at
  realistic values; every such path uses `u128` intermediates and returns an
  error rather than wrapping, with `overflow-checks` on in release too.
- **Novelty is necessary, never sufficient.** A duplicate artifact verifies fine
  and mints zero. Issuance is gated on funded demand.
- **Time is not reproducible.** `replay` refuses to treat wall-clock, memory, or
  FLOPs as a checkable field — those measure the host, not the computation.
- **Attribution conserves exactly.** Citation-flow payouts sum to the amount
  distributed, at any reward and any δ, with a deterministic rule for the odd
  unit in an uneven split.

## Coordination: don't schedule it, price it

Thousands of participants on one objective must avoid duplicating each other and
share what they find. That's usually attacked with machinery — dispatchers,
reservations, locks. Most of it is self-inflicted: **a winner-take-all bounty
gives everyone a reason to hoard**, so nobody shares and everyone rediscovers the
same partial results.

`frontier.rs` changes the payment structure instead. An objective carries a
monotone best-known score; whoever moves it is paid for the distance moved.
Payouts telescope, so the pool is exactly exhausted at the target however the
curve is chopped.

```
alice: 12-point cap set     reward 300000
eve:   copies alice         reward 0        (does not improve)
bob:   16, citing alice     reward 400000
carol: 20, citing bob       reward 400000   (pool exhausted)

after citation flow:  alice 442857 · bob 357143 · carol 300000
```

Alice ends up with the **largest total from the smallest direct reward**, because
two people built on her. Publishing immediately becomes the profitable move,
copying earns zero, and an improvement **must cite the frontier it beat** —
enforced at submission, so attribution needs no judgement.

Flow is weighted by each cited claim's *settled reward* — which on a ratchet is
the progress it moved — rather than decaying by citation depth. That is what
stops an improver chopping one advance into many steps to dilute the person
below them: a later contributor pays alice the same however bob packaged his
work, and slicing converges to a small premium instead of draining her. See
[the design note](docs/design/citation-flow-dilution.md).

### Three kinds of state, three consistency requirements

| state | volume | needs | mechanism |
|---|---|---|---|
| frontier — who holds the best score | low | total order | consensus |
| population — candidates worth mutating | high | eventual convergence | CRDT + gossip |
| work split — which region a node searches | zero messages | nothing | pure function |

The population is a bounded join-semilattice: merge is commutative, associative
and idempotent, so nodes converge with no rounds and no leader. Divergence is not
a bug — it's the island model preserving search diversity. **Gossip is
untrusted**: a peer asserting `score = 10^12` would evict every real candidate, so
`ingest()` re-scores locally and drops what doesn't reproduce.

## Agents paying agents

Every payment above points the same way: a funder escrows, an artifact verifies,
settlement releases, citation flow moves a fraction of that same money backwards.
Every unit that reaches a participant entered as somebody's bounty. Nothing pays
an agent for something another *agent* wanted — a decomposition, a sub-frontier
candidate, a branch somebody else explored.

The scope for closing that is [agent-market.md](docs/agent-market.md), and its
conclusion is that **the mechanism is already here**. `Objective::funder` is a
string, there is no balance and no transfer primitive anywhere in `src/`, and an
agent-to-agent payment is best expressed as an objective rather than a transfer:
escrow, verification, settlement, audit and citation flow then apply unchanged,
and fair exchange falls out instead of needing its own protocol.

What makes it tractable at all is an asymmetry that inverts the verifier's
dilemma. Nobody holds the right answer about an artifact, which is why
verification needs canaries — but

> **the buyer is the oracle.** An agent spending its own money on a good it wants
> is motivated to price it correctly, so the protocol enforces atomicity and never
> valuation.

That survives exactly one rule: **no protocol payment may ever be a function of
trade volume.** A sybil pair trades at any price for free, so a fee rebate or a
reputation that pays is the grinding attack with a market around it.

Three results the scope pins down:

- **The market cannot outbid the ratchet.** A buyer will not pay more than what
  publishing is worth to it, so `π < Δ + φ` and selling is dominated for anyone
  with standing to move the frontier. The market's whole domain is the goods the
  ratchet prices at *zero* — which is a boundary the payoffs already draw rather
  than one anybody has to enforce.
- **Even-splitting δ stops being safe.** Citation flow divides evenly across a
  claim's citations, which is fine while citable claims are scarce and is a free
  attack once an agent can fund cheap objectives its own identities settle. At
  δ = 1/4 and five citations, four fifths of what the ratchet promised the
  frontier holder is recoverable. This has to be fixed *before* agent funding,
  not after.
- **Decomposition has a floor, and it is high.** A sub-objective the network
  verifies for more than it settles is subsidized by everything else. At the
  reference parameters that break-even is 800,000 units per artifact under full
  redundancy, or 8,000·k under k-fold sampling — so subcontracting should be
  coarse, and sampled verification stops being optional.

And one risk that decides whether it is worth building at all: candidates
currently circulate through gossip *because* nothing prices them. Price them and
gossiping is giving away inventory, so a market for candidates may starve the
population the island model runs on. That is a payoff question, it is the highest-
value item in the scope, and it belongs in the harness before it belongs in code.

## Why anyone runs a node

Everything above pays *submitters*. Nothing in it pays the machines that re-run
the verifiers, hold the log, or custody the shares that open a sealed
submission — all public goods, all of which the dominant strategy is to leave to
somebody else.

The hard one is verification, and it is hard structurally rather than
quantitatively. Punish a node for accepting work that somebody *else* later
proves invalid, and

> **"everybody rubber-stamps" is a Nash equilibrium at any penalty** — if nobody
> checks, nobody is caught, so no penalty ever fires.

Raising the slash does not touch it. The mechanism has to manufacture its own
ground truth: **canaries**, artifacts whose verdict the protocol already knows,
mixed indistinguishably into each node's sample. Then the punishment is
unconditional and the equilibrium moves.

Availability and custody need no such trick, and the reason is the whole design
in one line: **the protocol already holds the right answer.** A Merkle challenge
is checked against a published root; a share that never appears names its
holder. Verification is the only service with no oracle.

`src/incentive/` is the mechanism and a harness that evaluates it — exact
rational payoffs (no floats, so "is this an equilibrium" is decidable), the full
ladder from individual rationality up to k-resilience and sybil-proofness, and
better-reply dynamics for where a population *lands* rather than where it could
rest.

And the verdict is a point, which is the weakest form of the claim. `--robustness`
walks each parameter outward until the report stops passing, in both directions —
`fraud_rate` breaks the mechanism by getting *smaller*, so a one-directional
search would call it safe. The result contradicts where the prose spends its
attention: **the four tightest constraints are all custody.** Verification, the
sub-game with the interesting structural argument, survives a sixteenfold error
in the cost of a check; custody does not survive a quarter. No passing verdict
would have said so. See [proving-it.md](docs/proving-it.md) for what that does
and does not establish.

```
$ proofwork incentives --canary-rate 0

verification -- honest action: verify
  honest profile                 strict Nash  ok
  pure equilibria                          2
  rival (strict) equilibria                1  FAIL
  smallest defection               100 nodes  FAIL
  free (zero-gain) drift                none  ok
  tipping point                    100 nodes  FAIL
  binding constraint        canary_rate must exceed 1/1425 (currently 0)
```

Three results worth stating plainly, each pinned by a test:

- **The reward pool decides how many nodes there are; it has no effect on
  whether they do the work.** A rubber-stamper collects the same share, so the
  pool cancels out of every honest-versus-lazy comparison. Paying operators more
  is never an answer to "nobody is checking".
- **Node rewards are a fee on settlement, not a mint** — the same demand-gating
  rule as everything else here, which means security spend is proportional to
  settled value and *zero at launch*. Stated, not solved.
- **The committee has to grow with the value it seals.** Raising the threshold
  makes early opening harder and censorship-by-withholding easier, so safety is
  a window; a shape safe for a small bounty is corruptible for a large one, with
  no code change in between.

Also stated rather than papered over: a committee member standing ready to
collude is behaviourally identical to an honest one, so the custody equilibrium
is **weak at every parameter set** and no bond makes it strict. What the bond
buys is that reaching the threshold does not pay.

## Local storage: encrypted, bounded, yours

Where a node's data lives is the operator's choice, and what leaks off their disk
is their risk. Four things, one command each:

```sh
proofwork keygen                                   # 32-byte key at ~/.proofwork/key, 0600
proofwork --data-dir /Volumes/ext/pw audit         # data wherever you want it
proofwork --data-dir /Volumes/ext/pw --max-size 20GB store gc
proofwork --data-dir /Volumes/ext/pw sync ~/Dropbox/pw-backup
proofwork --data-dir /Volumes/ext/pw store rekey   # new key, same root, no plaintext on disk
proofwork --data-dir /Volumes/ext/pw store export --out public.jsonl
```

`rekey` is the one worth a sentence. It re-seals every line under a fresh key and
requires the new file to re-derive the same entries and the same Merkle root
*before* anything is swapped. It keeps the old key at `<key>.previous` — a mirror
you made last month is still sealed under it — and does **not** keep the old
ciphertext, which would otherwise sit there readable by the key you are retiring.

`export` is the inverse of `store encrypt`, and it exists because sealing a store
must not be a one-way door out of the claim at the top of this file. Without it,
an operator who encrypted their own copy could no longer produce the readable log
anyone else would audit.

### `src/swarm/`: piece-level transfer and a DHT, alongside `p2p`

Two things here that `src/p2p/` does not have, and one honest overlap.

**A Kademlia DHT** (`src/swarm/dht.rs`) for the question a fetch actually asks:
*who holds digest `D` right now*. `p2p::discovery` answers which peers exist;
without a provider lookup, finding a blob means asking everyone. XOR metric,
k-buckets, provider records with expiry, and the α-parallel iterative lookup as a
pure state machine — convergence and termination asserted against a synthetic
200-node network built from real routing tables.

The k-bucket policy is the part worth reading twice, because it is backwards from
every cache written by reflex: when a bucket is full the **oldest still-live**
contact wins and the newcomer is discarded. Longevity is the one thing an
attacker flooding fresh identities cannot manufacture. So `insert` does not
evict — it returns the contact to *probe* and lets the caller decide after
actually trying it, which keeps the policy testable without a network.

DHTs earned a bad security reputation honestly, and it does not transfer here:

> **Every DHT answer is a hint. The digest decides.**

A lying provider record costs one wasted dial, checked against a digest the log
fixed before the lookup started. Eclipse costs *liveness*, never correctness.
Node IDs are hashes of ed25519 public keys, so claiming one costs a keypair and a
signature — S/Kademlia's crypto-ID mitigation, free from the identity layer.

**Piece-level transfer** (`piece.rs`, `wire.rs`) — manifests of piece hashes,
bitfields, rarest-first, bounded pipelining, tit-for-tat choking, endgame with
cancels. Piece hashes buy not trust (anyone can compute a manifest) but **blame**:
a bad piece is localised to one peer instead of costing the whole download. And
rarest-first is really a *durability* rule rather than a throughput trick — it
prevents the last-copy state the availability mechanism pays to avoid.

**The overlap, and what was done about it.** The DHT is no longer duplicated:
the metric, the k-buckets, the iterative lookup and the provider store live in
`src/dht.rs`, generic over a contact type, and `swarm::dht` and `p2p::dht` are
both instantiations of it. `p2p::dht` is the one the daemon runs: a session
asks which of the blobs this node wants the peer holds, and `Service::peers_for`
then asks a peer that said yes instead of asking three at random.

Asks, not announces, and that is the interesting constraint. `p2p::code` already
refuses to offer an inventory of held blobs, because that list is a list of the
objectives a node is working on. Building a DHT by publishing it would spend
exactly the privacy `code` declined to spend, so holdership is pulled: a node
answers only for addresses the peer named, and the set it names is the
`code_want` already sent on that connection. The round adds routing knowledge at
no additional disclosure.

Two details that are specific rather than incidental. A `PeerId` is already
`sha256(McEliece public key)`, so it *is* the Kademlia id — identity is
self-certifying through the handshake, with no signature needed. And a contact
deliberately does not carry the key, because that key is 261,120 bytes and a
full routing table holding one per contact would cost about 1.3 GB; the key
comes from the address book at dial time, which is why a `p2p` routing answer is
a hint checked by dialling rather than a proof.

**Everything that opens a socket goes over the encrypted transport.** Records,
code, DHT, populations — and now `swarm::tcp`, which spent a while in plaintext
behind an off-by-default feature because `swarm`'s peer records named an ed25519
identity while the transport needs a 261,120-byte McEliece key. Giving the
record the 32-byte *id* of one settled that, and the feature gate is gone.
Neither claim is asserted in a comment: `tests/wire_encryption.rs` and
`a_transfer_puts_no_plaintext_on_the_wire` each put a recording relay between
two real nodes and check the captured bytes.

`swarm::tcp` is now driven by `proofwork blob serve` and `proofwork blob fetch`,
and `scripts/blob-demo.sh` runs both sides in CI: a node holding only the log
fetches its pinned verifier from a stranger and settles a claim with it. That
was worth doing for its own sake and it also found two bugs that no unit test on
either side could reach, because the module had **no caller in any shipped
binary** and so had only ever been checked against itself. See
[storage.md](docs/storage.md#moving-one-between-peers).

The two address books look like a duplicate and are not, which took reading
both to establish. `p2p::discovery::AddressBook` maps a transport id to an
endpoint — an address *and* the 261 KiB McEliece key needed to dial it. It is a
local key cache and nothing about it is relayable. `swarm::discovery` holds
**signed** peer records — ed25519 identity, addresses, a monotonic sequence — and
exists to be handed to strangers: `offer` and `share` are peer exchange, with
bounds and persistence. One says *how to open a session*, the other says *who a
peer is and where it claims to be*, verifiably. `swarm::tcp::KeySource` is the
join between them, and it is what lets an address learned by asking become a
dial.

What *was* duplicated — two transports — is gone: `swarm::tcp` runs over
`p2p::transport` like everything else here.

The real remaining gap was narrower and is closed: `p2p` had the signed
sequence available and was throwing it away. `seed_from_log` reads `peer`
records out of the log, where `Node::peers` has already resolved
highest-seq-wins and the audit reports one that fails to advance — and then
handed the routing table a hardcoded zero. Since the table takes a contact when
`seq >= held`, at zero a replayed record always won, so anyone who had once seen
a peer record could steer traffic back to an address that peer had left. See
[discovery.md](docs/discovery.md) for the design and the survey, including why
encrypted DNS answers a different question than the one people ask it.

One caveat that argues against the whole module: `blobs::MAX_BLOB_BYTES` caps a
blob at 1 MiB, which is four pieces. At that size rarest-first and choking buy
nothing, and `p2p::code`'s whole-blob transfer is the right call. The swarm
machinery is sized for a constraint this design does not currently have.


## Censorship resistance

Assume censorship. But separate four properties that get bundled under "encrypt
it", because encryption delivers only one of them:

| property | mechanism |
|---|---|
| confidentiality — observers can't read | encryption |
| unlinkability — observers can't tell *who* | pseudonyms, ZK |
| censorship resistance — your submission gets included | forced/blind inclusion |
| availability — content can't be withheld | replication, gossip |

**Encrypting settled artifacts would destroy the project.** Public verifiability
requires them readable; encrypt them and you're back to trusting an operator.

The real censorship hole is elsewhere: **commit–reveal requires the submitter to
act twice.** An adversary who can't forge or steal your work can still take it by
stopping the second action — a DoS, a network block, a detention, or a sequencer
that drops your reveal until the deadline passes.

So submissions are **sealed**, and opened *without* the submitter:

```
commit    commitment = H(artifact ‖ submitter ‖ nonce)      (unchanged)
          envelope   = ChaCha20-Poly1305(K, {artifact, nonce})
          shares     = Shamir(K, t-of-n), each sealed via ephemeral X25519
epoch end ≥t committee members publish shares → anyone reconstructs → opens
```

You can be offline, jailed, or firewalled and still be paid. It also kills
in-flight front-running, and makes selective censorship visible — a sequencer
can't see what it's dropping, so it must include everything or censor
indiscriminately. The commitment binds the plaintext, so a submitter who seals
garbage is caught the moment the committee opens it.

Sealing moves **when** an artifact becomes public, never **whether**.

Two things are stated rather than papered over: **citation flow requires
linkage** — the pseudonym graph is public by construction because paying people
for being built upon is what it's for — and **encryption does not stop a
sequencer that includes nothing**, which needs forced inclusion on a base layer.

## Consensus: validators don't vote on truth

For a pure pinned verifier, correctness is **not** a consensus question — anyone
re-runs the checker and gets the same answer. What needs agreement is narrower:
**ordering** (who advanced the frontier first) and **data availability** (was this
published, or withheld).

That inverts the usual priorities. Throughput barely matters; frontier advances
are minutes apart. **Censorship resistance matters enormously**, because
withholding a competitor's reveal steals a bounty, and liveness is money.

So: don't write a consensus protocol, and don't run an L1. Use a rollup on an
established chain — the bootstrap circularity (stake value ← research ← chain)
has no starting point, and forced inclusion via a base layer delivers the primary
security property directly. The state transition is already the pure function in
`node.rs`, and `audit()` is already the re-derivation a fraud proof needs.

## Layout

```
src/                 Rust implementation (primary)
  canonical.rs       content addressing; the cross-implementation contract
  records.rs         Objective / Commitment / Claim
  ledger.rs          hash-linked append-only log
  node.rs            the rules engine and the audit
  frontier.rs        progressive bounties
  attribution.rs     recursive citation flow
  gossip.rs          the candidate population CRDT
  partition.rs       coordinator-free work assignment
  verifiers/         certificate, evaluator, lean, replay
  crypto/            Shamir, sealed envelopes, pseudonymous identity
  sealed.rs          sealed submissions, openable without the submitter
  incentive/         the node-operator mechanism, and the harness that evaluates it
  store/             at-rest encryption, the data directory, the size cap, the mirror
  swarm/             piece-level transfer and a Kademlia DHT, alongside p2p/
conformance/         cross-implementation vectors — the binding contract
docs/                the design notes
examples/            worked objectives with real artifacts
```

## Docs

- [diagrams.md](docs/diagrams.md) — architecture and detailed design, drawn from the code
- [architecture.md](docs/architecture.md) — the full design and which work shapes fit
- [verification.md](docs/verification.md) — the verification ladder; authoring verifiers
- [economics.md](docs/economics.md) — what mints, why demand-gating, citation flow
- [coordination.md](docs/coordination.md) — the hoarding trap, the ratchet, CRDT gossip
- [agent-market.md](docs/agent-market.md) — agent-to-agent rewards: what a peer-to-peer mechanism would be, and what it breaks
- [consensus.md](docs/consensus.md) — what validators are for, and why not to build a chain
- [censorship.md](docs/censorship.md) — confidentiality, unlinkability, sealed submissions
- [node-incentives.md](docs/node-incentives.md) — why anyone runs a node, and the game-theoretic evaluation
- [review-pcw.md](docs/review-pcw.md) — a review of Proof of Adaptive Challenge Solving as a consensus mechanism, and what to salvage from it
- [proving-it.md](docs/proving-it.md) — what a game-theoretic proof here would be, what it would not be, and where this one is weakest
- [storage.md](docs/storage.md) — encryption at rest, the data directory, the size cap, sync
- [serving.md](docs/serving.md) — publishing a log over HTTP, and why submissions queue instead of appending
- [threat-model.md](docs/threat-model.md) — attacks, and which are actually handled
- [launch-review.md](docs/launch-review.md) — the pre-launch pass: what was fixed, and the gaps that remain, in priority order
- [p2p.md](docs/p2p.md) — removing the operator: what needs agreement, and the McEliece handshake
- [agents.md](docs/agents.md) — running Claude Code / Codex / OpenCode against the network over MCP
- [.claude/skills/proofwork/](.claude/skills/proofwork/) — the Claude Code skill: ask Claude to start the network and it builds, wires MCP, and posts objectives
- [AGENTS.md](AGENTS.md) — instructions agents read: contributing here, and contributing *to* the network
- [CONTRIBUTING.md](CONTRIBUTING.md) — the two different things "contributing" means here, and the gate for each
- [roadmap.md](docs/roadmap.md) — what Stage 1–3 add, in the order worth doing
- [formal-model.md](docs/formal-model.md) — which rules TLC actually checks, and which are only tested
- [design-stage0-completion.md](docs/design-stage0-completion.md) — what "Stage 0 is done" was defined to mean
- [conformance/README.md](conformance/README.md) — the cross-implementation contract

## What this is not

- **Not a blockchain.** One sequencer, no consensus, no token. Deliberate: the
  valuable property is "anyone can check", not "no one is in charge".
- **Sandboxed, not virtualized.** Pinned verifier code runs in an OS jail
  (bubblewrap / seatbelt): no network, confined writes, a deadline. A kernel
  bug is still an escape, macOS does not confine reads, and a host with no
  jail mechanism runs unconfined unless `PROOFWORK_REQUIRE_SANDBOX=1` is set.
  VM-class isolation is Stage 2; see the threat model before opening
  objective authorship to strangers.
- **Not able to verify judgement.** Whether a direction is promising, whether a
  result is novel against the literature — no mechanism settles these.
- **Not able to pay fairly for effort that produced nothing**, which is most of
  real research. The deepest limitation, and not solved here.
- **Not able to price a shared technique.** Citation flow tracks artifacts,
  because artifacts are checkable. If you tell me "try annealing on the third
  coordinate" and I win, nothing pays you.
- **Not running the node mechanism.** `src/incentive/` is a mechanism and its
  evaluation, not a code path. No canary is generated, no bond is posted, no
  Merkle challenge is issued. It exists now because the parameters it demands
  are expensive to discover after launch.

## Prior art

[FunSearch / AlphaEvolve](https://deepmind.google/discover/blog/funsearch-making-new-discoveries-in-mathematical-sciences-using-large-language-models/)
for propose-and-evaluate, the
[Equational Theories Project](https://arxiv.org/html/2512.07087) for crowdsourced
kernel-verified mathematics, and
[INTELLECT-2 / TOPLOC](https://www.primeintellect.ai/blog/intellect-2) for
verifying permissionlessly contributed inference across non-deterministic GPUs.

## License

Apache-2.0
