# Node incentives

Why anyone runs a node, and how the answer is checked rather than asserted.

## The gap

Everything else in this repository pays *submitters*. An objective is funded, an
artifact verifies, escrow releases, citation flow pays the claims it was built
on. Nothing pays the machines that re-run the verifiers, hold the log, serve it
to a stranger who wants to audit it, or custody the Shamir shares that let a
sealed submission be opened without its author.

Each of those is a public good: the operator bears the whole cost and captures a
vanishing slice of the benefit. The dominant move is to let somebody else do it,
and when everybody plays the dominant move, *"anyone can independently re-derive
every result"* — the one property Stage 0 claims — becomes a sentence in a
README rather than a fact about the world.

```sh
proofwork incentives                          # the reference network
proofwork incentives --canary-rate 0           # what breaks without canaries
proofwork incentives --settled 500000          # what breaks at bootstrap
```

Tuning a parameter means asking where it *stops* holding, not whether it holds
at one point, and that is a grid rather than a report:

```sh
proofwork incentives --sweep canary-rate=1/20..1/5:5 --sweep stake=1000..10000:4 \
                     --out sweep.csv
```

One row per grid point, with the same measurements the single-point report
carries. It runs the same evaluation -- a swept row that disagreed with
`incentives` at the same parameters would be a bug in the sweep -- and a point
`validate` refuses becomes a row carrying its reason rather than stopping the
table early. `--format jsonl` if that suits the thing you plot with better.

## Three services, and only one of them is hard

| service | who holds the right answer | so the fix is |
|---|---|---|
| **availability** — store the log, answer for it | the protocol: a Merkle root | sample it. A node that can't answer didn't store it |
| **custody** — hold a share, publish at epoch end | the protocol: shares are committed in advance | attribute it. A share that never appears names its holder |
| **verification** — re-run pinned verifiers | **nobody** | this is the hard one |

Two of the three are easy for the same reason: the protocol already knows the
correct answer, so a node that fails a challenge has proved something about
itself, unconditionally and without anyone's cooperation. Verification has no
such oracle: the whole point of re-verifying is that nobody yet knows whether
the artifact is good, so a node that says "accept" without running anything is
indistinguishable from a node that ran everything — and it is cheaper.

"Sample it" is a sentence, and for a while it was only a sentence: the log had
a Merkle root and no way to prove anything against it, so a challenge had no
answer shorter than the whole log. It has one now.

```
proofwork prove 12 --height 25 --out proof.json     # the holder answers
proofwork check proof.json --from checkpoint.json \
  --root-key operator.pub                           # the challenger checks
```

`check` reads no log — that is the property that makes it a challenge rather
than a second audit. It needs the proof and a root, and a signed checkpoint is
where the root comes from. The cost is `log2(n)` hashes: five for the
twenty-five-entry log in `launch/`, fifteen for twenty thousand. A node that
cannot produce one for an entry it was paid to hold has answered the sample, in
the negative, and the answer is checkable by anyone.

Three things can go wrong and they accuse different people, so they are
reported separately: an entry that does not hash to the digest it carries is
the *holder's* file being edited; a path for the wrong slot is a proof about
some other entry; a path that does not reach the root means the entry is not in
that log — or, far more often, that the checkpoint is older than the proof.
That last case is common enough to name its own remedy, and `check` prints it.

The payment is in the log too, because a challenge nobody is paid to answer is
a challenge nobody answers:

```
proofwork availability fund --funder treasury --per-epoch 7 \
    --from-epoch 0 --to-epoch 4000
proofwork availability undertake --identity node.json   # the promise
proofwork availability answer    --identity node.json   # this epoch's sample
proofwork availability settle                           # pay it, name the silent
```

The sample is drawn `assign(identity, undertaking, beacon(epoch, anchor),
height)` — a pure function of the log, so nobody issues the challenge and
nobody can decline to issue it. Identity is in the draw so a coalition cannot
pool one stored entry; the undertaking id is in it so a node that promised
twice answers two questions; the beacon is in it so the answer is not knowable
in advance.

Settlement divides the epoch's pot **by weight** — floor-divided in proportion
to how much each identity promised — records the remainder it could not divide,
and names every promise that was samplable and said nothing. The silence is the half a slash would attach to. Writing it down
before a bond exists is what makes the record worth having: the accusation is
permanent and checkable, even while the penalty is not yet money.

The answer carries the sampled **entry** as well as its path, and that is the
difference between proving storage and proving arithmetic. It did not, at first:
the verifier recomputed the leaf from its own copy, so an answerer needed only
the entry hashes — every path is derivable from those — and a node that kept 10%
of a log reproduced the honest answer byte for byte. The pool was buying a hash
tree.

The promise is not the promiser's to size, either. With the height free,
promising *one* entry drew index 0 every epoch, answered with an empty path, and
collected exactly what promising the whole log collected. An undertaking now
covers the log as it stood, the share is weighted by that height, and one
identity is paid once however many promises it made.

**One bound remains, stated plainly.** The answer proves a node *produced* the
challenged entry, not that it *stored* it — fetching it from a peer the moment
the epoch opens is not ruled out, and ruling it out needs a time bound or
sequential work this stage does not have. So it excludes a node that stored
nothing and has no source, which is the population the payment exists to
exclude, and it does not catch a cache. And a fixed pot bounds a funder's cost
however many nodes appear, but it does not price **identity**: ten identities
behind one disk answer ten samples from one copy and take ten shares. Weighting
by height stops one identity multiplying itself through extra promises; nothing
here stops ten identities. That is what `stake` above is for, and why the
roadmap lists availability sampling as *bonded* at Stage 2 — **so a pool should
not carry real money until it exists.**

## The verifier's dilemma is structural, not quantitative

Punish a node for accepting work that somebody *else* later proves invalid, and

> **"everybody rubber-stamps" is a Nash equilibrium at any penalty.**

If nobody checks, nobody is caught, so no penalty ever fires. Raising the slash
does not touch it. This is not an argument in prose; it is
`rubber_stamping_survives_any_penalty_when_the_trigger_is_conditional`, which
sweeps stakes up to the modelling bound at a 100% slash rate and finds the trap
standing every time.

The mechanism has to manufacture its own ground truth. **Canaries** — artifacts
the protocol knows the verdict of, mixed indistinguishably into each node's
sample — make the punishment unconditional, and the equilibrium moves.

Write `D` for the rate at which a rubber-stamper meets a canary it cannot
recognise and the protocol knows is invalid, `c` for the cost of one check, `p`
for the genuine fraud rate, `β` for the catch bounty, `S'` for the slashable
stake and `n` for the node count. Two constraints, both necessary:

```
honest profile stable      (D + p)(β/n + S')  >  c
lazy profile destroyed     D(β + S')          >  c − pβ
```

A designer who checks only the first ships a mechanism with a working honest
equilibrium *and* a working dishonest one, and the population lands in whichever
it is nudged into. `design::minimum_canary_rate` takes the worse of the two.
For the reference network it returns **1 in 1425** — which already
discounts the 5% of canaries the reference parameters assume a node can
recognise. With a perfect canary pipeline it would be 1 in 1500.

The second constraint also admits an alternative: a catch bounty above `c/p`
destroys the trap with **no canaries at all**. That is a real design and it is
usually unaffordable — at a fraud rate of one in a thousand it means paying a
thousand times the cost of a check, on the rare occasions there is anything to
catch. Canaries are cheaper precisely because the protocol manufactures the
occasions.

### The perverse comparative static

With no canaries, the only reason to check is the chance of catching real fraud.
So **the more honest the network, the weaker the incentive to verify it** — and
the network where nobody checks is exactly the one where an undetected fraud is
worth the most. Bounty-only schemes fail hardest where they look least
necessary.

### There are two ways to attest without looking

A node that blindly *rejects* everything passes every known-bad canary with
flying colours. Only a known-**good** canary catches it, so the canary mix
matters and the binding constraint is whichever side is smaller.

But blind rejection barely needs defending, and the reason is the most useful
asymmetry in the whole design: a wrongful rejection denies a submitter their
bounty, and the submitter — unlike every other party — is strictly motivated to
re-run the verifier and dispute it. **False rejections police themselves. False
acceptances do not.** Everything above is downstream of that.

## Two knobs, two jobs

The pool share appears identically in the verify, rubber-stamp and reject
payoffs, because the mechanism cannot tell those nodes apart — that is the
problem restated as algebra. So it cancels:

> **The size of the reward pool decides how many nodes there are. It has no
> effect whatever on whether they do the work.**

Paying operators more is an answer to "nobody is running nodes" and never an
answer to "nobody is checking anything". A design that reaches for it in the
second case is buying nothing, and
`the_pool_share_cancels_out_of_the_honest_versus_lazy_comparison` holds it to
that at a fortyfold change in pool size.

## Where the money comes from

Not from a new mint. [economics.md](economics.md) argues that issuance not gated
on funded demand is the grinding attack wearing a different hat, and a per-block
subsidy for node operators is exactly that. So node rewards are a **protocol fee
on settlement**, split three ways across the services.

That choice has a cost and the harness reports it rather than burying it:
security spend is proportional to settled value, which is right in the limit and
**zero at launch**. `proofwork incentives --settled 0` prints `fee pool supports
no nodes`. The bootstrap problem is stated, not solved.

## The committee sits in a vice

The `t`-of-`n` committee from [censorship.md](censorship.md) faces two attacks
that pull the threshold in opposite directions:

- **Open early.** Any `t` members reconstruct the key before the epoch ends and
  front-run the submission. Raising `t` makes it harder.
- **Withhold.** Any `n − t + 1` members make reconstruction impossible, denying
  the submitter the bounty a rival then collects. Raising `t` makes it *easier*.

```
early opening does not pay    when   V  ≤  t · d · S'
withholding does not pay      when   V  ≤  (n − t + 1) · (S' + r − g)
```

so a committee is workable at all only when `n + 1` exceeds
`V/(d·S') + V/(S' + r − g)`. **The committee has to grow with the size of the
bounties it seals.** A shape that is safe for a thousand-unit bounty is
corruptible for a million-unit one and nothing about the code changes in
between. `committee_window` sweeps the thresholds with the solver;
`the_committee_window_matches_its_closed_form` checks the sweep against the
algebra above, so neither is trusted alone.

For the reference network the window is **thresholds 10–17 of 21**.

### The part that cannot be fixed

A committee member who has agreed to open early but whose cartel has not reached
`t` does exactly what an honest member does and earns exactly what an honest
member earns. There is no observable to punish. So:

- the custody equilibrium is **weak at every parameter set**, and no amount of
  stake promotes it to strict;
- a cartel can assemble at zero cost and becomes profitable *discontinuously* at
  the threshold.

What the bond buys is not that cartels don't form. It is that reaching the
threshold doesn't pay. The harness reports the free drift on its own line rather
than letting a strict-equilibrium check quietly miss it.

## Sybils

Almost every per-node reward is sybil-*attracting* by construction: a pool split
evenly pays `k` times as much to `k` identities. Only rewards proportional to a
resource that cannot be split for free — stake — resist it, because stake is
conserved when it is divided. `reward_rule` is a parameter rather than a
constant so the report can price the rejected alternative:

```
sybil resistance -- identities one operator would run
  even per-node split (rejected)   100 identities  why not
  stake-weighted split (in use)        1 identity  ok
```

## What the harness actually is

`src/incentive/` — about 5,200 lines, 95 tests.

| module | what it does |
|---|---|
| `exact` | rational payoffs over `i128`. No floats, so "is this an equilibrium" is decidable |
| `game` | the solvers: best response, Nash, strict Nash, dominance, k-resilience, invasion, sybil |
| `mechanism` | proofwork's three sub-games, with the payoff algebra and where each term comes from |
| `dynamics` | better-reply dynamics: where a population *lands*, not where it could rest |
| `design` | the inverse question — smallest canary rate, bond, committee that close the gap |

### Why exact rationals

An equilibrium claim is a claim about a comparison. On `f64`, two payoffs that
are *equal* in the mechanism — and equality is the interesting case, because it
separates a strict equilibrium from a knife-edge one — differ in the last bit
after a few multiplications, and the harness reports "no profitable deviation"
or "deviation gain 1e-17" depending on the order the terms were summed in.

Exactness is what makes `at_the_threshold_the_trap_is_still_standing` a
meaningful test: at precisely the reported canary rate, the rubber-stamp profile
is a *weak* equilibrium — nobody gains by switching and nobody loses. Design
above the number, not at it. A float harness could not distinguish that case
from either neighbour.

It also makes a report reproducible to the byte, so it can be checked in and
diffed when a parameter changes.

## The evaluation ladder

Each rung is strictly stronger than the one below, and the mechanism earns a
different rung in each sub-game — which is the useful output, not a single
pass/fail.

| rung | predicate | what it rules out | proofwork |
|---|---|---|---|
| individual rationality | payoff ≥ outside option | operators not showing up | verification ✓ (fee-funded) |
| Nash | no profitable unilateral deviation | one operator defecting alone | all three ✓ |
| **strict** Nash | no *weakly* profitable deviation | indifference, laziness, zero-price bribes | verification ✓, availability ✓, custody ✗ (impossible) |
| dominance | best regardless of others | needing to predict anyone | availability ✓ |
| k-resilience | no coalition of ≤ k gains | cartels, one operator behind many machines | all three ✓ at the reference bond |
| invasion resistance | resident repels m mutants | a defecting minority growing | all three ✓ |
| sybil-proofness | one identity is optimal | paying for machines instead of work | ✓ under stake weighting |

**Nash on its own is close to worthless here.** A mechanism whose honest profile
is *a* Nash equilibrium can have a dishonest profile that is also one, and if
the dishonest one pays better that is where a population lands. So the harness
enumerates *all* equilibria rather than checking the one the designer hoped for,
and reports rival strict equilibria as a separate line.

Equally, "the honest profile is a strict Nash equilibrium" says nothing about
how much slack there is. `tipping_point` answers that: how many operators have
to start out lazy before the network stops recovering. Switch canaries off in
the reference network and the answer is not "it collapses" — it is that the
network becomes **bistable**, fine until essentially everyone moves at once, and
a shared client default or one popular piece of software that skips the check
gets there in a single step. Thin the bond as well and it becomes a slope: one
lazy operator is enough. Two different failures wanting two different fixes.

## The verdict is a point; the useful claim is a region

Everything above answers a question about *one* parameter set. That verdict is
worth less than it looks, and the reason is uncomfortable: `passes` at the
reference parameters is equally consistent with "the mechanism is sound" and
"the reference parameters were chosen -- consciously or not -- to be a point
where it passes." Nothing in the verdict distinguishes those.

`proofwork incentives --robustness` distinguishes them. For each parameter it
walks outward on a geometric ladder and reports the first rung at which the
report stops passing, in *both* directions -- because `fraud_rate` breaks the
mechanism by getting smaller, and a one-directional search would call it safe.

The result contradicts where this document spends its attention:

```
  stake: 4000000 survives 1.25x, breaks lowering to 3200000
  sealed_value: 2000000 survives 1.25x, breaks raising to 2500000
  slash_rate: 10000 survives 1.25x, breaks lowering to 8000
  detection_rate: 50000 survives 1.25x, breaks lowering to 40000
  ...
  verify_cost: 200 survives 16.00x, breaks raising to 3200
  canary_rate: 1000 survives 16.00x, breaks lowering to 62
  binding constraint    stake -- measure this one first
```

**The four tightest constraints are all custody.** Verification -- the sub-game
this document argues about at length, and the one with the interesting
structural result -- survives a sixteenfold error in the cost of a check.
Custody does not survive a quarter. The interesting argument is not the fragile
one, and no passing verdict would have said so.

See [proving-it.md](proving-it.md) for what that does and does not establish.

## Where this is wrong

Every number is a parameter somebody has to measure, and the output is a
conditional: *if* verification costs this and fraud pays that, *then* these are
the equilibria. It cannot tell you the fraud rate.

More specifically:

- **Operators are modelled as maximising money over one epoch.** No reputation,
  no legal exposure, no repeated play, and none of the people who would run a
  node because they want the thing to exist. All of those point towards more
  honesty than this predicts, which is the right direction for a security
  argument to be wrong in.
- **Canaries must be indistinguishable from real submissions.** This is the
  assumption everything rests on and it is an engineering problem, not an
  economic one: canaries need to come from the same pipeline, with the same
  identity distribution, against live objectives. `canary_leak` is set nonzero
  in the reference parameters deliberately, so no report quietly assumes
  perfection — and at `canary_leak = 1` the harness reports that no canary rate
  works at all.
- **Full sampling redundancy.** Every node is modelled as checking the same
  artifact. Under real sampling a rubber-stamper is caught only if a verifier
  drew the same item, which weakens the conditional term further and makes the
  canary argument *stronger*. Modelling full redundancy is the conservative
  choice, not a convenient one.
- **Worst-case committee liveness.** The committee analysis is combinatorial —
  "up to `n − t` members may fail" — not probabilistic. A probabilistic model
  needs an availability assumption the harness does not have and would not be
  able to justify.
- **The three sub-games are solved independently, and one operator plays all
  three with one bond.** `stake` is slashable in verification, in availability
  and in custody, so a deviation that risks the bond in one game changes what
  the others cost -- an operator already facing a custody slash has less left to
  lose by rubber-stamping. Separability is assumed rather than proved, and
  unlike every other caveat here it is assumed in the direction that *flatters*
  the mechanism. It is also structural: no choice of parameters fixes it.
- **No saturation proof.** Bounded parameters keep every payoff far inside
  `i128`, but that is a *tested* property rather than a proved one, which is why
  every service finding carries an `exact` flag and a report says so when the
  arithmetic ran out of room.

## Status

This is a mechanism and its evaluation, not shipped code paths. Nothing in
`src/incentive/` runs at settlement time, no canary is generated, no bond is
posted, and no Merkle challenge is issued. See [roadmap.md](roadmap.md) — the
mechanism lands with Stage 2's permissionless verification, and the point of
building the harness first is that the parameters it demands (a committee that
scales with sealed value, a bond in the millions, a canary rate a real pipeline
has to sustain) are the kind of thing that is very expensive to discover
afterwards.
