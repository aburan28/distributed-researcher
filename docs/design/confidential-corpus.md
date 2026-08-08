# A confidential corpus, and what else this design can carry

Two questions, taken together because the answer to the second constrains the
first: which kinds of claim can this network settle, and how does material the
network cannot read fit alongside them.

`src/corpus.rs` implements the storage and release half. This note records the
evaluation that produced it, and the parts deliberately left undone.

## What the design actually requires of a claim

The founding guarantee is that anyone can re-derive every settled result from
the log alone. That is not a statement about mathematics. It is a statement
about **decidability against a pinned artifact**, and it is worth being precise
about the boundary, because the temptation is to widen the network to "research"
and discover afterwards that the guarantee went with it.

| domain | how a verdict is reached | deterministic | cheap | fits |
|---|---|---|---|---|
| formal proof (Lean, Coq, Metamath) | kernel re-checks the proof term | yes | yes | **fully** |
| certificates (DRAT/UNSAT, LP duality, Pratt/ECPP primality) | check the certificate, never redo the search | yes | yes, asymmetrically | **fully** |
| verified computation | replay under a pinned environment | only if the environment is pinned | usually | **with care** |
| benchmark/held-out evaluation | run the pinned scorer on pinned data | yes | yes | **with care** — the data must be in the log's reach |
| numerical simulation | bitwise replay | only with pinned FP semantics | often not | **partial** |
| empirical results (measurement, wet lab) | repeat the experiment | no | no | **no** |
| historical and archival scholarship | weigh evidence, argue | no | no | **no** |

The line is not "hard science versus soft". It is whether a verdict is a
*function of the artifact* or a *judgement about the world*. Everything above
the line has a decision procedure; everything below it has an argument.

This matters because the bottom two rows are exactly where a knowledge base of
research papers points. A corpus of history papers is entirely servable by this
network and entirely unsettleable by it: the documents are artifacts, and the
claims made in them are not certificate-checkable. Trying to pay for the latter
means either inventing an oracle or falling back to adjudication —
TrueBit-style dispute games, or staked prediction in the Numerai shape — and
both replace "cheap to check" with "expensive to arbitrate", which is a
different system with a different threat model. Storing the corpus is in scope.
Settling claims about its contents is not, and should be said out loud rather
than discovered.

## Proof of history

The phrase carries two meanings and both are live here.

**Sequential-time proofs.** Solana's Proof of History is a sequential hash chain
whose length is evidence that time passed: generation is inherently serial,
verification parallelises. True VDFs (Wesolowski; Pietrzak) do the same with a
succinct proof, over groups of unknown order.

This is directly relevant to two open items rather than being a new idea to
graft on:

- `beacon(epoch, anchor)` needs to be unbiasable. `AGENTS.md` already records
  that any part of the settlement key a submitter can re-roll is a free lottery
  ticket. A VDF-derived beacon closes the remaining re-roll surface, because a
  value that takes *T* sequential steps to compute cannot be ground against.
- `docs/p2p.md` lists settlement order across peers as unsolved: each node keys
  its batch on its own ledger head, and two independently ordered logs do not
  share one. A shared sequential-time chain is a common clock that needs no
  consensus, which is precisely the shape of the missing piece.

Priority is the third use and the one a research network feels most. "Who got
there first" is currently answered by `created_at`, which is self-reported and
which `src/time.rs` correctly calls advisory. Commit–reveal stops a submitter
copying somebody else's artifact, and does nothing to stop them backdating their
own. A sequential-time anchor is what turns a timestamp into evidence.

**History as a discipline** is the other reading, and the table above answers it:
servable, not settleable.

## The corpus itself

Implemented in `src/corpus.rs`. The design in one line: **the serving node is
never given a key**, which is a different and stronger property than encrypting
a node's own store.

`src/store/atrest.rs` is explicit that it does not defend against live access to
a running node, because the key must be readable for the node to work. Building
confidentiality-from-the-operator on that would inherit exactly the caveat it
warns about. So the corpus reuses none of it. A document is sealed by its
contributor, addressed by the hash of its ciphertext, and served as bytes whose
meaning the holder has no route to.

Three claims hide under "nodes must never view the material":

| claim | status |
|---|---|
| a serving node holds bytes it cannot read | held — it never receives a key |
| no single node can decrypt unilaterally | held — the content key is split `t`-of-`n` |
| no operator can ever read the material | **not holdable.** Whoever may read it may also run a node |

The third is access control wearing a cryptography costume. Saying so is the
same discipline `docs/threat-model.md` applies elsewhere.

### Release is policy, not cryptography

`Document::open` refuses before the release epoch, and that refusal binds
whoever calls the code and nobody else. Any `t` colluding committee members can
combine shares whenever they like. The epoch is what an *honest* committee waits
for; the security argument is the cost of collusion among `t` members, which
`proofwork incentives` already models and which needs a `threat-model.md` row it
does not yet have.

`open_regardless` exists so this is visible in one place rather than smeared
through the decryption path, and so a committee can demonstrate what early
opening would produce. It is not an escalation: anyone holding `t` shares can
already do it.

### Decisions worth their cost

**The plaintext digest is sealed, not published.** Publishing it would be
convenient and would be a confirmation-of-file oracle: anyone with a candidate
document could test membership by hashing it, which for an embargoed preprint is
most of what an adversary wanted. After release the digest is what makes a
citation checkable.

**Addressing is over ciphertext.** Same reason, and it costs deduplication
between two independent contributions of one document. Convergent encryption
would buy that back at exactly the price just refused.

**The release epoch is in the AAD.** A committee that published for an epoch-10
document has not thereby opened an epoch-200 one. `a_share_does_not_carry_across_two_release_epochs` pins it.

### What does not change, and one thing that improves

Availability sampling is a Merkle root over ciphertext chunks, so a node proves
possession without comprehension and the existing challenge needs no
modification.

The improvement is real and slightly surprising. `src/incentive/mod.rs` explains
that verification is the hard service because canaries must be indistinguishable
from honest work. For *storage*, canaries are indistinguishable **by
construction**: a node cannot tell a canary document from a real one when it can
read neither. Blind storage makes the availability game easier to keep honest,
not harder.

## Deliberately not built

**A time-lock backstop.** RSW puzzles would make early opening cost sequential
work rather than agreement, and would remove committee liveness from the release
path. Composing it as a *second* recovery path for one key means confidentiality
becomes the weaker of the two branches — you get robustness of release and lose
the tighter confidentiality bound. That is a real trade and belongs in a
decision, not in a commit.

**Per-reader access control.** Proxy re-encryption (Blaze–Bleumer–Strauss;
Ateniese et al.) lets a semi-trusted proxy convert owner-ciphertext to
reader-ciphertext without seeing plaintext, which maps onto blind nodes well. It
is orthogonal to time release and composes with it.

**Search.** The largest gap, and the one that decides whether this is a
knowledge base or a filesystem. Searchable symmetric encryption exists and leaks
access patterns; the leakage-abuse literature (Islam–Kuzu–Kantarcioglu;
Cash et al.; Grubbs et al.) recovers a great deal from that leakage. PIR avoids
it and is expensive. There is no version of this that is both cheap and
leak-free, so it needs a decision and a threat-model row rather than an
implementation.

**Traffic analysis.** A blind node still learns which document was requested, by
whom, and how often. If readership is sensitive, encryption at rest does not
touch it.

## Threat-model rows this owes

Three, none of them written yet:

- **early committee opening** — `t` members collude before the release epoch.
  Partial: priced, not prevented.
- **corpus search leakage** — not handled; nothing is implemented, and the
  honest entry says so rather than leaving the row absent.
- **readership deanonymisation** — not handled.
