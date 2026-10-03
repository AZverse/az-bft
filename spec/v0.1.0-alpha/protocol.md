# Consensus Protocol

## Epochs and validator weight

Consensus runs within an epoch identified by `u64`. A validator member contains
its `NodeId`, secp256k1 public key, optional BLS12-381 public key and
proof-of-possession, and `u64` stake. Members are sorted by `NodeId` and
deduplicated. The quorum threshold is:

```text
quorum(W) = floor(2 * W / 3) + 1
```

All vote, timeout and certificate aggregation counts distinct validator stake,
not signature count. Unknown, duplicate, malformed or below-quorum signers
invalidate an aggregate.

## Leader selection

The leader schedule is a chain constant committed by genesis.

- `round_robin` selects `members[round mod member_count]`.
- `stake_weighted` hashes the round to an integer point in `[0, W)` and selects
  the corresponding cumulative-stake bucket. It uses integer arithmetic only.

Every validator in an epoch MUST use the same schedule and validator set.

## Rounds and proposals

Rounds are monotonically increasing `u64` values within an epoch. On entering a
round, the core arms a logical timer. If the local validator is leader, it asks
the Host for a payload. The eventual `PayloadReady` event is accepted only when
its epoch, round, parent QC, height, timestamp and proposer still match the
current build context.

A proposal contains a block and an optional timeout certificate (TC) for the
previous round. The leader signs the canonical bytes of the entire proposal.
A receiver MUST reject a proposal when any of these checks fails:

1. epoch and author match the current epoch and scheduled leader;
2. the proposal signature is valid;
3. the parent QC is valid, except for the fixed genesis QC;
4. height increments the known parent by one;
5. timestamp is monotonic, advances at most 60,000 ms, and is not more than
   5,000 ms ahead of the receiver wall clock on the live path;
6. the proposal is round-justified;
7. its reconfiguration, if any, is authorized and deterministic;
8. the local safety rules permit a vote.

A consecutive proposal has `block.round = parent_qc.round + 1` and carries no
TC. A non-consecutive proposal MUST carry a valid TC for `block.round - 1` and
MUST extend the `(round, block_id)` of that TC's highest QC.

## Voting and safety rules

A vote binds epoch, block identifier, round and voter. A validator votes only
when:

```text
block.round > last_voted_round
block.parent_qc.round >= preferred_round
```

Before emitting the vote, the core advances `last_voted_round` and emits the
new safety snapshot for durable persistence. Processing a certified block
raises `preferred_round` monotonically to at least the parent-QC round.

A local timeout also advances `last_voted_round` to the timed-out round before
the timeout message is emitted. An honest validator therefore does not both
time out and later vote in that same round.

## Quorum certificates

A QC contains `block_id`, `round` and an aggregate of quorum vote signatures.
The signed vote digest binds both `block_id` and `round`; relabelling a QC to a
different round invalidates it.

QC formation may use sorted secp256k1 signatures or a BLS12-381 aggregate plus
a sorted signer set. Verification dispatches from the certificate's encoded
signature variant, so historical certificates remain verifiable after a
forming-scheme change. A validator set carrying BLS keys MUST provide a valid
proof of possession for each such key before adoption.

A verified QC may update `high_qc`, raise the safety lock, finalize blocks and
advance the local round to at least `qc.round + 1`. An unverified QC MUST have no
such effects.

## Two-chain finality

Let `P` be a block and `B` its child. `P` is finalized when:

1. `B.parent_qc` is a valid QC for `P`;
2. a valid QC certifies `B`;
3. `B.round = P.round + 1`.

The core emits newly finalized blocks in ancestor-first order. Each
`Command::Commit` carries the block and a linked commit certificate so the Host
does not reconstruct proof state from a later `high_qc`.

Finality is independent of execution. Execution failure or lag does not revert
an AZBFT finality decision.

## Timeout and view change

On local timeout the validator signs `(epoch, round)` in the timeout domain,
includes its `high_qc`, broadcasts the timeout, and backs off the next timer
exponentially. The backoff doubles on consecutive timeouts and resets only on a
certified round — one carried by a QC. Leaving a round by timeout certificate is
not progress and carries the backoff over, so the timer keeps growing while
rounds keep expiring. The timer stops growing after six doublings, at 64 times
the base, which also bounds how long recovery waits once rounds stop expiring.

Verified timeouts are deduplicated by sender and weighted by stake. Weight
exceeding the maximum Byzantine weight causes an honest validator that is
behind that future round to relay its own timeout after persisting its voting
watermark. Quorum timeout weight forms a TC. The TC selects the highest carried
QC, advances to the next round and justifies the next non-consecutive proposal.

Timeout votes and TCs use secp256k1 in this alpha even when QCs use BLS.

## Epoch boundary

A reconfiguration proposal does not end an epoch merely by being proposed. Once
its block receives a valid QC, the core permits only its direct child as the
adjacent-round commit vehicle and does not vote further in the old epoch.
Applying the resulting epoch-change certificate and starting the next epoch is
a Host lifecycle action described in the recovery specification.
