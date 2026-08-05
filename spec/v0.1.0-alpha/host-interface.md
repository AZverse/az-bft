# Host Interface

## Deterministic transition

The public consensus boundary is:

```text
handle(Event, logical_time) -> Vec<Command>
```

For identical initialized state, event order and logical time, compatible
implementations MUST produce equivalent state transitions and command order.
The core performs no file, socket, process, wall-clock or execution-client I/O.

## Events

The Host may deliver:

- `Proposal`, `Vote`, and `RemoteTimeout`: signed consensus messages;
- `LocalTimeout(round)`: expiry of a timer previously requested by the core;
- `PayloadReady { context, payload }`: result of an earlier payload request;
- `RequestReconfig`: operator-authorized next validator set;
- `RequestRemoval`: evidence-authorized validator removal;
- `RequestJail`: operator-authorized temporary removal with a return epoch;
- `SyncApply { blocks, commit_qc }`: an already validated synchronization
  segment and its commit QC.

The Host MUST preserve message bytes until decoding and signature verification.
It MUST use the logical time supplied to the transition for live timestamp
validation. Replay validation omits local wall-clock drift checks but retains
canonical chain checks.

## Commands and order

The core may return:

- `Persist(snapshot)`: durably store safety state;
- `Broadcast(message)` or `Send(node, message)`: hand a signed message to the
  transport owned by the Host;
- `SetTimer(round, duration)` and `CancelTimer`;
- `CreatePayload { round, parent }`: begin deterministic payload preparation;
- `Commit(committed_block)`: append one finalized block and its linked proof;
- `Equivocation(proof)`: retain or forward verified double-sign evidence.

The Host MUST process commands in vector order. When handling an event changes
`last_voted_round` or `preferred_round`, `Persist` is placed before messages or
commits that depend on that state. The Host MUST atomically persist and force
that snapshot before continuing with later commands in the batch.

The Host MUST treat stale timers and stale payload results as discardable. It
MUST NOT reuse a payload whose build context no longer exactly matches the
current epoch, round and parent certificate.

## Ordered, finalized and executed pipeline

AZBFT can finalize ahead of execution. The intended flow is:

```text
proposal/certification -> Command::Commit -> durable ordered queue -> execution
```

`Command::Commit` is the consensus finality boundary. The Host appends commit
commands in their emitted ancestor-first order. It may execute them
asynchronously and may have multiple pending finalized blocks, but execution
MUST preserve that order and MUST be deterministic for the same block sequence.

Execution results, state roots, receipts, mempool policy and proposal payload
selection are opaque Host data. They are not consensus-core types in this
release.

## Payload and proposal responsibilities

`CreatePayload` requests data; it does not authorize a proposal by itself. The
Host prepares bytes under its local policy and returns `PayloadReady` with the
immutable build context. The core hashes the payload and constructs/signs the
proposal only if the context remains current.

Payload availability and semantic validation are Host responsibilities. Every
validator must apply deterministic admission rules if those rules affect
voting. The public core does not prescribe transaction ordering or expose an
execution endpoint.

## Evidence responsibility

The core detects verified double votes and emits `Equivocation` before any
co-emitted quorum-dependent output. The Host is responsible for durable
evidence retention or forwarding. The deterministic devnet intentionally
acknowledges this effect without durable storage.
