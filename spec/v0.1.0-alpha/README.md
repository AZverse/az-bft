# AZBFT Protocol Specification v0.1.0-alpha

This directory specifies the consensus behavior implemented by the AZBFT
`v0.1.0-alpha` source release.

## Normative scope

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT,
and MAY describe requirements for implementations that claim compatibility
with this version. The alpha wire format and Rust API may change in later
versions; a change to canonical bytes, signing preimages, certificate
validation or finality rules requires a new specification version.

The normative documents are:

- [Protocol](protocol.md): fault model, validators, rounds, certificates,
  timeouts and finality.
- [Host interface](host-interface.md): deterministic events, ordered commands,
  persistence and the execution boundary.
- [Encoding and cryptography](encoding.md): canonical bytes, hashes, signing
  domains and certificate encodings.
- [Recovery and reconfiguration](recovery-and-reconfiguration.md): restart,
  synchronization, checkpoints and epoch changes.

If code and this specification disagree at the `v0.1.0-alpha` tag, the
inconsistency is a release defect and must be reported.

## System and fault model

AZBFT is a weighted Byzantine fault-tolerant state-machine-replication
protocol. Each epoch has a finite validator set with total voting weight `W`.
A quorum has weight `floor(2W/3) + 1`. Safety assumes Byzantine voting weight is
less than one third of `W` and honest validators preserve their safety state
across restart. Liveness assumes partial synchrony: after an unknown global
stabilization time, messages between responsive honest validators arrive
within a bounded delay, more than two thirds of voting weight remains
responsive, and honest leaders are eventually selected.

The core is sans-I/O. Network delivery, timers, durable storage, payload
availability, execution, key custody and operator policy are Host
responsibilities and are outside this source distribution.

## Terminology

- **Proposed:** a leader has signed and distributed a candidate block.
- **Certified:** a valid quorum certificate (QC) names the block and round.
- **Finalized:** a valid adjacent-round two-chain commits the parent block.
- **Ordered:** the ancestor-first sequence of finalized blocks emitted through
  `Command::Commit`. In this version ordering and finality occur at the same
  core transition.
- **Executed:** a Host has applied an ordered block to its deterministic state
  machine. Execution may trail finality and cannot revoke or redefine it.
- **Host:** the embedding node component that supplies events and performs
  commands in order.

## Host responsibility

A compatible Host MUST execute each returned command batch in vector order,
MUST durably complete `Command::Persist` before any later dependent command in
the same batch, and MUST preserve finalized block order. The Host MUST NOT
interpret an unfinalized proposal or QC as an execution commitment.

This repository does not specify production transport, node admission, an
execution-client protocol or a public validator endpoint.
