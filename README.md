# AZBFT

AZBFT is the BFT consensus engine powering the permissioned AZ Layer 1.

AZBFT implements a weighted, two-chain HotStuff-family protocol with deterministic safety, pacemaking, reconfiguration, and recovery rules.

This repository contains the consensus state machine, safety rules, cryptography, deterministic devnet, offline finality verifier, and local command-line tools used to demonstrate AZBFT behavior.

> **Release status:** `v0.1.0-alpha`. This is a source release of the sans-I/O
> consensus core and deterministic tooling, not a production node
> distribution. See [STATUS.md](STATUS.md) for the supported boundary and known
> limitations.

## Repository boundary

Production transport is not included in this repository.

The public package has no production networking stack, execution client, operator configuration, validator credentials, or deployment topology. Its devnet is an in-memory deterministic scheduler with test-only identities. The resulting transcripts carry real quorum signatures and linked commit certificates and can be verified offline.

## Components

- `azbft-types`: canonical blocks, votes, quorum certificates, timeout certificates, evidence, reconfiguration, and checkpoint types.
- `azbft-crypto`: domain-separated secp256k1 and BLS12-381 signing and quorum aggregation.
- `azbft-safety`: deterministic two-chain voting and locking rules.
- `azbft-core`: sans-I/O consensus state machine expressed as `Event -> Vec<Command>`.
- `azbft-devnet`: bounded four-validator deterministic execution harness.
- `azbft-verifier`: offline transcript and commit-certificate verification.
- `azbft-cli`: local devnet, verify, and inspect commands.

## Quick start

The workspace requires Rust 1.93 or later.

```bash
cargo test --workspace

cargo run -p azbft-cli --bin azbft -- \
  devnet run --validators 4 --blocks 20 --seed 42 --output azbft-20.azbft

cargo run -p azbft-cli --bin azbft -- verify azbft-20.azbft

cargo run -p azbft-cli --bin azbft -- \
  inspect azbft-20.azbft --height 10
```

A healthy four-validator run finalizes the requested blocks. The fault harness also demonstrates recovery after an unavailable leader and refuses to claim finality when fewer than quorum participants are available.

## Project documentation

- [Protocol specification](spec/v0.1.0-alpha/README.md)
- [Release status and known limitations](STATUS.md)
- [Project roadmap](ROADMAP.md)
- [Contribution policy](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Release policy](RELEASES.md)
- [Changelog](CHANGELOG.md)
- [Provenance](PROVENANCE.md)

## Consensus surface

The core accepts and emits only three signed consensus message classes: proposal, vote, and timeout. Host-specific payload transfer, execution, networking, and operations remain outside the core. This keeps the consensus package deterministic and reusable without exposing a production node endpoint.

## License and provenance

AZBFT is licensed under Apache License 2.0. See [LICENSE](LICENSE), [NOTICE](NOTICE), [PROVENANCE.md](PROVENANCE.md), and [THIRD_PARTY.md](THIRD_PARTY.md).

## Protocol specification

The normative alpha protocol is versioned under
[`spec/v0.1.0-alpha/`](spec/v0.1.0-alpha/README.md). It defines the weighted
fault model, two-chain finality, Host command contract, canonical encoding,
recovery and reconfiguration behavior implemented by this source release.
