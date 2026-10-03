# Changelog

All notable user-visible changes to AZBFT are documented here. The project uses
Semantic Versioning for source releases, including prerelease identifiers.

## [Unreleased]

### Fixed

- The pacemaker backoff is no longer reset when a round is left by timeout
  certificate, only when a round is certified. Resetting on every advance
  capped the round timer at one doubling, so a chain whose proposals arrived
  after the timer could not recover by backing off.

### Changed

- The round timer stops growing after six doublings (64 times the base) instead
  of sixteen. With the backoff now carried across timed-out rounds the cap is
  reachable, and it bounds how long validators wait once the cause is gone.

## [0.1.0-alpha] - 2026-08-04

### Added

- Deterministic sans-I/O consensus state machine with weighted validators,
  proposal/vote/timeout processing, QC/TC formation and two-chain finality.
- Persist-before-dependent-effects safety snapshots and linked commit
  certificates for restart and finality verification.
- secp256k1 consensus signatures, BLS12-381 QC aggregation and validator
  proof-of-possession checks.
- Reconfiguration, equivocation evidence, operator authorization, jailing,
  epoch-change certificates and genesis-anchored checkpoints.
- Deterministic four-validator devnet, portable finality transcripts, offline
  verifier and local CLI.
- Versioned protocol specification, conformance fixtures and short public CI.

### Compatibility

- Cargo package version: `0.1.0-alpha`.
- Source tag: `v0.1.0-alpha`.
- Block header version: 2.
- Transcript version: 1.
- The Rust API and wire encoding remain alpha and may change in a later release;
  encoding, signature-preimage and finality changes require explicit release
  notes and a new versioned specification.

### Known limitations

- Checkpoints do not carry jailed-validator state.
- Timeout certificates remain secp256k1 when QCs use BLS.
- Production networking, execution, key management and node admission are Host
  responsibilities outside this repository.
