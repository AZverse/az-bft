# Release status

## Alpha release

AZBFT `v0.1.0-alpha` publishes a deterministic, sans-I/O BFT consensus core,
cryptographic certificate implementation, bounded in-memory devnet, portable
finality transcript, offline verifier, and local CLI.

It is intended for protocol evaluation, integration development, and
reproducible consensus demonstrations.

## Included boundary

- Proposal, vote, timeout, QC, TC, commit, evidence, reconfiguration, and
  checkpoint data structures.
- Deterministic safety, pacemaker, commit, recovery, and reconfiguration state
  transitions.
- secp256k1 signing for consensus messages and certificates.
- BLS12-381 aggregate signatures for QCs, including proof-of-possession checks
  when BLS validator keys are adopted.
- A deterministic four-validator devnet with test-only identities.
- Offline transcript verification and inspection.

## Host responsibilities

Production transport, durable storage, payload acquisition, execution,
validator key management, peer discovery, operator configuration, metrics
export, and deployment topology are not included.

Equivocation evidence persistence is a host responsibility. The core detects
conflicting signed votes and emits an evidence command before dependent
network output. The deterministic devnet intentionally treats that durable
host effect as a no-op.

## Known limitations

- Jailed-validator state is not carried in checkpoints. A catching-up validator
  that did not replay the relevant jail transition can reject a later valid
  return reconfiguration. Deployments using validator jailing must replay the
  required history until a checkpoint format carrying this state is defined.
- Consumed-evidence state is not carried in checkpoints. A Host must persist or
  replay finalized evidence before voting after checkpoint adoption so an
  already punished equivocation cannot be reused. A later checkpoint version
  will carry this replay-protection state explicitly.
- Timeout votes and timeout certificates use secp256k1 even when the network
  forms quorum certificates with BLS.
- Production networking and node admission are outside this repository.
- Deterministic seed-derived keys are test/devnet facilities and must never be
  used for validator, operator, or other production identities.

## Compatibility policy

The alpha wire format and public Rust API may change before the first stable
release. Changes that affect transcript verification or certificate encoding
will be called out explicitly in release notes.
