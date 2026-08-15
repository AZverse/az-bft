# Roadmap

This roadmap separates release operations for the current source alpha from
later protocol-assurance and production-readiness work. It is a statement of
scope and sequencing, not a delivery-date commitment.

## Public alpha release

- Complete participant source-origin confirmation, including the exact public
  revisions and review time ranges for implementation references.
- Create the public GitHub repository and enable private vulnerability
  reporting before changing visibility.
- Run the checked-in short GitHub Actions workflow from a clean public clone.
- Review the repository description and create the signed annotated
  `v0.1.0-alpha` tag.

These are release-owner operations.

## Beta protocol assurance

- Define a versioned checkpoint format that carries jailed-validator and
  consumed-evidence state and add migration fixtures.
- Expand Host recovery conformance for durable safety state, committed-tip
  restoration, checkpoint adoption, evidence retention and replay.
- Decide whether timeout certificates also use BLS or remain secp256k1, then
  update the versioned specification and fixtures for that decision.
- Build an executable consensus model in Quint or TLA+ and model-check the
  voting, locking, timeout, commit and reconfiguration invariants.
- Add system-level Byzantine scenarios covering Twins, network partition and
  heal, message duplication, reordering and delay, combined validator
  crash/restart, and randomized model-based event sequences.
- Establish contribution licensing, a code of conduct and maintainer
  governance before accepting external pull requests.

These tasks improve assurance. They do not block the source-only alpha while
the current limitations remain explicit in `STATUS.md` and the versioned spec.

## Mainnet readiness

- Complete an independent security assessment of the consensus core,
  cryptographic integration, recovery contract and versioned wire format.
- Resolve assessment findings and repeat adversarial, recovery, upgrade and
  operational qualification against a release candidate.
- Freeze compatibility and coordinated-upgrade rules for the first supported
  production release.

Production transport, execution integration, validator admission, key
management and deployment topology remain outside this public repository.
