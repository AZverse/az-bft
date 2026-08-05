# Third-party software

The following direct dependencies are resolved by the current `Cargo.lock`. Their source remains governed by their respective licenses.

| Dependency | Resolved version | License expression | Use |
|---|---:|---|---|
| borsh | 1.8.0 | MIT OR Apache-2.0 | Deterministic encoding |
| blake3 | 1.8.5 | CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception | Hash commitments |
| blst | 0.3.17 | Apache-2.0 | BLS12-381 primitives |
| k256 | 0.13.4 | Apache-2.0 OR MIT | secp256k1 signatures |
| rand_core | 0.6.4 | MIT OR Apache-2.0 | Deterministic key utilities |
| rand_chacha | 0.3.1 | MIT OR Apache-2.0 | Seeded devnet scheduling |
| thiserror | 2.0.19 | MIT OR Apache-2.0 | Typed errors |
| clap | 4.6.5 | MIT OR Apache-2.0 | Local command-line interface |
| proptest | 1.11.0 | MIT OR Apache-2.0 | Development tests |
| tempfile | 3.27.0 | MIT OR Apache-2.0 | Command integration tests |

This list covers direct workspace and test dependencies, not every transitive package. The lockfile is the authoritative resolved dependency inventory.
