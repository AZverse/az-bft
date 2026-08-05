# Recovery, Checkpoints and Reconfiguration

## Crash-safety state

Before any dependent outbound effect, the Host durably persists:

```text
SafetySnapshot {
    epoch,
    last_voted_round,
    preferred_round,
}
```

After restart, the core restores these monotonic watermarks only when the
snapshot epoch matches the initialized epoch. This prevents double voting and
lock regression across crashes. The Host MUST use an atomic replacement and
force-to-durable-storage procedure appropriate to its platform.

The block tree and `high_qc` are not part of the minimal safety snapshot. They
are reconstructed from finalized storage, a verified commit certificate and
block synchronization. A durable tip restore MUST verify its linked commit
certificate before mutating the core.

## Synchronization

`SyncApply` ingests an ordered block segment and a commit QC. A compatible Host
must obtain all missing blocks and validate canonical decoding before delivery.
The core rejects wrong-epoch, non-contiguous or uncertified input without
partially accepting an invalid finality claim.

A catching-up node must synchronize finalized consensus state before voting. It
may execute the ordered backlog asynchronously, subject to the private chain's
backpressure and admission policy, but it must not vote from unverified state.
The public core does not define network catch-up or validator admission.

## Genesis-anchored checkpoints

A checkpoint contains a finalized commit certificate, chain anchor, active
validator set and epoch. Verification starts from the configured genesis
validator set and consumes exactly one epoch-change certificate for every prior
epoch, in order and without gaps. Each handoff is verified under the preceding
validator set, and any adopted BLS keys require valid proofs of possession.

The checkpoint's height and chain anchor must equal its certified block. The
final validator set must equal the set derived by the epoch-change chain. A
failure at any step rejects the checkpoint; it does not create a new trust root.

## Reconfiguration

A block may carry a next validator set through one of two authorization paths:

1. an operator authorization over canonical reconfiguration bytes; or
2. verified equivocation evidence that exactly covers each removed or
   stake-reduced validator and introduces no new member.

An equivocation proof contains two canonically ordered, validly signed votes
from the same validator, epoch and round for different block identifiers.
Committed evidence acts are consumed and cannot be reused for a second
punishment.

A temporary jail reconfiguration records the offender and earliest return
epoch. A return is accepted only through operator authorization, after the
minimum epoch, and for a validator already recorded as jailed.

A reconfiguration block changes lifecycle only after certification. Its direct
child supplies the adjacent two-chain commit. The Host then verifies and applies
the epoch-change certificate and initializes the new epoch with its validator
set and reset round state while retaining required durable history.

## Alpha limitations

Jailed-validator state is not encoded in checkpoints in `v0.1.0-alpha`. A node
that did not replay the jail transition may reject a later valid return. A Host
using jailing MUST replay the necessary finalized history and restore jailed
state separately until a later checkpoint version carries it.

Consumed-evidence and equivocation retention also require Host persistence and
replay. Timeout certificates remain secp256k1 even when quorum certificates use
BLS. These limitations are release-visible and must not be hidden by Host
integration claims.
