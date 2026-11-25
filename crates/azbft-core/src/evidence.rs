use azbft_crypto::domain::Domain;
use azbft_types::evidence::EquivocationProof;
use azbft_types::{
    operator_multisig_decode, reconfig_signing_bytes, reconfig_signing_bytes_jail, OperatorSet,
    Reconfig, ValidatorSet,
};
use std::collections::BTreeSet;

/// True iff `p` is a valid equivocation: same (voter, epoch, round), different
/// block_id, canonical order, and BOTH signatures verify under the voter's key.
///
/// Replay handling is intentionally outside this pure cryptographic verifier.
/// `ConsensusCore` records committed evidence by `(voter, epoch, round)` and
/// rejects later reconfiguration proposals that reuse a consumed act. Hosts
/// must preserve that derived ledger across epoch changes and recovery.
pub fn verify_equivocation_proof(p: &EquivocationProof, vset: &ValidatorSet) -> bool {
    let (a, b) = (&p.vote_a.inner, &p.vote_b.inner);
    if a.voter != b.voter || a.epoch != b.epoch || a.round != b.round {
        return false;
    }
    if a.block_id == b.block_id {
        return false; // must conflict
    }
    if a.block_id > b.block_id {
        return false; // must be canonical order
    }
    let Some(pk) = vset.pubkey_of(&a.voter).map(|p| p.to_vec()) else {
        return false;
    };
    azbft_crypto::keypair::verify(
        Domain::Vote,
        &azbft_types::vote_digest(&a.block_id, a.round).0,
        &p.vote_a.sig,
        &pk,
    ) && azbft_crypto::keypair::verify(
        Domain::Vote,
        &azbft_types::vote_digest(&b.block_id, b.round).0,
        &p.vote_b.sig,
        &pk,
    )
}

/// Gate for reconfig blocks: any carried evidence must be valid AND justify a
/// legitimate punishment in this reconfig. Accepted punishment forms:
///
/// 1. **Removal**: the offender is in `current` but NOT in `next_set`.
/// 2. **Stake slash**: the offender is in BOTH `current` AND `next_set`,
///    but `next_set` carries a strictly smaller stake for that offender than
///    `current` does. This is the new slash branch — the offender stays in the
///    validator set but their economic weight is reduced.
///
/// Empty evidence passes this evidence-only helper; the caller separately requires
/// operator authorization for an ordinary reconfiguration.
/// Invalid/forged evidence, evidence against a non-member, or evidence where
/// the offender's stake was NOT actually reduced → returns false.
pub fn verify_removal_justified(current: &ValidatorSet, rc: &Reconfig) -> bool {
    for p in &rc.evidence {
        let voter = p.vote_a.inner.voter;
        // Offender must be a current member.
        if !current.contains(&voter) {
            return false; // voter not in current set — irrelevant evidence
        }
        // Exactly one of two justified forms must hold:
        //   (a) removal: offender absent from next_set.
        //   (b) stake slash: offender present in next_set with strictly
        //       reduced stake (no forgery: next_stake < current_stake).
        let current_stake = current.stake_of(&voter).expect("just checked contains");
        let justified = if !rc.next_set.contains(&voter) {
            // Form (a): removal.
            true
        } else {
            // Form (b): slash — stake strictly reduced.
            let next_stake = rc.next_set.stake_of(&voter).expect("just checked contains");
            next_stake < current_stake
        };
        if !justified {
            return false; // neither removed nor slashed — irrelevant evidence
        }
        if !verify_equivocation_proof(p, current) {
            return false; // invalid/forged equivocation proof
        }
    }
    true
}

/// Verify an M-of-N operator authorization over `msg` (Domain::Reconfig).
///
/// - Single-key authority: `sig_bytes` is a raw secp256k1 signature verified
///   against the sole key.
/// - M-of-N: `sig_bytes` decodes (borsh) to `(key_index, signature)` pairs; the
///   authorization holds iff at least `threshold` DISTINCT keys each contribute
///   one valid signature over `msg`. A repeated index counts once; an
///   out-of-range index or invalid signature contributes nothing; malformed
///   bytes fail closed. The pair list is capped at `keys.len()` (a well-formed
///   multi-sig never exceeds one pair per operator), bounding verify work at N.
pub(crate) fn verify_operator_multisig(set: &OperatorSet, msg: &[u8], sig_bytes: &[u8]) -> bool {
    if set.is_legacy_single() {
        return azbft_crypto::keypair::verify(Domain::Reconfig, msg, sig_bytes, &set.keys[0]);
    }
    let Some(pairs) = operator_multisig_decode(sig_bytes) else {
        return false;
    };
    if pairs.len() > set.keys.len() {
        return false;
    }
    let mut seen: BTreeSet<u16> = BTreeSet::new();
    for (idx, sig) in &pairs {
        let i = *idx as usize;
        if i >= set.keys.len() || seen.contains(idx) {
            continue;
        }
        if azbft_crypto::keypair::verify(Domain::Reconfig, msg, sig, &set.keys[i]) {
            seen.insert(*idx);
        }
    }
    (seen.len() as u32) >= set.threshold
}

/// Evidence names who may be punished; it authorizes nothing else. Every
/// surviving member keeps its exact secp key, BLS key and proof of possession,
/// and only an offender named by the evidence may lose stake. Without this, a
/// genuine proof against one validator could carry a stake or key change for
/// another one through the operator-free path (AZverse/layer1_infra#61).
fn only_offenders_changed(current: &ValidatorSet, rc: &Reconfig) -> bool {
    rc.next_set.members().iter().all(|next| {
        let Some(before) = current
            .members()
            .iter()
            .find(|member| member.node_id == next.node_id)
        else {
            return false;
        };
        let offender = rc
            .evidence
            .iter()
            .any(|proof| proof.vote_a.inner.voter == next.node_id);
        let stake_allowed = if offender {
            next.stake <= before.stake
        } else {
            next.stake == before.stake
        };
        stake_allowed
            && next.pubkey == before.pubkey
            && next.bls_pubkey == before.bls_pubkey
            && next.bls_pop == before.bls_pop
    })
}

/// Authorize a reconfig block: EITHER a valid operator signature over
/// (next_set, epoch[, jail]), OR a pure evidence-driven punishment (Evidence-based removal / Stake slashing).
/// Empty-evidence + no-signature ⇒ rejected (closes the unauthorized-reconfig gap).
///
/// - Path 1: operator-signed — any change to the validator set (additions,
///   removals, or stake adjustments) authorized by a valid operator authority
///   over the canonical bytes (Domain::Reconfig), verified via
///   `verify_operator_multisig` (single key or M-of-N). Binds the sig to the
///   specific set, epoch, and (for jail reconfigs) jail record, preventing
///   replay and tampering of the jail term.
///   - Plain reconfig / slash: signed over `reconfig_signing_bytes(next_set, epoch)`.
///   - Jail reconfig (`rc.jail.is_some()`): signed over
///     `reconfig_signing_bytes_jail(next_set, epoch, &rc.jail)`, which includes
///     the JailRecord (offender + until_epoch) to prevent tampering post-signing.
/// - Path 2: pure evidence-driven punishment — no additions (every next_set
///   member was in current), a non-empty next_set, no change to any surviving
///   member's keys or proof of possession, no stake change except a reduction
///   for an offender named by the evidence, non-empty evidence, every proof valid+relevant
///   (verify_removal_justified rejects irrelevant/invalid/fake-slash), and
///   every punished validator (removed OR stake-slashed) is covered by at
///   least one proof in the evidence list.
pub fn verify_reconfig_authorized(
    current: &ValidatorSet,
    rc: &Reconfig,
    epoch: u64,
    operator_set: &OperatorSet,
) -> bool {
    // Path 1: operator-signed (any change).
    // For jail reconfigs the signing bytes include the JailRecord to prevent
    // tampering (e.g. extending until_epoch after the operator signed).
    // Plain reconfigs use the legacy two-field form for backward compatibility.
    if let Some(sig) = &rc.operator_sig {
        // Consumed-evidence replay protection: operator authorization requires EMPTY evidence. The operator
        // signature covers only (next_set, epoch[, jail]) — NOT the `evidence` field —
        // so authorizing an evidence-bearing reconfig via operator_sig alone would let
        // a Byzantine proposer attach arbitrary garbage proofs to an otherwise-valid
        // operator signature. Those act keys would then be recorded into the insert-only
        // consumed-evidence ledger on commit and permanently deny any FUTURE genuine
        // evidence-driven (Path 2) punishment of those acts. Honest operator reconfigs
        // always stage evidence=[]; a reconfig that carries evidence MUST be authorized
        // via the pure-evidence path below (which validates every proof), so the
        // recorded acts are always ones this reconfig actually punished.
        if rc.evidence.is_empty() {
            let msg = if rc.jail.is_some() {
                reconfig_signing_bytes_jail(&rc.next_set, epoch, &rc.jail)
            } else {
                reconfig_signing_bytes(&rc.next_set, epoch)
            };
            if verify_operator_multisig(operator_set, &msg, sig) {
                return true;
            }
        }
    }
    // Path 2: pure evidence-driven punishment — no additions, non-empty
    // evidence, every proof valid+relevant, and every punished validator
    // (removed OR stake-slashed) is covered by at least one proof.
    let no_additions = rc
        .next_set
        .members()
        .iter()
        .all(|m| current.contains(&m.node_id));
    if no_additions
        && !rc.next_set.is_empty()
        && !rc.evidence.is_empty()
        && only_offenders_changed(current, rc)
        && verify_removal_justified(current, rc)
    {
        // A member is "punished" if:
        //   (a) removed: in current but not in next_set.
        //   (b) stake-slashed: in both but with strictly reduced stake in next_set.
        // Every punished member must be covered by at least one evidence proof.
        let all_punished_covered = current.members().iter().all(|m| {
            let id = &m.node_id;
            // Not punished at all — no coverage needed.
            let removed = !rc.next_set.contains(id);
            let slashed = rc
                .next_set
                .stake_of(id)
                .map(|ns| ns < m.stake)
                .unwrap_or(false);
            if !removed && !slashed {
                return true;
            }
            // Punished — must be covered by some proof.
            rc.evidence.iter().any(|p| &p.vote_a.inner.voter == id)
        });
        if all_punished_covered {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests;
