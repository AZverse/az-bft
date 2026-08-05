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
///   member was in current), non-empty evidence, every proof valid+relevant
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
    if no_additions && !rc.evidence.is_empty() && verify_removal_justified(current, rc) {
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
mod tests {
    use super::*;
    use azbft_crypto::keypair::Keypair;
    use azbft_types::evidence::EquivocationProof;
    use azbft_types::{
        blake3_id, operator_multisig_encode, reconfig_signing_bytes, Hash, OperatorSet, Reconfig,
        Round, Signed, ValidatorSet, Vote,
    };

    /// Build a single-validator set from a keypair.
    fn single_vset(kp: &Keypair) -> ValidatorSet {
        ValidatorSet::new(vec![(kp.node_id(), kp.pubkey_bytes(), 1u64)])
    }

    /// Build a valid Signed<Vote> for a given keypair, block_id, epoch and round.
    fn signed_vote(kp: &Keypair, block_id: Hash, epoch: u64, round: Round) -> Signed<Vote> {
        Signed {
            inner: Vote {
                epoch,
                block_id,
                round,
                voter: kp.node_id(),
            },
            sig: kp.sign(Domain::Vote, &azbft_types::vote_digest(&block_id, round).0),
        }
    }

    fn block_ids() -> (Hash, Hash) {
        let a = blake3_id(&b"a".to_vec());
        let b = blake3_id(&b"b".to_vec());
        // Ensure canonical order: return (smaller, larger)
        if a <= b {
            (a, b)
        } else {
            (b, a)
        }
    }

    #[test]
    fn valid_proof_verifies() {
        let kp = Keypair::from_seed(1);
        let vset = single_vset(&kp);
        let (id_a, id_b) = block_ids();
        let sv_a = signed_vote(&kp, id_a, 0, Round(3));
        let sv_b = signed_vote(&kp, id_b, 0, Round(3));
        let proof = EquivocationProof::new(sv_a, sv_b);
        assert!(verify_equivocation_proof(&proof, &vset));
    }

    #[test]
    fn tampered_sig_a_fails() {
        let kp = Keypair::from_seed(1);
        let vset = single_vset(&kp);
        let (id_a, id_b) = block_ids();
        let sv_a = signed_vote(&kp, id_a, 0, Round(3));
        let sv_b = signed_vote(&kp, id_b, 0, Round(3));
        let mut proof = EquivocationProof::new(sv_a, sv_b);
        // Flip one byte in vote_a's sig
        if let Some(byte) = proof.vote_a.sig.first_mut() {
            *byte ^= 0xff;
        }
        assert!(!verify_equivocation_proof(&proof, &vset));
    }

    #[test]
    fn tampered_sig_b_fails() {
        let kp = Keypair::from_seed(1);
        let vset = single_vset(&kp);
        let (id_a, id_b) = block_ids();
        let sv_a = signed_vote(&kp, id_a, 0, Round(3));
        let sv_b = signed_vote(&kp, id_b, 0, Round(3));
        let mut proof = EquivocationProof::new(sv_a, sv_b);
        // Flip one byte in vote_b's sig
        if let Some(byte) = proof.vote_b.sig.first_mut() {
            *byte ^= 0xff;
        }
        assert!(!verify_equivocation_proof(&proof, &vset));
    }

    #[test]
    fn same_block_id_fails() {
        let kp = Keypair::from_seed(1);
        let vset = single_vset(&kp);
        let id = blake3_id(&b"same".to_vec());
        let sv_a = signed_vote(&kp, id, 0, Round(3));
        let sv_b = signed_vote(&kp, id, 0, Round(3));
        // Bypass new() to force same block_id
        let proof = EquivocationProof {
            vote_a: sv_a,
            vote_b: sv_b,
        };
        assert!(!verify_equivocation_proof(&proof, &vset));
    }

    #[test]
    fn different_voter_fails() {
        let kp_a = Keypair::from_seed(1);
        let kp_b = Keypair::from_seed(2);
        let vset = ValidatorSet::new(vec![
            (kp_a.node_id(), kp_a.pubkey_bytes(), 1u64),
            (kp_b.node_id(), kp_b.pubkey_bytes(), 1u64),
        ]);
        let (id_a, id_b) = block_ids();
        // vote_a is from kp_a, vote_b is from kp_b — different voters
        let sv_a = signed_vote(&kp_a, id_a, 0, Round(3));
        let sv_b = Signed {
            inner: Vote {
                epoch: 0,
                block_id: id_b,
                round: Round(3),
                voter: kp_b.node_id(),
            },
            sig: kp_b.sign(Domain::Vote, &azbft_types::vote_digest(&id_b, Round(3)).0),
        };
        let proof = EquivocationProof {
            vote_a: sv_a,
            vote_b: sv_b,
        };
        assert!(!verify_equivocation_proof(&proof, &vset));
    }

    #[test]
    fn different_epoch_fails() {
        let kp = Keypair::from_seed(1);
        let vset = single_vset(&kp);
        let (id_a, id_b) = block_ids();
        let sv_a = signed_vote(&kp, id_a, 0, Round(3));
        let sv_b = signed_vote(&kp, id_b, 1, Round(3)); // different epoch
        let proof = EquivocationProof {
            vote_a: sv_a,
            vote_b: sv_b,
        };
        assert!(!verify_equivocation_proof(&proof, &vset));
    }

    #[test]
    fn different_round_fails() {
        let kp = Keypair::from_seed(1);
        let vset = single_vset(&kp);
        let (id_a, id_b) = block_ids();
        let sv_a = signed_vote(&kp, id_a, 0, Round(3));
        let sv_b = signed_vote(&kp, id_b, 0, Round(4)); // different round
        let proof = EquivocationProof {
            vote_a: sv_a,
            vote_b: sv_b,
        };
        assert!(!verify_equivocation_proof(&proof, &vset));
    }

    #[test]
    fn non_canonical_order_fails() {
        let kp = Keypair::from_seed(1);
        let vset = single_vset(&kp);
        let (id_a, id_b) = block_ids(); // id_a <= id_b
        let sv_a = signed_vote(&kp, id_a, 0, Round(3));
        let sv_b = signed_vote(&kp, id_b, 0, Round(3));
        // Directly construct with vote_a having the LARGER block_id — non-canonical
        let proof = EquivocationProof {
            vote_a: sv_b,
            vote_b: sv_a,
        };
        assert!(!verify_equivocation_proof(&proof, &vset));
    }

    #[test]
    fn voter_not_in_vset_fails() {
        let kp = Keypair::from_seed(1);
        let other_kp = Keypair::from_seed(99);
        // vset only contains `other_kp`, not `kp`
        let vset = single_vset(&other_kp);
        let (id_a, id_b) = block_ids();
        let sv_a = signed_vote(&kp, id_a, 0, Round(3));
        let sv_b = signed_vote(&kp, id_b, 0, Round(3));
        let proof = EquivocationProof::new(sv_a, sv_b);
        assert!(!verify_equivocation_proof(&proof, &vset));
    }

    #[test]
    fn canonicalization_is_order_independent() {
        let kp = Keypair::from_seed(1);
        let (id_a, id_b) = block_ids();
        let sv_a = signed_vote(&kp, id_a, 0, Round(3));
        let sv_b = signed_vote(&kp, id_b, 0, Round(3));
        let proof_xy = EquivocationProof::new(sv_a.clone(), sv_b.clone());
        let proof_yx = EquivocationProof::new(sv_b, sv_a);
        assert_eq!(proof_xy, proof_yx);
    }

    // ---- verify_removal_justified tests ----

    /// Build a valid EquivocationProof for `kp` against the given vset.
    fn valid_proof(kp: &Keypair) -> EquivocationProof {
        let (id_a, id_b) = block_ids();
        let sv_a = signed_vote(kp, id_a, 0, Round(3));
        let sv_b = signed_vote(kp, id_b, 0, Round(3));
        EquivocationProof::new(sv_a, sv_b)
    }

    #[test]
    fn removal_justified_empty_evidence_trusted() {
        // Empty evidence always returns true (trusted operator reconfig, operator-authorized path).
        let kp = Keypair::from_seed(1);
        let current = single_vset(&kp);
        let next_set = current.without(&kp.node_id());
        let rc = Reconfig {
            next_set,
            evidence: vec![],
            operator_sig: None,
            jail: None,
        };
        assert!(verify_removal_justified(&current, &rc));
    }

    #[test]
    fn removal_justified_valid_relevant_evidence() {
        // Valid proof for a voter that is in current but not next_set → true.
        let kp = Keypair::from_seed(1);
        let current = single_vset(&kp);
        let next_set = current.without(&kp.node_id());
        let proof = valid_proof(&kp);
        let rc = Reconfig {
            next_set,
            evidence: vec![proof],
            operator_sig: None,
            jail: None,
        };
        assert!(verify_removal_justified(&current, &rc));
    }

    #[test]
    fn removal_justified_bad_sig_fails() {
        // Tampered sig in the proof → false.
        let kp = Keypair::from_seed(1);
        let current = single_vset(&kp);
        let next_set = current.without(&kp.node_id());
        let mut proof = valid_proof(&kp);
        if let Some(byte) = proof.vote_a.sig.first_mut() {
            *byte ^= 0xff;
        }
        let rc = Reconfig {
            next_set,
            evidence: vec![proof],
            operator_sig: None,
            jail: None,
        };
        assert!(!verify_removal_justified(&current, &rc));
    }

    #[test]
    fn removal_justified_voter_still_in_next_set_fails() {
        // Voter appears in both current and next_set → evidence is irrelevant → false.
        let kp = Keypair::from_seed(1);
        let current = single_vset(&kp);
        // Keep the voter in next_set (no actual removal).
        let proof = valid_proof(&kp);
        let rc = Reconfig {
            next_set: current.clone(),
            evidence: vec![proof],
            operator_sig: None,
            jail: None,
        };
        assert!(!verify_removal_justified(&current, &rc));
    }

    #[test]
    fn removal_justified_voter_not_in_current_fails() {
        // Voter is not in current set at all → irrelevant → false.
        let kp_current = Keypair::from_seed(10);
        let kp_outsider = Keypair::from_seed(99);
        let current = single_vset(&kp_current);
        // next_set also has only kp_current (kp_outsider removed from nowhere)
        let next_set = current.clone();
        let proof = valid_proof(&kp_outsider);
        let rc = Reconfig {
            next_set,
            evidence: vec![proof],
            operator_sig: None,
            jail: None,
        };
        assert!(!verify_removal_justified(&current, &rc));
    }

    #[test]
    fn reconfig_borsh_roundtrip() {
        let kp = Keypair::from_seed(1);
        let current = single_vset(&kp);
        let proof = valid_proof(&kp);
        let rc = Reconfig {
            next_set: current.without(&kp.node_id()),
            evidence: vec![proof],
            operator_sig: None,
            jail: None,
        };
        let bytes = borsh::to_vec(&rc).unwrap();
        let back: Reconfig = borsh::from_slice(&bytes).unwrap();
        assert_eq!(rc, back);
    }

    // ---- Reconfiguration authorization tests ----

    const OP_SEED: u64 = 999_999;

    /// Sign the canonical reconfig bytes with the operator key.
    fn op_sign(next_set: &ValidatorSet, epoch: u64) -> Vec<u8> {
        let op = Keypair::from_seed(OP_SEED);
        op.sign(Domain::Reconfig, &reconfig_signing_bytes(next_set, epoch))
    }

    #[test]
    fn reconfig_authorized_valid_operator_sig() {
        let kp = Keypair::from_seed(1);
        let current = single_vset(&kp);
        let next_set = current.without(&kp.node_id()); // a change
        let epoch = 5u64;
        let sig = op_sign(&next_set, epoch);
        let rc = Reconfig {
            next_set,
            evidence: vec![],
            operator_sig: Some(sig),
            jail: None,
        };
        let op_pk = Keypair::from_seed(OP_SEED).pubkey_bytes();
        assert!(verify_reconfig_authorized(
            &current,
            &rc,
            epoch,
            &azbft_types::OperatorSet::single(op_pk.clone())
        ));
    }

    /// Consumed-evidence replay protection (ledger-poisoning fix): an operator-signed reconfig that ALSO
    /// carries evidence must NOT be authorized via the operator path (Path 1 now
    /// requires empty evidence). Here the proof is IRRELEVANT (its voter kp2 is NOT
    /// punished by next_set), so the pure-evidence path (Path 2) also fails and the
    /// whole reconfig is rejected. BEFORE the fix, Path 1 authorized it on the valid
    /// operator_sig alone — letting a Byzantine proposer piggyback a garbage act key
    /// that would poison the insert-only consumed-evidence ledger on commit.
    #[test]
    fn operator_sig_with_irrelevant_evidence_not_authorized() {
        let kp = Keypair::from_seed(1);
        let kp2 = Keypair::from_seed(2);
        let current = ValidatorSet::new(vec![
            (kp.node_id(), kp.pubkey_bytes(), 1u64),
            (kp2.node_id(), kp2.pubkey_bytes(), 1u64),
        ]);
        // A legitimate operator change: remove kp. Operator signs THIS next_set.
        let next_set = current.without(&kp.node_id());
        let epoch = 4u64;
        let sig = op_sign(&next_set, epoch);
        // Attach an irrelevant proof (voter kp2 is NOT removed by next_set).
        let proof = valid_proof(&kp2);
        let rc = Reconfig {
            next_set,
            evidence: vec![proof],
            operator_sig: Some(sig),
            jail: None,
        };
        let op_pk = Keypair::from_seed(OP_SEED).pubkey_bytes();
        assert!(
            !verify_reconfig_authorized(
                &current,
                &rc,
                epoch,
                &azbft_types::OperatorSet::single(op_pk.clone())
            ),
            "operator_sig + irrelevant evidence must be rejected (Path 1 needs empty \
             evidence; Path 2 fails on the unpunished voter)"
        );
    }

    #[test]
    fn reconfig_authorized_flipped_sig_fails() {
        let kp = Keypair::from_seed(1);
        let current = single_vset(&kp);
        let next_set = current.without(&kp.node_id());
        let epoch = 5u64;
        let mut sig = op_sign(&next_set, epoch);
        if let Some(b) = sig.first_mut() {
            *b ^= 0xff;
        }
        let rc = Reconfig {
            next_set,
            evidence: vec![],
            operator_sig: Some(sig),
            jail: None,
        };
        let op_pk = Keypair::from_seed(OP_SEED).pubkey_bytes();
        assert!(!verify_reconfig_authorized(
            &current,
            &rc,
            epoch,
            &azbft_types::OperatorSet::single(op_pk.clone())
        ));
    }

    #[test]
    fn reconfig_authorized_sig_over_different_next_set_fails() {
        let kp = Keypair::from_seed(1);
        let kp2 = Keypair::from_seed(2);
        let current = ValidatorSet::new(vec![
            (kp.node_id(), kp.pubkey_bytes(), 1u64),
            (kp2.node_id(), kp2.pubkey_bytes(), 1u64),
        ]);
        let next_set_for_sig = current.without(&kp.node_id());
        let next_set_in_rc = current.without(&kp2.node_id()); // different set
        let epoch = 3u64;
        let sig = op_sign(&next_set_for_sig, epoch); // signed for a different set
        let rc = Reconfig {
            next_set: next_set_in_rc,
            evidence: vec![],
            operator_sig: Some(sig),
            jail: None,
        };
        let op_pk = Keypair::from_seed(OP_SEED).pubkey_bytes();
        assert!(!verify_reconfig_authorized(
            &current,
            &rc,
            epoch,
            &azbft_types::OperatorSet::single(op_pk.clone())
        ));
    }

    #[test]
    fn reconfig_authorized_sig_for_different_epoch_fails() {
        let kp = Keypair::from_seed(1);
        let current = single_vset(&kp);
        let next_set = current.without(&kp.node_id());
        let epoch = 7u64;
        let sig = op_sign(&next_set, epoch + 1); // signed for wrong epoch
        let rc = Reconfig {
            next_set,
            evidence: vec![],
            operator_sig: Some(sig),
            jail: None,
        };
        let op_pk = Keypair::from_seed(OP_SEED).pubkey_bytes();
        assert!(!verify_reconfig_authorized(
            &current,
            &rc,
            epoch,
            &azbft_types::OperatorSet::single(op_pk.clone())
        ));
    }

    #[test]
    fn reconfig_authorized_pure_evidence_removal() {
        // next_set = current.without(X), evidence=[valid proof_X], operator_sig=None → true
        let kp = Keypair::from_seed(1);
        let current = single_vset(&kp);
        let next_set = current.without(&kp.node_id());
        let proof = valid_proof(&kp);
        let rc = Reconfig {
            next_set,
            evidence: vec![proof],
            operator_sig: None,
            jail: None,
        };
        let op_pk = Keypair::from_seed(OP_SEED).pubkey_bytes();
        assert!(verify_reconfig_authorized(
            &current,
            &rc,
            0,
            &azbft_types::OperatorSet::single(op_pk.clone())
        ));
    }

    #[test]
    fn reconfig_authorized_evidence_irrelevant_voter_still_in_next_set_fails() {
        // evidence with irrelevant proof (voter still in next_set) → false
        let kp = Keypair::from_seed(1);
        let current = single_vset(&kp);
        let proof = valid_proof(&kp);
        // next_set keeps the voter: evidence is irrelevant
        let rc = Reconfig {
            next_set: current.clone(),
            evidence: vec![proof],
            operator_sig: None,
            jail: None,
        };
        let op_pk = Keypair::from_seed(OP_SEED).pubkey_bytes();
        assert!(!verify_reconfig_authorized(
            &current,
            &rc,
            0,
            &azbft_types::OperatorSet::single(op_pk.clone())
        ));
    }

    #[test]
    fn reconfig_authorized_partial_coverage_fails() {
        // Remove X and Y but evidence only for X → Y not covered → false
        let kp_x = Keypair::from_seed(10);
        let kp_y = Keypair::from_seed(11);
        let current = ValidatorSet::new(vec![
            (kp_x.node_id(), kp_x.pubkey_bytes(), 1u64),
            (kp_y.node_id(), kp_y.pubkey_bytes(), 1u64),
        ]);
        // Remove both X and Y from next_set
        let next_set = ValidatorSet::new(vec![]);
        // Only provide evidence for X
        let proof_x = valid_proof(&kp_x);
        let rc = Reconfig {
            next_set,
            evidence: vec![proof_x],
            operator_sig: None,
            jail: None,
        };
        let op_pk = Keypair::from_seed(OP_SEED).pubkey_bytes();
        assert!(!verify_reconfig_authorized(
            &current,
            &rc,
            0,
            &azbft_types::OperatorSet::single(op_pk.clone())
        ));
    }

    #[test]
    fn reconfig_authorized_addition_present_fails() {
        // next_set has a member NOT in current (an addition) → path 2 fails
        let kp = Keypair::from_seed(1);
        let kp_new = Keypair::from_seed(42);
        let current = single_vset(&kp);
        // next_set has a new member not in current
        let next_set = ValidatorSet::new(vec![
            (kp.node_id(), kp.pubkey_bytes(), 1u64),
            (kp_new.node_id(), kp_new.pubkey_bytes(), 1u64),
        ]);
        let proof = valid_proof(&kp);
        let rc = Reconfig {
            next_set,
            evidence: vec![proof],
            operator_sig: None,
            jail: None,
        };
        let op_pk = Keypair::from_seed(OP_SEED).pubkey_bytes();
        assert!(!verify_reconfig_authorized(
            &current,
            &rc,
            0,
            &azbft_types::OperatorSet::single(op_pk.clone())
        ));
    }

    #[test]
    fn reconfig_authorized_empty_evidence_no_sig_fails() {
        // empty evidence + no sig → rejected (closes unauthorized-reconfig gap)
        let kp = Keypair::from_seed(1);
        let current = single_vset(&kp);
        let next_set = current.without(&kp.node_id());
        let rc = Reconfig {
            next_set,
            evidence: vec![],
            operator_sig: None,
            jail: None,
        };
        let op_pk = Keypair::from_seed(OP_SEED).pubkey_bytes();
        assert!(!verify_reconfig_authorized(
            &current,
            &rc,
            0,
            &azbft_types::OperatorSet::single(op_pk.clone())
        ));
    }

    // ---- Stake slashing: stake-slash tests ----

    /// Helper: build a vset with given stake values for each keypair.
    fn vset_with_stakes(pairs: &[(&Keypair, u64)]) -> ValidatorSet {
        ValidatorSet::new(
            pairs
                .iter()
                .map(|(kp, s)| (kp.node_id(), kp.pubkey_bytes(), *s))
                .collect(),
        )
    }

    #[test]
    fn slash_justified_stake_reduced_passes() {
        // Valid evidence for a voter whose stake is strictly lower in next_set → true.
        let kp = Keypair::from_seed(1);
        let current = vset_with_stakes(&[(&kp, 100)]);
        let next_set = vset_with_stakes(&[(&kp, 50)]); // stake halved
        let proof = valid_proof(&kp);
        let rc = Reconfig {
            next_set,
            evidence: vec![proof],
            operator_sig: None,
            jail: None,
        };
        assert!(verify_removal_justified(&current, &rc));
    }

    #[test]
    fn slash_justified_stake_same_fails() {
        // Offender stays in next_set with SAME stake (no slash) → false ("fake slash").
        let kp = Keypair::from_seed(1);
        let current = vset_with_stakes(&[(&kp, 100)]);
        let next_set = vset_with_stakes(&[(&kp, 100)]); // unchanged
        let proof = valid_proof(&kp);
        let rc = Reconfig {
            next_set,
            evidence: vec![proof],
            operator_sig: None,
            jail: None,
        };
        assert!(!verify_removal_justified(&current, &rc));
    }

    #[test]
    fn slash_justified_stake_increased_fails() {
        // Offender stays but stake INCREASED → should be rejected (not a punishment).
        let kp = Keypair::from_seed(1);
        let current = vset_with_stakes(&[(&kp, 100)]);
        let next_set = vset_with_stakes(&[(&kp, 150)]); // increased — not a slash
        let proof = valid_proof(&kp);
        let rc = Reconfig {
            next_set,
            evidence: vec![proof],
            operator_sig: None,
            jail: None,
        };
        assert!(!verify_removal_justified(&current, &rc));
    }

    #[test]
    fn slash_justified_invalid_sig_fails() {
        // Stake is reduced but the equivocation proof sig is tampered → false.
        let kp = Keypair::from_seed(1);
        let current = vset_with_stakes(&[(&kp, 100)]);
        let next_set = vset_with_stakes(&[(&kp, 50)]);
        let mut proof = valid_proof(&kp);
        if let Some(byte) = proof.vote_a.sig.first_mut() {
            *byte ^= 0xff;
        }
        let rc = Reconfig {
            next_set,
            evidence: vec![proof],
            operator_sig: None,
            jail: None,
        };
        assert!(!verify_removal_justified(&current, &rc));
    }

    #[test]
    fn slash_justified_honest_validator_no_evidence_fails() {
        // Slashing an honest validator (no evidence for them) → false.
        // Two-member set: kp1 (honest, no equivocation), kp2 (offender).
        let kp1 = Keypair::from_seed(1);
        let kp2 = Keypair::from_seed(2);
        let current = vset_with_stakes(&[(&kp1, 100), (&kp2, 100)]);
        // next_set slashes kp1 (the honest one) — kp2 proof is irrelevant to kp1.
        let next_set = vset_with_stakes(&[(&kp1, 50), (&kp2, 100)]);
        // Evidence is for kp2, not kp1 — so slashing kp1 is unjustified.
        let proof_kp2 = valid_proof(&kp2);
        let rc = Reconfig {
            next_set,
            evidence: vec![proof_kp2],
            operator_sig: None,
            jail: None,
        };
        assert!(!verify_removal_justified(&current, &rc));
    }

    #[test]
    fn slash_justified_voter_not_in_current_fails() {
        // Evidence for a validator not in current set → false.
        let kp_in = Keypair::from_seed(1);
        let kp_out = Keypair::from_seed(99);
        let current = vset_with_stakes(&[(&kp_in, 100)]);
        // next_set keeps kp_in at reduced stake (kp_out not in either set).
        let next_set = vset_with_stakes(&[(&kp_in, 50)]);
        let proof_outsider = valid_proof(&kp_out);
        let rc = Reconfig {
            next_set,
            evidence: vec![proof_outsider],
            operator_sig: None,
            jail: None,
        };
        assert!(!verify_removal_justified(&current, &rc));
    }

    #[test]
    fn slash_authorized_operator_signed_passes() {
        // Operator-signed slash: Path 1 (operator sig) covers any vset change.
        let kp = Keypair::from_seed(1);
        let current = vset_with_stakes(&[(&kp, 100)]);
        let next_set = vset_with_stakes(&[(&kp, 50)]); // slash
        let epoch = 0u64;
        let op = Keypair::from_seed(OP_SEED);
        let sig = op.sign(Domain::Reconfig, &reconfig_signing_bytes(&next_set, epoch));
        let rc = Reconfig {
            next_set,
            evidence: vec![],
            operator_sig: Some(sig),
            jail: None,
        };
        let op_pk = op.pubkey_bytes();
        assert!(verify_reconfig_authorized(
            &current,
            &rc,
            epoch,
            &azbft_types::OperatorSet::single(op_pk.clone())
        ));
    }

    #[test]
    fn slash_authorized_pure_evidence_path_passes() {
        // Pure-evidence slash (Path 2): no operator sig, but valid proof + stake reduced.
        let kp = Keypair::from_seed(1);
        let current = vset_with_stakes(&[(&kp, 100)]);
        let next_set = vset_with_stakes(&[(&kp, 50)]);
        let proof = valid_proof(&kp);
        let rc = Reconfig {
            next_set,
            evidence: vec![proof],
            operator_sig: None,
            jail: None,
        };
        let op_pk = Keypair::from_seed(OP_SEED).pubkey_bytes();
        assert!(verify_reconfig_authorized(
            &current,
            &rc,
            0,
            &azbft_types::OperatorSet::single(op_pk.clone())
        ));
    }

    #[test]
    fn slash_authorized_no_evidence_no_sig_fails() {
        // Slash with no evidence and no operator sig → rejected.
        let kp = Keypair::from_seed(1);
        let current = vset_with_stakes(&[(&kp, 100)]);
        let next_set = vset_with_stakes(&[(&kp, 50)]);
        let rc = Reconfig {
            next_set,
            evidence: vec![],
            operator_sig: None,
            jail: None,
        };
        let op_pk = Keypair::from_seed(OP_SEED).pubkey_bytes();
        assert!(!verify_reconfig_authorized(
            &current,
            &rc,
            0,
            &azbft_types::OperatorSet::single(op_pk.clone())
        ));
    }

    #[test]
    fn slash_and_removal_coexist_in_same_reconfig() {
        // Two offenders: one removed, one slash. Both covered by evidence → true.
        let kp1 = Keypair::from_seed(1);
        let kp2 = Keypair::from_seed(2);
        let current = vset_with_stakes(&[(&kp1, 100), (&kp2, 100)]);
        // kp1 removed, kp2 slashed.
        let next_set = vset_with_stakes(&[(&kp2, 50)]);
        let proof1 = valid_proof(&kp1);
        let proof2 = valid_proof(&kp2);
        let rc = Reconfig {
            next_set,
            evidence: vec![proof1, proof2],
            operator_sig: None,
            jail: None,
        };
        let op_pk = Keypair::from_seed(OP_SEED).pubkey_bytes();
        assert!(verify_reconfig_authorized(
            &current,
            &rc,
            0,
            &azbft_types::OperatorSet::single(op_pk.clone())
        ));
    }

    // ---- M-of-N operator multisig tests (verify_operator_multisig) ----

    /// Three distinct operator keypairs. Seeds are chosen to not collide with the
    /// validator keypairs used above (which use small seeds like 1, 2, 10, 42, 99).
    fn op_keypairs_3() -> (Keypair, Keypair, Keypair) {
        (
            Keypair::from_seed(700),
            Keypair::from_seed(701),
            Keypair::from_seed(702),
        )
    }

    /// Common fixture for the M-of-N tests: a real vset change plus the canonical
    /// operator-signing bytes over it. Returns `(current, next_set, epoch, msg)`.
    fn multisig_ctx() -> (ValidatorSet, ValidatorSet, u64, Vec<u8>) {
        let kp = Keypair::from_seed(1);
        let current = single_vset(&kp);
        let next_set = current.without(&kp.node_id());
        let epoch = 5u64;
        let msg = reconfig_signing_bytes(&next_set, epoch);
        (current, next_set, epoch, msg)
    }

    #[test]
    fn operator_multisig_2of3_accepts_two_distinct() {
        // 2-of-3: two distinct valid signatures (indices 0 and 1) meet threshold 2.
        let (current, next_set, epoch, msg) = multisig_ctx();
        let (op0, op1, op2) = op_keypairs_3();
        let op_set = OperatorSet::new(
            vec![op0.pubkey_bytes(), op1.pubkey_bytes(), op2.pubkey_bytes()],
            2,
        )
        .expect("valid 2-of-3 set");
        let sig0 = op0.sign(Domain::Reconfig, &msg);
        let sig1 = op1.sign(Domain::Reconfig, &msg);
        let operator_sig = operator_multisig_encode(&[(0u16, sig0), (1u16, sig1)]);
        let rc = Reconfig {
            next_set,
            evidence: vec![],
            operator_sig: Some(operator_sig),
            jail: None,
        };
        assert!(verify_reconfig_authorized(&current, &rc, epoch, &op_set));
    }

    #[test]
    fn operator_multisig_1of3_insufficient_rejected() {
        // Only one valid signature against a threshold-2 set → rejected.
        let (current, next_set, epoch, msg) = multisig_ctx();
        let (op0, op1, op2) = op_keypairs_3();
        let op_set = OperatorSet::new(
            vec![op0.pubkey_bytes(), op1.pubkey_bytes(), op2.pubkey_bytes()],
            2,
        )
        .expect("valid 2-of-3 set");
        let sig0 = op0.sign(Domain::Reconfig, &msg);
        let operator_sig = operator_multisig_encode(&[(0u16, sig0)]);
        let rc = Reconfig {
            next_set,
            evidence: vec![],
            operator_sig: Some(operator_sig),
            jail: None,
        };
        assert!(!verify_reconfig_authorized(&current, &rc, epoch, &op_set));
    }

    #[test]
    fn operator_multisig_duplicate_index_counts_once() {
        // Same valid index twice → distinct count is 1 < threshold 2 → rejected.
        let (_current, _next_set, _epoch, msg) = multisig_ctx();
        let (op0, op1, op2) = op_keypairs_3();
        let op_set = OperatorSet::new(
            vec![op0.pubkey_bytes(), op1.pubkey_bytes(), op2.pubkey_bytes()],
            2,
        )
        .expect("valid 2-of-3 set");
        let sig0 = op0.sign(Domain::Reconfig, &msg);
        let sig_bytes = operator_multisig_encode(&[(0u16, sig0.clone()), (0u16, sig0)]);
        assert!(!verify_operator_multisig(&op_set, &msg, &sig_bytes));
    }

    #[test]
    fn operator_multisig_wrong_key_rejected() {
        // Index 1 carries a signature from a NON-operator key → that pair fails
        // verify against op1's pubkey → only 1 distinct valid < threshold 2.
        let (_current, _next_set, _epoch, msg) = multisig_ctx();
        let (op0, op1, op2) = op_keypairs_3();
        let op_set = OperatorSet::new(
            vec![op0.pubkey_bytes(), op1.pubkey_bytes(), op2.pubkey_bytes()],
            2,
        )
        .expect("valid 2-of-3 set");
        let non_operator = Keypair::from_seed(888); // not in the set
        let sig0 = op0.sign(Domain::Reconfig, &msg);
        let bad_sig = non_operator.sign(Domain::Reconfig, &msg); // placed at index 1
        let sig_bytes = operator_multisig_encode(&[(0u16, sig0), (1u16, bad_sig)]);
        assert!(!verify_operator_multisig(&op_set, &msg, &sig_bytes));
    }

    #[test]
    fn operator_multisig_out_of_range_index_skipped() {
        // Index 99 is out of range and skipped → only 1 distinct valid < threshold 2.
        let (_current, _next_set, _epoch, msg) = multisig_ctx();
        let (op0, op1, op2) = op_keypairs_3();
        let op_set = OperatorSet::new(
            vec![op0.pubkey_bytes(), op1.pubkey_bytes(), op2.pubkey_bytes()],
            2,
        )
        .expect("valid 2-of-3 set");
        let sig0 = op0.sign(Domain::Reconfig, &msg);
        let sig_anything = op0.sign(Domain::Reconfig, &msg);
        let sig_bytes = operator_multisig_encode(&[(0u16, sig0), (99u16, sig_anything)]);
        assert!(!verify_operator_multisig(&op_set, &msg, &sig_bytes));
    }

    #[test]
    fn operator_multisig_bloated_list_rejected() {
        // A pairs list longer than keys.len() is rejected outright, even if the
        // pairs would otherwise satisfy the threshold (fail-closed on N cap).
        let (_current, _next_set, _epoch, msg) = multisig_ctx();
        let (op0, op1, _op2) = op_keypairs_3();
        let op_set = OperatorSet::new(vec![op0.pubkey_bytes(), op1.pubkey_bytes()], 1)
            .expect("valid 1-of-2 set");
        let sig0 = op0.sign(Domain::Reconfig, &msg);
        // Length 3 > keys.len() == 2 → rejected before counting.
        let sig_bytes =
            operator_multisig_encode(&[(0u16, sig0.clone()), (0u16, sig0.clone()), (0u16, sig0)]);
        assert!(!verify_operator_multisig(&op_set, &msg, &sig_bytes));
    }

    #[test]
    fn operator_multisig_malformed_bytes_rejected() {
        // operator_sig that is not valid borsh for the pairs list → decode None → false.
        let (current, next_set, epoch, _msg) = multisig_ctx();
        let (op0, op1, _op2) = op_keypairs_3();
        let op_set = OperatorSet::new(vec![op0.pubkey_bytes(), op1.pubkey_bytes()], 2)
            .expect("valid 2-of-2 set");
        let rc = Reconfig {
            next_set,
            evidence: vec![],
            operator_sig: Some(vec![0xFF, 0x00, 0x13, 0x37]),
            jail: None,
        };
        assert!(!verify_reconfig_authorized(&current, &rc, epoch, &op_set));
    }

    #[test]
    fn operator_multisig_single_key_accepts_raw_signature() {
        // A one-key authority accepts the raw secp256k1 signature encoding.
        let (current, next_set, epoch, msg) = multisig_ctx();
        let (op0, _op1, _op2) = op_keypairs_3();
        let op_set = OperatorSet::single(op0.pubkey_bytes());
        let raw_sig0 = op0.sign(Domain::Reconfig, &msg);
        let rc_raw = Reconfig {
            next_set: next_set.clone(),
            evidence: vec![],
            operator_sig: Some(raw_sig0.clone()),
            jail: None,
        };
        assert!(verify_reconfig_authorized(
            &current, &rc_raw, epoch, &op_set
        ));

        // The SAME legacy set given a LIST-encoded operator_sig must be REJECTED:
        // the legacy path only accepts a raw single sig, not the pair encoding.
        let list_encoded = operator_multisig_encode(&[(0u16, raw_sig0)]);
        let rc_list = Reconfig {
            next_set,
            evidence: vec![],
            operator_sig: Some(list_encoded),
            jail: None,
        };
        assert!(!verify_reconfig_authorized(
            &current, &rc_list, epoch, &op_set
        ));
    }
}
