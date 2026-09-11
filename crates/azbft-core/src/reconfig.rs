//! Verification of commit, epoch-change, and checkpoint certificates.
//!
//! These functions bind certificate structure, quorum signatures, epochs, and
//! validator-set transitions without adding a trust root beyond the configured
//! genesis validator set.

use azbft_crypto::aggregator::verify_agg;
use azbft_crypto::domain::Domain;
use azbft_types::{
    Block, ChainAnchorV2, Checkpoint, CommitCert, EpochChangeCert, LockedEpoch, QuorumCert,
    ShortAnchor, ValidatorSet, SHORT_ANCHOR_MAX_LOCKED,
};

/// Verifies that `block` is committed by a certified child in the next round.
/// Both quorum certificates must verify against `vset`.
pub fn verify_two_chain_commit(
    block: &Block,
    child: &Block,
    commit_qc: &QuorumCert,
    vset: &ValidatorSet,
) -> bool {
    if commit_qc.block_id != child.id() || commit_qc.round != child.round {
        return false;
    }
    // Each certificate selects its aggregate-signature scheme, allowing a
    // checkpoint chain to contain certificates created under either scheme.
    if verify_agg(
        &commit_qc.agg,
        &azbft_types::vote_digest(&child.id(), commit_qc.round),
        Domain::Vote,
        vset,
    )
    .is_err()
    {
        return false;
    }
    if child.parent_qc.block_id != block.id() || child.parent_qc.round != block.round {
        return false;
    }
    if verify_agg(
        &child.parent_qc.agg,
        &azbft_types::vote_digest(&block.id(), child.parent_qc.round),
        Domain::Vote,
        vset,
    )
    .is_err()
    {
        return false;
    }
    child.round.0 == block.round.0 + 1
}

/// Verifies a generic two-chain commit certificate against `vset`.
pub fn verify_commit_cert(cc: &CommitCert, vset: &ValidatorSet) -> bool {
    verify_two_chain_commit(&cc.block, &cc.child, &cc.commit_qc, vset)
}

/// Verifies a checkpoint from the genesis validator set.
///
/// The epoch-change chain contains exactly one certificate per preceding
/// epoch, in order and without gaps. Validation and adoption use the same
/// sequence, whose terminal certificate identifies the checkpoint commit proof.
pub fn verify_checkpoint(
    cp: &Checkpoint,
    genesis_vset: &ValidatorSet,
    ecc_chain: &[EpochChangeCert],
) -> bool {
    // Epoch `e` requires certificates for epochs `0..e`.
    if ecc_chain.len() as u64 != cp.epoch {
        return false;
    }
    let certified_anchor = ChainAnchorV2::from_block(&cp.commit_cert.block);
    if cp.chain_anchor != certified_anchor || cp.height != certified_anchor.height {
        return false;
    }

    let mut cur_vset = genesis_vset.clone();
    let mut signer_vset = genesis_vset.clone();
    // Advance through the exact certificate sequence supplied for adoption.
    for (k, ecc) in ecc_chain.iter().enumerate() {
        if !verify_epoch_change_cert(ecc, &cur_vset, k as u64) {
            return false;
        }
        // Every adopted BLS key must carry a proof of possession. Secp-only
        // validator sets require no BLS proof.
        if !azbft_crypto::aggregator::verify_vset_pops(ecc.next_set()) {
            return false;
        }
        signer_vset = cur_vset.clone();
        cur_vset = ecc.next_set().clone();
    }
    if cur_vset != cp.validator_set {
        return false;
    }
    // The checkpoint anchor must be the terminal epoch-change certificate.
    if cp.epoch > 0 {
        let last = &ecc_chain[ecc_chain.len() - 1];
        if cp.commit_cert.block != last.reconfig_block
            || cp.commit_cert.child != last.child_block
            || cp.commit_cert.commit_qc != last.commit_qc
        {
            return false;
        }
    }
    if !verify_commit_cert(&cp.commit_cert, &signer_vset) {
        return false;
    }
    if cp.epoch > 0 {
        if cp.commit_cert.block.epoch != cp.epoch - 1 {
            return false;
        }
        if cp.commit_cert.block.reconfig.is_none() {
            return false;
        }
    }
    true
}

/// Verifies an ops-trusted short anchor against the supplied locked-epoch sets.
///
/// Unlike [`verify_checkpoint`], this does **not** walk a genesis-anchored ECC
/// spine. Membership for each locked epoch is an out-of-band trust input: the
/// caller must additionally confirm that `vsets` match the local ops file
/// ([`short_anchor_matches_ops`]) before adopting.
///
/// Rules:
/// 1. `1 <= locked.len() <= SHORT_ANCHOR_MAX_LOCKED`, epochs consecutive,
///    start heights strictly increasing.
/// 2. `vsets.len() == locked.len()`, and every set passes BLS PoP checks.
/// 3. `anchor.epoch == locked[0].epoch`.
/// 4. `verify_commit_cert(&anchor.tip_commit, &vsets[0])`.
/// 5. `anchor.height` equals the tip block's certified height, and the tip
///    block's epoch equals `anchor.epoch`.
pub fn verify_short_anchor(anchor: &ShortAnchor, vsets: &[ValidatorSet]) -> bool {
    let locked = &anchor.locked;
    if locked.is_empty() || locked.len() > SHORT_ANCHOR_MAX_LOCKED {
        return false;
    }
    if vsets.len() != locked.len() {
        return false;
    }
    for window in locked.windows(2) {
        if window[1].epoch != window[0].epoch + 1 {
            return false;
        }
        if window[1].start_height <= window[0].start_height {
            return false;
        }
    }
    if anchor.epoch != locked[0].epoch {
        return false;
    }
    for vset in vsets {
        if !azbft_crypto::aggregator::verify_vset_pops(vset) {
            return false;
        }
    }
    if !verify_commit_cert(&anchor.tip_commit, &vsets[0]) {
        return false;
    }
    let certified = ChainAnchorV2::from_block(&anchor.tip_commit.block);
    if anchor.height != certified.height {
        return false;
    }
    if anchor.tip_commit.block.epoch != anchor.epoch {
        return false;
    }
    true
}

/// Confirms that every locked epoch's validator set matches the ops-trusted
/// source. `ops_lookup(epoch)` returns the expected set for that epoch, or
/// `None` when the ops file is missing the epoch (fail-closed).
pub fn short_anchor_matches_ops(
    locked: &[LockedEpoch],
    vsets: &[ValidatorSet],
    mut ops_lookup: impl FnMut(u64) -> Option<ValidatorSet>,
) -> bool {
    if locked.len() != vsets.len() {
        return false;
    }
    for (le, vset) in locked.iter().zip(vsets.iter()) {
        match ops_lookup(le.epoch) {
            Some(expected) if expected == *vset => {}
            _ => return false,
        }
    }
    true
}

/// Verifies a two-chain epoch-change certificate for `expected_epoch`.
pub fn verify_epoch_change_cert(
    ecc: &EpochChangeCert,
    vset: &ValidatorSet,
    expected_epoch: u64,
) -> bool {
    verify_two_chain_commit(&ecc.reconfig_block, &ecc.child_block, &ecc.commit_qc, vset)
        && ecc.reconfig_block.reconfig.is_some()
        && ecc.reconfig_block.epoch == ecc.child_block.epoch
        && ecc.reconfig_block.epoch == expected_epoch
}

#[cfg(test)]
mod tests {
    use super::*;
    use azbft_crypto::aggregator::{SecpMultiSig, VoteAggregator};
    use azbft_crypto::keypair::Keypair;
    use azbft_types::*;

    /// 4 validator(seeds 1..=4),quorum=3.
    fn validators() -> (Vec<Keypair>, ValidatorSet) {
        let kps: Vec<Keypair> = (1..=4u64).map(Keypair::from_seed).collect();
        let members = kps
            .iter()
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect();
        (kps, ValidatorSet::new(members))
    }

    fn qc_over(block_id: Hash, round: Round, kps: &[Keypair]) -> QuorumCert {
        let sigs: Vec<(NodeId, Vec<u8>)> = kps
            .iter()
            .take(3)
            .map(|k| {
                (
                    k.node_id(),
                    k.sign(Domain::Vote, &azbft_types::vote_digest(&block_id, round).0),
                )
            })
            .collect();
        QuorumCert {
            block_id,
            round,
            agg: SecpMultiSig::aggregate(&sigs),
        }
    }

    fn valid_ecc(epoch: u64, r0: u64) -> (EpochChangeCert, ValidatorSet) {
        let (kps, vset) = validators();
        let next = ValidatorSet::new(
            kps.iter()
                .take(3)
                .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
                .collect(),
        );
        let recfg = Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 1,
            timestamp_ms: 1,
            epoch,
            round: Round(r0),
            parent_qc: QuorumCert::genesis(),
            payload_hash: blake3_id(&b"recfg".to_vec()),
            author: vset.leader(Round(r0)),
            reconfig: Some(Reconfig {
                next_set: next,
                evidence: vec![],
                operator_sig: None,
                jail: None,
            }),
        };
        let qc_recfg = qc_over(recfg.id(), Round(r0), &kps);
        let child = Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 1,
            timestamp_ms: 1,
            epoch,
            round: Round(r0 + 1),
            parent_qc: qc_recfg,
            payload_hash: blake3_id(&b"child".to_vec()),
            author: vset.leader(Round(r0 + 1)),
            reconfig: None,
        };
        let qc_child = qc_over(child.id(), Round(r0 + 1), &kps);
        (
            EpochChangeCert {
                reconfig_block: recfg,
                child_block: child,
                commit_qc: qc_child,
            },
            vset,
        )
    }

    #[test]
    fn valid_commit_cert_verifies() {
        let (kps, vset) = validators();
        let b1 = Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 1,
            timestamp_ms: 1,
            epoch: 0,
            round: Round(5),
            parent_qc: QuorumCert::genesis(),
            payload_hash: blake3_id(&b"b1".to_vec()),
            author: vset.leader(Round(5)),
            reconfig: None,
        };
        let b2 = Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 1,
            timestamp_ms: 1,
            epoch: 0,
            round: Round(6),
            parent_qc: qc_over(b1.id(), Round(5), &kps),
            payload_hash: blake3_id(&b"b2".to_vec()),
            author: vset.leader(Round(6)),
            reconfig: None,
        };
        let cc = CommitCert {
            block: b1,
            child: b2.clone(),
            commit_qc: qc_over(b2.id(), Round(6), &kps),
        };
        assert!(verify_commit_cert(&cc, &vset));
        let mut bad = cc.clone();
        bad.commit_qc.agg = AggSig::default(); // empty agg → below quorum
        assert!(!verify_commit_cert(&bad, &vset));
    }

    #[test]
    fn valid_cert_verifies() {
        let (ecc, vset) = valid_ecc(0, 5);
        assert!(verify_epoch_change_cert(&ecc, &vset, 0));
        assert_eq!(ecc.epoch(), 0);
        assert_eq!(ecc.next_set().len(), 3);
    }

    #[test]
    fn reconfig_none_fails() {
        let (mut ecc, vset) = valid_ecc(0, 5);
        ecc.reconfig_block.reconfig = None;
        assert!(!verify_epoch_change_cert(&ecc, &vset, 0));
    }

    #[test]
    fn tampered_commit_qc_fails() {
        let (mut ecc, vset) = valid_ecc(0, 5);
        ecc.commit_qc.agg = AggSig::default();
        assert!(!verify_epoch_change_cert(&ecc, &vset, 0));
    }

    #[test]
    fn nonconsecutive_rounds_fail() {
        let (kps, _v) = validators();
        let (mut ecc, vset) = valid_ecc(0, 5);
        ecc.child_block.round = Round(8);
        ecc.commit_qc = qc_over(ecc.child_block.id(), Round(8), &kps);
        assert!(!verify_epoch_change_cert(&ecc, &vset, 0));
    }

    #[test]
    fn wrong_vset_fails() {
        let (ecc, _vset) = valid_ecc(0, 5);
        let other = ValidatorSet::new(
            (10..=13u64)
                .map(Keypair::from_seed)
                .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
                .collect(),
        );
        assert!(!verify_epoch_change_cert(&ecc, &other, 0));
    }

    #[test]
    fn wrong_expected_epoch_fails() {
        let (ecc, vset) = valid_ecc(0, 5);
        assert!(!verify_epoch_change_cert(&ecc, &vset, 1));
        assert!(verify_epoch_change_cert(&ecc, &vset, 0));
    }

    // ===== Checkpoint validation: verify_checkpoint adversarial tests =====

    use azbft_types::Checkpoint;

    /// A validator set built from keypair seeds (stake 1 each).
    fn vset_from_seeds(seeds: &[u64]) -> (Vec<Keypair>, ValidatorSet) {
        let kps: Vec<Keypair> = seeds.iter().copied().map(Keypair::from_seed).collect();
        let members = kps
            .iter()
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect();
        (kps, ValidatorSet::new(members))
    }

    /// Build a real, cryptographically-valid ECC for `epoch` whose 2-chain is
    /// QC'd by `signer_kps` (the ACTIVE set at `epoch`) and whose reconfig hands
    /// off to `next` (the active set for `epoch+1`). Rounds are arbitrary but
    /// consecutive (R0=5, child=6).
    fn ecc_handoff(epoch: u64, signer_kps: &[Keypair], next: ValidatorSet) -> EpochChangeCert {
        let r0 = 5u64;
        let recfg = Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 1,
            timestamp_ms: 1,
            epoch,
            round: Round(r0),
            parent_qc: QuorumCert::genesis(),
            payload_hash: blake3_id(&format!("recfg-{epoch}")),
            author: NodeId::default(),
            reconfig: Some(Reconfig {
                next_set: next,
                evidence: vec![],
                operator_sig: None,
                jail: None,
            }),
        };
        let qc_recfg = qc_over(recfg.id(), Round(r0), signer_kps);
        let child = Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 1,
            timestamp_ms: 1,
            epoch,
            round: Round(r0 + 1),
            parent_qc: qc_recfg,
            payload_hash: blake3_id(&format!("child-{epoch}")),
            author: NodeId::default(),
            reconfig: None,
        };
        let qc_child = qc_over(child.id(), Round(r0 + 1), signer_kps);
        EpochChangeCert {
            reconfig_block: recfg,
            child_block: child,
            commit_qc: qc_child,
        }
    }

    /// Build a genesis-anchored chain of `n` epoch boundaries (epoch 0..n) plus a
    /// checkpoint taken at the epoch (n-1)->n boundary. Each epoch e's active set
    /// is seeds `[10+e .. 10+e+4)` (4 validators, quorum 3), so consecutive epochs
    /// have genuinely different sets and the handoff is non-trivial.
    ///
    /// Returns `(genesis_vset, ecc_chain, checkpoint)`. The checkpoint's
    /// commit_cert IS the last ECC's three-tuple (anchor = the reconfig block that
    /// ends epoch n-1), epoch = n, validator_set = the active set for epoch n.
    fn build_chain(n: u64) -> (ValidatorSet, Vec<EpochChangeCert>, Checkpoint) {
        assert!(n >= 1, "epoch-boundary checkpoint needs n>=1");
        // Active set for each epoch e in 0..=n.
        let active: Vec<(Vec<Keypair>, ValidatorSet)> = (0..=n)
            .map(|e| vset_from_seeds(&[10 + e, 11 + e, 12 + e, 13 + e]))
            .collect();
        let genesis_vset = active[0].1.clone();
        let mut chain = Vec::new();
        for e in 0..n {
            // ECC ending epoch e is signed by epoch e's active set; hands off to
            // epoch e+1's active set.
            let signer_kps = &active[e as usize].0;
            let next = active[(e + 1) as usize].1.clone();
            chain.push(ecc_handoff(e, signer_kps, next));
        }
        let last = chain.last().unwrap();
        let cp = Checkpoint {
            height: last.reconfig_block.height,
            epoch: n,
            validator_set: active[n as usize].1.clone(),
            chain_anchor: ChainAnchorV2::from_block(&last.reconfig_block),
            commit_cert: CommitCert {
                block: last.reconfig_block.clone(),
                child: last.child_block.clone(),
                commit_qc: last.commit_qc.clone(),
            },
        };
        (genesis_vset, chain, cp)
    }

    #[test]
    fn valid_checkpoint_adopts() {
        let (genesis_vset, chain, cp) = build_chain(3);
        assert!(verify_checkpoint(&cp, &genesis_vset, &chain));
        assert_eq!(cp.epoch, 3);
        assert_eq!(&cp.validator_set, chain.last().unwrap().next_set());
    }

    #[test]
    fn checkpoint_rejects_a_tampered_chain_anchor() {
        let (genesis_vset, chain, mut cp) = build_chain(3);
        cp.chain_anchor.timestamp_ms += 1;
        assert!(!verify_checkpoint(&cp, &genesis_vset, &chain));
    }

    #[test]
    fn checkpoint_rejects_a_height_outside_the_signed_anchor() {
        let (genesis_vset, chain, mut cp) = build_chain(3);
        cp.height += 1;
        assert!(!verify_checkpoint(&cp, &genesis_vset, &chain));
    }

    #[test]
    fn tampered_vset_rejected() {
        let (genesis_vset, chain, mut cp) = build_chain(3);
        // Swap the claimed active set to a different one ⇒ step 2 fails.
        cp.validator_set = vset_from_seeds(&[200, 201, 202, 203]).1;
        assert!(!verify_checkpoint(&cp, &genesis_vset, &chain));
    }

    #[test]
    fn tampered_commit_cert_rejected() {
        let (genesis_vset, chain, mut cp) = build_chain(3);
        // Strip the commit_qc signatures ⇒ step 3 (verify_commit_cert) fails.
        cp.commit_cert.commit_qc.agg = AggSig::default();
        assert!(!verify_checkpoint(&cp, &genesis_vset, &chain));
    }

    #[test]
    fn wrong_epoch_length_mismatch_rejected() {
        let (genesis_vset, chain, cp) = build_chain(3);
        // cp.epoch=3 but pass only a 2-ECC chain ⇒ step 0 length check fails.
        assert!(!verify_checkpoint(&cp, &genesis_vset, &chain[..2]));
        // cp.epoch declared smaller than the (correct) chain length ⇒ step 0 fails.
        let mut cp2 = cp.clone();
        cp2.epoch = 2;
        assert!(!verify_checkpoint(&cp2, &genesis_vset, &chain));
    }

    #[test]
    fn anchor_epoch_self_inconsistent_rejected() {
        // Chain length matches cp.epoch, but the anchor block's epoch is wrong.
        let (genesis_vset, chain, mut cp) = build_chain(3);
        // Anchor (commit_cert.block) is epoch 2 (= cp.epoch-1). Mutate it to epoch
        // 1 — this breaks step 4's `block.epoch == cp.epoch-1` check. (We mutate a
        // standalone field copy so the ECC chain itself is untouched and step 1
        // still passes; step 3 verify_commit_cert would also fail on the mutated
        // block, but step 4 is the documented guard for anchor self-consistency.)
        cp.commit_cert.block.epoch = 1;
        assert!(!verify_checkpoint(&cp, &genesis_vset, &chain));
    }

    #[test]
    fn broken_ecc_chain_gap_rejected() {
        let (genesis_vset, mut chain, cp) = build_chain(3);
        // Drop the middle ECC (epoch 1) and duplicate epoch 0 to keep length=3:
        // chain becomes [e0, e0, e2] — length matches cp.epoch but epoch labels
        // are 0,0,2 not 0,1,2 ⇒ step 1's expected_epoch=k binding rejects at k=1.
        chain[1] = chain[0].clone();
        assert!(!verify_checkpoint(&cp, &genesis_vset, &chain));
    }

    #[test]
    fn out_of_order_ecc_chain_rejected() {
        let (genesis_vset, mut chain, cp) = build_chain(3);
        // Swap epoch-0 and epoch-1 ECCs ⇒ first ECC has epoch 1 != expected 0,
        // AND it isn't signed by genesis_vset ⇒ step 1 fails immediately.
        chain.swap(0, 1);
        assert!(!verify_checkpoint(&cp, &genesis_vset, &chain));
    }

    #[test]
    fn forged_chain_from_genesis_rejected() {
        // An attacker fabricates a full chain signed by THEIR OWN keys (seeds
        // 900..), anchored on an attacker-controlled genesis. It is internally
        // self-consistent, but presented to a node whose REAL genesis set is
        // seeds 10.. it must be rejected: step 1's first verify_epoch_change_cert
        // checks the attacker's commit_qc against the real genesis set and fails
        // (no historical majority private keys ⇒ no chain forks from the real root).
        let attacker_genesis = vset_from_seeds(&[900, 901, 902, 903]).1;
        let real_genesis = vset_from_seeds(&[10, 11, 12, 13]).1;
        let active: Vec<(Vec<Keypair>, ValidatorSet)> = (0..=2u64)
            .map(|e| vset_from_seeds(&[900 + e, 901 + e, 902 + e, 903 + e]))
            .collect();
        let mut forged_chain = Vec::new();
        for e in 0..2u64 {
            forged_chain.push(ecc_handoff(
                e,
                &active[e as usize].0,
                active[(e + 1) as usize].1.clone(),
            ));
        }
        let last = forged_chain.last().unwrap().clone();
        let forged_cp = Checkpoint {
            height: last.reconfig_block.height,
            epoch: 2,
            validator_set: active[2].1.clone(),
            chain_anchor: ChainAnchorV2::from_block(&last.reconfig_block),
            commit_cert: CommitCert {
                block: last.reconfig_block.clone(),
                child: last.child_block.clone(),
                commit_qc: last.commit_qc.clone(),
            },
        };
        // Internally self-consistent against the attacker's own genesis…
        assert!(verify_checkpoint(
            &forged_cp,
            &attacker_genesis,
            &forged_chain
        ));
        // …but rejected against the real genesis root.
        assert!(!verify_checkpoint(&forged_cp, &real_genesis, &forged_chain));
    }

    #[test]
    fn anchor_not_reconfig_rejected() {
        // cp.epoch>0 requires the anchor to be the last ECC's reconfig block.
        // Point the checkpoint's commit_cert at a NON-reconfig 2-chain (a plain
        // committed block) signed by the correct epoch-1 active set. The anchor
        // is then NOT equal to the last ECC's reconfig block → step-3 identity
        // check rejects (and the reconfig.is_some() guard would too). The
        // commit_cert is itself cryptographically valid for epoch-1's set, so the
        // ONLY reason for rejection is the anchor/reconfig binding — not a bad sig.
        let (genesis_vset, _chain, mut cp) = build_chain(2);
        // Epoch 1 (= cp.epoch-1) active set = seeds [11,12,13,14] (build_chain's
        // active[1]). It signs a plain 2-chain.
        let (kps, signer) = vset_from_seeds(&[11, 12, 13, 14]);
        let b1 = Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 1,
            timestamp_ms: 1,
            epoch: 1,
            round: Round(9),
            parent_qc: QuorumCert::genesis(),
            payload_hash: blake3_id(&b"plain1".to_vec()),
            author: NodeId::default(),
            reconfig: None, // NOT a reconfig block
        };
        let b2 = Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 2,
            timestamp_ms: 2,
            epoch: 1,
            round: Round(10),
            parent_qc: qc_over(b1.id(), Round(9), &kps),
            payload_hash: blake3_id(&b"plain2".to_vec()),
            author: NodeId::default(),
            reconfig: None,
        };
        cp.height = b1.height;
        cp.chain_anchor = ChainAnchorV2::from_block(&b1);
        cp.commit_cert = CommitCert {
            block: b1,
            child: b2.clone(),
            commit_qc: qc_over(b2.id(), Round(10), &kps),
        };
        // Sanity: the commit_cert IS valid for epoch-1's signer set (rejection is
        // purely the anchor/reconfig binding, not a signature failure).
        assert!(verify_commit_cert(&cp.commit_cert, &signer));
        assert!(!verify_checkpoint(
            &cp,
            &genesis_vset,
            &cp_chain_for(&cp, &genesis_vset)
        ));
    }

    /// Rebuild the (correct) ECC chain for a checkpoint produced by build_chain,
    /// so a test can mutate cp.commit_cert independently while keeping the chain
    /// intact (the chain's last ECC still describes the true anchor).
    fn cp_chain_for(cp: &Checkpoint, _genesis: &ValidatorSet) -> Vec<EpochChangeCert> {
        // build_chain(n) is deterministic; reconstruct its chain for cp.epoch.
        let (_g, chain, _cp) = build_chain(cp.epoch);
        chain
    }

    // ===== BLS proof-of-possession validation during checkpoint adoption =====

    /// Build a 1-epoch genesis-anchored checkpoint (epoch 0 → 1) whose single ECC
    /// hands off to a `next_set` carrying a BLS column on every member.
    /// `pop_valid` selects whether member 0's proof-of-possession matches its own
    /// BLS key (accept) or is borrowed from an unrelated BLS key (rogue-key
    /// forgery → reject on adoption).
    ///
    /// Genesis set (epoch 0, the signer of the ECC) and all QCs stay secp — only
    /// the *adopted* committee for epoch 1 carries BLS keys, isolating the PoP
    /// gate from the forming scheme (the gate is CONTENT-driven). The checkpoint's
    /// `validator_set` is set to the same adopted committee so step 2 (vset match)
    /// passes; rejection, when it happens, is purely the PoP gate.
    fn checkpoint_with_bls_next_set(
        pop_valid: bool,
    ) -> (ValidatorSet, Vec<EpochChangeCert>, Checkpoint) {
        use azbft_crypto::bls::BlsSecretKey;
        // Epoch-0 active set (signer of the ECC), secp-only.
        let (gen_kps, genesis_vset) = vset_from_seeds(&[10, 11, 12, 13]);
        // Epoch-1 committee with BLS columns (4 validators, quorum 3).
        let next_seeds = [20u64, 21, 22, 23];
        let next_members: Vec<Member> = next_seeds
            .iter()
            .enumerate()
            .map(|(i, &seed)| {
                let k = Keypair::from_seed(seed);
                let bsk = BlsSecretKey::from_seed(800 + i as u64);
                let pop = if !pop_valid && i == 0 {
                    BlsSecretKey::from_seed(515_151)
                        .prove_possession()
                        .to_bytes()
                        .to_vec()
                } else {
                    bsk.prove_possession().to_bytes().to_vec()
                };
                Member::new(
                    k.node_id(),
                    k.pubkey_bytes(),
                    bsk.public().to_bytes().to_vec(),
                    pop,
                    1u64,
                )
            })
            .collect();
        let next = ValidatorSet::new_members(next_members);
        // ECC ending epoch 0, signed by the genesis set, handing off to `next`.
        let ecc = ecc_handoff(0, &gen_kps, next.clone());
        let cp = Checkpoint {
            height: ecc.reconfig_block.height,
            epoch: 1,
            validator_set: next.clone(),
            chain_anchor: ChainAnchorV2::from_block(&ecc.reconfig_block),
            commit_cert: CommitCert {
                block: ecc.reconfig_block.clone(),
                child: ecc.child_block.clone(),
                commit_qc: ecc.commit_qc.clone(),
            },
        };
        (genesis_vset, vec![ecc], cp)
    }

    #[test]
    fn checkpoint_adopts_next_set_with_valid_pop() {
        // Accept counterpart: a checkpoint rolling into a BLS-keyed committee with
        // valid PoPs verifies exactly like a secp-only one.
        let (genesis_vset, chain, cp) = checkpoint_with_bls_next_set(true);
        assert!(
            verify_checkpoint(&cp, &genesis_vset, &chain),
            "checkpoint handing off to a BLS committee with valid PoPs must verify"
        );
    }

    #[test]
    fn checkpoint_rejects_next_set_with_invalid_pop() {
        // A peer presents a checkpoint that rolls the chain into a committee
        // carrying a rogue BLS key (member 0's PoP is for a different key). The
        // ECC's 2-chain crypto is valid (secp QCs over the genesis set) and the
        // claimed validator_set matches the adopted set, so the ONLY reason to
        // reject is the failed proof-of-possession — closing the rogue-key hole on
        // checkpoint adoption. CONTENT-driven, independent of forming scheme.
        let (genesis_vset, chain, cp) = checkpoint_with_bls_next_set(false);
        assert!(
            !verify_checkpoint(&cp, &genesis_vset, &chain),
            "checkpoint handing off to a committee with a forged PoP must be rejected (rogue-key defense)"
        );
    }

    #[test]
    fn i1_same_selection_chain_coverage_mismatch_rejected() {
        // Adversarial selection test: a chain whose LENGTH equals cp.epoch but whose epoch
        // labels are shifted (1..=cp.epoch instead of 0..cp.epoch). verify must
        // reject — proving the ECC sequence selection is uniquely determined (the
        // apply path will roll the SAME sequence verify accepted, so a chain
        // verify rejects can never be applied).
        let (genesis_vset, _chain, cp) = build_chain(3);
        // Build a length-3 chain labelled epochs 1,2,3 (active sets shifted up).
        let active: Vec<(Vec<Keypair>, ValidatorSet)> = (1..=4u64)
            .map(|e| vset_from_seeds(&[10 + e, 11 + e, 12 + e, 13 + e]))
            .collect();
        let mut shifted = Vec::new();
        for idx in 0..3usize {
            let e = (idx as u64) + 1; // epochs 1,2,3
            shifted.push(ecc_handoff(e, &active[idx].0, active[idx + 1].1.clone()));
        }
        // Length is 3 == cp.epoch, so step 0 passes, but step 1 expects epoch 0
        // at k=0 while shifted[0].epoch == 1 ⇒ rejected.
        assert!(!verify_checkpoint(&cp, &genesis_vset, &shifted));
    }

    // ===== Short-anchor validation: verify_short_anchor adversarial tests =====

    /// Tip commit cert whose 2-chain is QC'd by `signer_kps` at `epoch`/`height`.
    fn tip_commit_cert(epoch: u64, height: u64, round: u64, signer_kps: &[Keypair]) -> CommitCert {
        let block = Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height,
            timestamp_ms: height,
            epoch,
            round: Round(round),
            parent_qc: QuorumCert::genesis(),
            payload_hash: blake3_id(&format!("tip-block-{epoch}-{height}")),
            author: NodeId::default(),
            reconfig: None,
        };
        let child = Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: height + 1,
            timestamp_ms: height + 1,
            epoch,
            round: Round(round + 1),
            parent_qc: qc_over(block.id(), Round(round), signer_kps),
            payload_hash: blake3_id(&format!("tip-child-{epoch}-{height}")),
            author: NodeId::default(),
            reconfig: None,
        };
        CommitCert {
            block,
            child: child.clone(),
            commit_qc: qc_over(child.id(), Round(round + 1), signer_kps),
        }
    }

    fn valid_short_anchor() -> (ShortAnchor, Vec<ValidatorSet>, Vec<Keypair>) {
        let (kps, vset) = vset_from_seeds(&[10, 11, 12, 13]);
        let tip = tip_commit_cert(5, 100, 50, &kps);
        let height = ChainAnchorV2::from_block(&tip.block).height;
        let anchor = ShortAnchor {
            height,
            epoch: 5,
            tip_commit: tip,
            locked: vec![LockedEpoch {
                epoch: 5,
                start_height: 80,
            }],
        };
        (anchor, vec![vset], kps)
    }

    #[test]
    fn short_anchor_accepts_valid_single_locked_epoch() {
        let (anchor, vsets, _) = valid_short_anchor();
        assert!(verify_short_anchor(&anchor, &vsets));
        assert!(short_anchor_matches_ops(&anchor.locked, &vsets, |e| {
            vsets
                .iter()
                .zip(anchor.locked.iter())
                .find(|(_, le)| le.epoch == e)
                .map(|(v, _)| v.clone())
        }));
    }

    #[test]
    fn short_anchor_accepts_two_consecutive_locked_epochs() {
        let (kps0, v0) = vset_from_seeds(&[10, 11, 12, 13]);
        let (_kps1, v1) = vset_from_seeds(&[20, 21, 22, 23]);
        let tip = tip_commit_cert(5, 100, 50, &kps0);
        let height = ChainAnchorV2::from_block(&tip.block).height;
        let anchor = ShortAnchor {
            height,
            epoch: 5,
            tip_commit: tip,
            locked: vec![
                LockedEpoch {
                    epoch: 5,
                    start_height: 80,
                },
                LockedEpoch {
                    epoch: 6,
                    start_height: 120,
                },
            ],
        };
        let vsets = vec![v0, v1];
        assert!(verify_short_anchor(&anchor, &vsets));
    }

    #[test]
    fn short_anchor_rejects_empty_locked() {
        let (mut anchor, vsets, _) = valid_short_anchor();
        anchor.locked.clear();
        assert!(!verify_short_anchor(&anchor, &vsets));
    }

    #[test]
    fn short_anchor_rejects_three_locked_epochs() {
        let (kps, v0) = vset_from_seeds(&[10, 11, 12, 13]);
        let tip = tip_commit_cert(5, 100, 50, &kps);
        let height = ChainAnchorV2::from_block(&tip.block).height;
        let anchor = ShortAnchor {
            height,
            epoch: 5,
            tip_commit: tip,
            locked: vec![
                LockedEpoch {
                    epoch: 5,
                    start_height: 80,
                },
                LockedEpoch {
                    epoch: 6,
                    start_height: 90,
                },
                LockedEpoch {
                    epoch: 7,
                    start_height: 100,
                },
            ],
        };
        let vsets = vec![v0.clone(), v0.clone(), v0];
        assert!(!verify_short_anchor(&anchor, &vsets));
    }

    #[test]
    fn short_anchor_rejects_non_consecutive_epochs() {
        let (kps, v0) = vset_from_seeds(&[10, 11, 12, 13]);
        let tip = tip_commit_cert(5, 100, 50, &kps);
        let height = ChainAnchorV2::from_block(&tip.block).height;
        let anchor = ShortAnchor {
            height,
            epoch: 5,
            tip_commit: tip,
            locked: vec![
                LockedEpoch {
                    epoch: 5,
                    start_height: 80,
                },
                LockedEpoch {
                    epoch: 7,
                    start_height: 90,
                },
            ],
        };
        assert!(!verify_short_anchor(&anchor, &[v0.clone(), v0]));
    }

    #[test]
    fn short_anchor_rejects_non_increasing_start_heights() {
        let (kps, v0) = vset_from_seeds(&[10, 11, 12, 13]);
        let tip = tip_commit_cert(5, 100, 50, &kps);
        let height = ChainAnchorV2::from_block(&tip.block).height;
        let anchor = ShortAnchor {
            height,
            epoch: 5,
            tip_commit: tip,
            locked: vec![
                LockedEpoch {
                    epoch: 5,
                    start_height: 90,
                },
                LockedEpoch {
                    epoch: 6,
                    start_height: 90,
                },
            ],
        };
        assert!(!verify_short_anchor(&anchor, &[v0.clone(), v0]));
    }

    #[test]
    fn short_anchor_rejects_vset_count_mismatch() {
        let (anchor, vsets, _) = valid_short_anchor();
        assert!(!verify_short_anchor(&anchor, &[]));
        assert!(!verify_short_anchor(
            &anchor,
            &[vsets[0].clone(), vsets[0].clone()]
        ));
    }

    #[test]
    fn short_anchor_rejects_epoch_not_matching_locked0() {
        let (mut anchor, vsets, _) = valid_short_anchor();
        anchor.epoch = 99;
        assert!(!verify_short_anchor(&anchor, &vsets));
    }

    #[test]
    fn short_anchor_rejects_height_outside_tip_block() {
        let (mut anchor, vsets, _) = valid_short_anchor();
        anchor.height = anchor.height + 1;
        assert!(!verify_short_anchor(&anchor, &vsets));
    }

    #[test]
    fn short_anchor_rejects_insufficient_tip_commit_stake() {
        let (kps, _) = vset_from_seeds(&[10, 11, 12, 13]);
        // Tip QC signed by only 2 of 4 — below 2f+1 for n=4.
        let tip = tip_commit_cert(5, 100, 50, &kps[..2]);
        let height = ChainAnchorV2::from_block(&tip.block).height;
        let (_, full) = vset_from_seeds(&[10, 11, 12, 13]);
        let anchor = ShortAnchor {
            height,
            epoch: 5,
            tip_commit: tip,
            locked: vec![LockedEpoch {
                epoch: 5,
                start_height: 80,
            }],
        };
        assert!(!verify_short_anchor(&anchor, &[full]));
    }

    #[test]
    fn short_anchor_rejects_invalid_pop() {
        use azbft_crypto::bls::BlsSecretKey;
        use azbft_types::Member;
        let (signer_kps, _) = vset_from_seeds(&[10, 11, 12, 13]);
        let tip = tip_commit_cert(5, 100, 50, &signer_kps);
        let height = ChainAnchorV2::from_block(&tip.block).height;
        // Build a BLS-keyed set with a forged PoP on member 0, but tip_commit is
        // still signed by the secp genesis-style set — so commit_cert verify will
        // fail against the BLS set. Use the same node ids as the tip signers so
        // the failure is specifically PoP (after we make tip verify against a
        // secp set that also has BLS columns).
        let members: Vec<Member> = signer_kps
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let bsk = BlsSecretKey::from_seed(900 + i as u64);
                let pop = if i == 0 {
                    BlsSecretKey::from_seed(515_151)
                        .prove_possession()
                        .to_bytes()
                        .to_vec()
                } else {
                    bsk.prove_possession().to_bytes().to_vec()
                };
                Member::new(
                    k.node_id(),
                    k.pubkey_bytes(),
                    bsk.public().to_bytes().to_vec(),
                    pop,
                    1u64,
                )
            })
            .collect();
        let bad = ValidatorSet::new_members(members);
        let anchor = ShortAnchor {
            height,
            epoch: 5,
            tip_commit: tip,
            locked: vec![LockedEpoch {
                epoch: 5,
                start_height: 80,
            }],
        };
        // PoP gate runs before commit_cert; forged PoP must reject.
        assert!(!verify_short_anchor(&anchor, &[bad]));
    }

    #[test]
    fn short_anchor_ops_mismatch_rejected() {
        let (anchor, vsets, _) = valid_short_anchor();
        let (_, other) = vset_from_seeds(&[90, 91, 92, 93]);
        assert!(!short_anchor_matches_ops(&anchor.locked, &vsets, |_| Some(
            other.clone()
        )));
        assert!(!short_anchor_matches_ops(&anchor.locked, &vsets, |_| None));
    }

    #[test]
    fn short_anchor_ops_match_accepts_exact_sets() {
        let (anchor, vsets, _) = valid_short_anchor();
        let expected = vsets[0].clone();
        assert!(short_anchor_matches_ops(&anchor.locked, &vsets, |e| (e
            == 5)
            .then(|| expected.clone())));
    }
}
