//! Vote aggregation with secp256k1 and BLS12-381 implementations.
//!
//! * [`SecpMultiSig`] stores a sorted set of per-validator signatures and
//!   verifies them individually.
//! * [`BlsMultiSig`] stores one aggregate signature plus a sorted signer set
//!   and uses fast aggregate verification.
//!
//! QC formation uses the scheme selected when the consensus core is
//! constructed. Verification dispatches on the certificate's own [`AggSig`]
//! variant via [`verify_agg`], so historical certificates remain verifiable.
//! The BLS path requires proof-of-possession validation when validator keys are
//! admitted.

use crate::bls::{
    aggregate_signatures, fast_aggregate_verify, pop_verify, BlsPublicKey, BlsSignature,
};
use crate::domain::Domain;
use crate::keypair::verify;
use azbft_types::{
    cert::{AggSig, BlsAgg},
    ids::{Hash, NodeId},
    ValidatorSet,
};

#[derive(Debug, thiserror::Error)]
pub enum AggError {
    #[error("below quorum: {got} < {need}")]
    BelowQuorum { got: u64, need: u64 },
    #[error("invalid signer {0:?}")]
    UnknownSigner(NodeId),
    #[error("bad signature from {0:?}")]
    BadSig(NodeId),
    #[error("duplicate signer {0:?}")]
    Duplicate(NodeId),
    /// The aggregate's bytes did not decode as a valid group element, or the
    /// certificate variant did not match the verifier called.
    #[error("malformed aggregate")]
    Malformed,
}

pub trait VoteAggregator {
    /// Aggregate per-validator vote signatures into an [`AggSig`]. `votes` is
    /// `(signer, sig_bytes)`; the resulting signer set is sorted+deduped so two
    /// honest formers over the same signer set produce byte-identical output.
    fn aggregate(votes: &[(NodeId, Vec<u8>)]) -> AggSig;
    /// Verify an aggregate against `msg`/`domain`/`vset`, requiring a stake
    /// quorum. Each implementation accepts only its own [`AggSig`] variant.
    fn verify(
        agg: &AggSig,
        msg: &Hash,
        domain: Domain,
        vset: &ValidatorSet,
    ) -> Result<(), AggError>;
}

pub struct SecpMultiSig;

impl VoteAggregator for SecpMultiSig {
    fn aggregate(votes: &[(NodeId, Vec<u8>)]) -> AggSig {
        let started = crate::perf::start();
        let mut sigs = votes.to_vec();
        sigs.sort_by_key(|a| a.0);
        sigs.dedup_by(|a, b| a.0 == b.0);
        let aggregate = AggSig::Secp(sigs);
        crate::perf::record_qc_aggregate(started);
        aggregate
    }

    fn verify(
        agg: &AggSig,
        msg: &Hash,
        domain: Domain,
        vset: &ValidatorSet,
    ) -> Result<(), AggError> {
        let sigs = match agg {
            AggSig::Secp(s) => s,
            AggSig::Bls(_) => return Err(AggError::Malformed),
        };
        let mut prev: Option<NodeId> = None;
        let mut power: u64 = 0;
        for (signer, sig) in sigs {
            if let Some(p) = prev {
                if p >= *signer {
                    return Err(AggError::Duplicate(*signer));
                }
            }
            prev = Some(*signer);
            let pk = vset
                .pubkey_of(signer)
                .ok_or(AggError::UnknownSigner(*signer))?;
            if !verify(domain, &msg.0, sig, pk) {
                return Err(AggError::BadSig(*signer));
            }
            power += vset.stake_of(signer).unwrap_or(0);
        }
        let need = vset.quorum();
        if power < need {
            return Err(AggError::BelowQuorum { got: power, need });
        }
        Ok(())
    }
}

pub struct BlsMultiSig;

impl VoteAggregator for BlsMultiSig {
    /// Aggregate per-validator BLS vote signatures into `AggSig::Bls`.
    ///
    /// Each `(signer, sig_bytes)` is parsed back into a [`BlsSignature`] and
    /// summed (`aggregate_signatures`). The `signers` set is sorted ascending by
    /// NodeId and deduped — this ordering is what keeps `Block::id()` stable
    /// across two honest formers (see `BlsAgg`).
    ///
    /// Formation only ever runs once collected stake crosses quorum, on votes
    /// whose single signatures were already verified at collection time
    /// (`on_vote`'s hoisted verify), so the inputs are well-formed; a signature
    /// that nonetheless fails to parse is dropped (it cannot have been a
    /// collected, verified vote).
    fn aggregate(votes: &[(NodeId, Vec<u8>)]) -> AggSig {
        let started = crate::perf::start();
        // Dedup by signer, keeping the first sig seen, then sort by NodeId.
        let mut seen: Vec<NodeId> = Vec::new();
        let mut sigs: Vec<BlsSignature> = Vec::new();
        let mut pairs: Vec<(NodeId, &Vec<u8>)> = Vec::with_capacity(votes.len());
        for (n, s) in votes {
            if seen.contains(n) {
                continue;
            }
            seen.push(*n);
            pairs.push((*n, s));
        }
        pairs.sort_by_key(|p| p.0);
        let mut signers: Vec<NodeId> = Vec::with_capacity(pairs.len());
        for (n, s) in pairs {
            match BlsSignature::from_bytes(s) {
                Some(sig) => {
                    signers.push(n);
                    sigs.push(sig);
                }
                None => continue, // unparseable: cannot be a collected verified vote
            }
        }
        let agg_sig = aggregate_signatures(&sigs)
            .map(|a| a.to_bytes())
            .unwrap_or([0u8; 96]); // empty only if no parseable sigs (never at quorum)
        let aggregate = AggSig::Bls(BlsAgg { agg_sig, signers });
        crate::perf::record_qc_aggregate(started);
        aggregate
    }

    /// Verify a BLS aggregate: resolve each signer's BLS public key from `vset`,
    /// enforce strictly-ascending (deduped) signer order, run one
    /// fast-aggregate-verify over `digest(domain, msg)`, and require a stake
    /// quorum.
    fn verify(
        agg: &AggSig,
        msg: &Hash,
        domain: Domain,
        vset: &ValidatorSet,
    ) -> Result<(), AggError> {
        let b: &BlsAgg = match agg {
            AggSig::Bls(b) => b,
            AggSig::Secp(_) => return Err(AggError::Malformed),
        };
        let mut prev: Option<NodeId> = None;
        let mut power: u64 = 0;
        let mut pks: Vec<BlsPublicKey> = Vec::with_capacity(b.signers.len());
        for signer in &b.signers {
            if let Some(p) = prev {
                if p >= *signer {
                    return Err(AggError::Duplicate(*signer));
                }
            }
            prev = Some(*signer);
            let pk_bytes = vset
                .bls_pubkey_of(signer)
                .ok_or(AggError::UnknownSigner(*signer))?;
            let pk = BlsPublicKey::from_bytes(pk_bytes).ok_or(AggError::UnknownSigner(*signer))?;
            pks.push(pk);
            power += vset.stake_of(signer).unwrap_or(0);
        }
        let agg_sig = BlsSignature::from_bytes(&b.agg_sig).ok_or(AggError::Malformed)?;
        // fast_aggregate_verify rejects an empty key list, so a quorum-empty
        // signer set is caught here as well as by the quorum check below.
        if !fast_aggregate_verify(domain, &msg.0, &agg_sig, &pks) {
            // No single signer to blame for an aggregate failure; report the
            // first listed signer (matches the secp `BadSig` shape).
            return Err(AggError::BadSig(
                *b.signers.first().unwrap_or(&NodeId([0; 20])),
            ));
        }
        let need = vset.quorum();
        if power < need {
            return Err(AggError::BelowQuorum { got: power, need });
        }
        Ok(())
    }
}

/// Verify an aggregate by dispatching on the certificate's **own** variant.
///
/// This is the single verification entry point used by every consensus
/// call-site (process_qc, ECC/commit-cert checks, sync). It deliberately does
/// **not** consult any injected/forming scheme: a node must be able to verify a
/// secp historical cert even on a BLS network, and vice-versa.
pub fn verify_agg(
    agg: &AggSig,
    msg: &Hash,
    domain: Domain,
    vset: &ValidatorSet,
) -> Result<(), AggError> {
    let started = matches!(domain, Domain::Vote)
        .then(crate::perf::start)
        .flatten();
    let guard = crate::perf::AggregateVerifyGuard::enter();
    let result = match agg {
        AggSig::Secp(_) => SecpMultiSig::verify(agg, msg, domain, vset),
        AggSig::Bls(_) => BlsMultiSig::verify(agg, msg, domain, vset),
    };
    drop(guard);
    crate::perf::record_aggregate_verify(started);
    result
}

/// Verify the proof-of-possession of every BLS key registered in `vset`.
///
/// Members with an empty BLS column (secp-only members) are skipped — they
/// register no BLS key and so present no rogue-key surface. For every member
/// that *does* carry a BLS public key, a valid PoP over that key is required;
/// a missing or forged PoP makes the whole set invalid. Call this when adopting
/// a vset from an untrusted source (reconfig `next_set`, sync, checkpoint) so a
/// rogue BLS key can never be admitted into the fast-aggregate set.
pub fn verify_vset_pops(vset: &ValidatorSet) -> bool {
    for m in vset.members() {
        if m.bls_pubkey.is_empty() {
            continue; // secp-only member: no BLS key to validate
        }
        let (Some(pk), Some(pop)) = (
            BlsPublicKey::from_bytes(&m.bls_pubkey),
            BlsSignature::from_bytes(&m.bls_pop),
        ) else {
            return false; // BLS column present but unparseable
        };
        if !pop_verify(&pk, &pop) {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::BlsSecretKey;
    use crate::{domain::Domain, keypair::Keypair};
    use azbft_types::{ids::Hash, Member, ValidatorSet};

    fn setup(n: u8) -> (Vec<Keypair>, ValidatorSet) {
        let kps: Vec<_> = (0..n).map(|i| Keypair::from_seed(100 + i as u64)).collect();
        let m = kps
            .iter()
            .map(|k| Member::secp_only(k.node_id(), k.pubkey_bytes(), 1u64))
            .collect();
        (kps, ValidatorSet::new_members(m))
    }

    /// Build a dual-key vset: each validator has a secp key (for node_id) and a
    /// BLS key derived from the SAME seed, with a valid PoP.
    fn setup_bls(n: u8) -> (Vec<Keypair>, Vec<BlsSecretKey>, ValidatorSet) {
        let kps: Vec<_> = (0..n).map(|i| Keypair::from_seed(500 + i as u64)).collect();
        let blss: Vec<_> = (0..n)
            .map(|i| BlsSecretKey::from_seed(500 + i as u64))
            .collect();
        let m = kps
            .iter()
            .zip(blss.iter())
            .map(|(k, b)| {
                Member::new(
                    k.node_id(),
                    k.pubkey_bytes(),
                    b.public().to_bytes().to_vec(),
                    b.prove_possession().to_bytes().to_vec(),
                    1u64,
                )
            })
            .collect();
        (kps, blss, ValidatorSet::new_members(m))
    }

    // ===== secp path (unchanged behaviour through the enum) =====

    #[test]
    fn quorum_of_votes_verifies() {
        let (kps, vs) = setup(4); // quorum = 3
        let msg = Hash([9u8; 32]);
        let votes: Vec<_> = kps
            .iter()
            .take(3)
            .map(|k| (k.node_id(), k.sign(Domain::Vote, &msg.0)))
            .collect();
        let agg = SecpMultiSig::aggregate(&votes);
        assert!(SecpMultiSig::verify(&agg, &msg, Domain::Vote, &vs).is_ok());
        // verify_agg dispatches to the secp path on a Secp cert.
        assert!(verify_agg(&agg, &msg, Domain::Vote, &vs).is_ok());
    }

    #[test]
    fn below_quorum_fails() {
        let (kps, vs) = setup(4);
        let msg = Hash([9u8; 32]);
        let votes: Vec<_> = kps
            .iter()
            .take(2)
            .map(|k| (k.node_id(), k.sign(Domain::Vote, &msg.0)))
            .collect();
        assert!(
            SecpMultiSig::verify(&SecpMultiSig::aggregate(&votes), &msg, Domain::Vote, &vs)
                .is_err()
        );
    }

    #[test]
    fn forged_sig_fails() {
        let (kps, vs) = setup(4);
        let msg = Hash([9u8; 32]);
        let mut votes: Vec<_> = kps
            .iter()
            .take(3)
            .map(|k| (k.node_id(), k.sign(Domain::Vote, &msg.0)))
            .collect();
        votes[0].1 = vec![0u8; votes[0].1.len()];
        assert!(
            SecpMultiSig::verify(&SecpMultiSig::aggregate(&votes), &msg, Domain::Vote, &vs)
                .is_err()
        );
    }

    #[test]
    fn wrong_domain_fails() {
        let (kps, vs) = setup(4);
        let msg = Hash([9u8; 32]);
        let votes: Vec<_> = kps
            .iter()
            .take(3)
            .map(|k| (k.node_id(), k.sign(Domain::Vote, &msg.0)))
            .collect();
        // signed under Vote, verified under Timeout -> reject
        assert!(
            SecpMultiSig::verify(&SecpMultiSig::aggregate(&votes), &msg, Domain::Timeout, &vs)
                .is_err()
        );
    }

    // BLS aggregation.

    /// Aggregate `take` BLS votes from `blss` over `msg`.
    fn bls_votes(
        kps: &[Keypair],
        blss: &[BlsSecretKey],
        msg: &Hash,
        take: usize,
    ) -> Vec<(NodeId, Vec<u8>)> {
        kps.iter()
            .zip(blss.iter())
            .take(take)
            .map(|(k, b)| {
                (
                    k.node_id(),
                    b.sign(Domain::Vote, &msg.0).to_bytes().to_vec(),
                )
            })
            .collect()
    }

    #[test]
    fn bls_quorum_roundtrip() {
        let (kps, blss, vs) = setup_bls(4); // quorum = 3
        let msg = Hash([42u8; 32]);
        let votes = bls_votes(&kps, &blss, &msg, 3);
        let agg = BlsMultiSig::aggregate(&votes);
        assert!(matches!(agg, AggSig::Bls(_)));
        assert!(BlsMultiSig::verify(&agg, &msg, Domain::Vote, &vs).is_ok());
        assert!(verify_agg(&agg, &msg, Domain::Vote, &vs).is_ok());
    }

    #[test]
    fn bls_below_quorum_fails() {
        let (kps, blss, vs) = setup_bls(4);
        let msg = Hash([42u8; 32]);
        let votes = bls_votes(&kps, &blss, &msg, 2); // < quorum
        let agg = BlsMultiSig::aggregate(&votes);
        assert!(matches!(
            BlsMultiSig::verify(&agg, &msg, Domain::Vote, &vs),
            Err(AggError::BelowQuorum { .. })
        ));
    }

    #[test]
    fn bls_tampered_agg_sig_rejected() {
        let (kps, blss, vs) = setup_bls(4);
        let msg = Hash([42u8; 32]);
        let votes = bls_votes(&kps, &blss, &msg, 3);
        let AggSig::Bls(mut b) = BlsMultiSig::aggregate(&votes) else {
            panic!("expected Bls");
        };
        b.agg_sig[40] ^= 0x01;
        let agg = AggSig::Bls(b);
        assert!(BlsMultiSig::verify(&agg, &msg, Domain::Vote, &vs).is_err());
    }

    #[test]
    fn bls_wrong_domain_fails() {
        let (kps, blss, vs) = setup_bls(4);
        let msg = Hash([42u8; 32]);
        let votes = bls_votes(&kps, &blss, &msg, 3);
        let agg = BlsMultiSig::aggregate(&votes);
        assert!(BlsMultiSig::verify(&agg, &msg, Domain::Timeout, &vs).is_err());
    }

    #[test]
    fn bls_unknown_signer_rejected() {
        let (kps, blss, vs) = setup_bls(4);
        let msg = Hash([42u8; 32]);
        let votes = bls_votes(&kps, &blss, &msg, 3);
        let AggSig::Bls(mut b) = BlsMultiSig::aggregate(&votes) else {
            panic!();
        };
        // Inject a signer not in vset (keep sorted order intact by using a high id).
        b.signers.push(NodeId([0xff; 20]));
        let agg = AggSig::Bls(b);
        assert!(matches!(
            BlsMultiSig::verify(&agg, &msg, Domain::Vote, &vs),
            Err(AggError::UnknownSigner(_))
        ));
    }

    #[test]
    fn bls_duplicate_or_unsorted_signers_rejected() {
        let (kps, blss, vs) = setup_bls(4);
        let msg = Hash([42u8; 32]);
        let votes = bls_votes(&kps, &blss, &msg, 3);
        let AggSig::Bls(mut b) = BlsMultiSig::aggregate(&votes) else {
            panic!();
        };
        // Reverse order -> not strictly ascending -> Duplicate.
        b.signers.reverse();
        let agg = AggSig::Bls(b.clone());
        assert!(matches!(
            BlsMultiSig::verify(&agg, &msg, Domain::Vote, &vs),
            Err(AggError::Duplicate(_))
        ));
        // Literal duplicate.
        let mut b2 = b.clone();
        b2.signers = vec![b2.signers[0], b2.signers[0]];
        assert!(matches!(
            BlsMultiSig::verify(&AggSig::Bls(b2), &msg, Domain::Vote, &vs),
            Err(AggError::Duplicate(_))
        ));
    }

    #[test]
    fn bls_aggregate_sorts_signers_deterministically() {
        // Input order does not affect the aggregate encoding.
        let (kps, blss, vs) = setup_bls(4);
        let _ = &vs;
        let msg = Hash([42u8; 32]);
        let mut votes = bls_votes(&kps, &blss, &msg, 3);
        let in_order = BlsMultiSig::aggregate(&votes);
        votes.reverse();
        let reversed = BlsMultiSig::aggregate(&votes);
        // Whole AggSig bytes must match (signer order + agg sig are canonical).
        assert_eq!(
            borsh::to_vec(&in_order).unwrap(),
            borsh::to_vec(&reversed).unwrap()
        );
    }

    #[test]
    fn bls_signer_set_integrity_mismatch_rejected() {
        // A signer list must match the keys used for aggregation.
        let (kps, blss, vs) = setup_bls(4);
        let msg = Hash([42u8; 32]);
        // Aggregate signatures from signers {0,1,2} ...
        let votes = bls_votes(&kps, &blss, &msg, 3);
        let AggSig::Bls(mut b) = BlsMultiSig::aggregate(&votes) else {
            panic!();
        };
        // ... but claim a different signer set {0,1,3} (still in vset, sorted).
        // Replace the 3rd signer (idx 2) with validator 3's node_id.
        let v3 = kps[3].node_id();
        b.signers[2] = v3;
        b.signers.sort();
        let agg = AggSig::Bls(b);
        // Signature was over {0,1,2}; verifying against pubkeys {0,1,3} must fail.
        assert!(BlsMultiSig::verify(&agg, &msg, Domain::Vote, &vs).is_err());
    }

    // Aggregate verification dispatch and scheme isolation.

    #[test]
    fn verify_agg_dispatches_by_variant() {
        let (kps, blss, vs) = setup_bls(4);
        let msg = Hash([7u8; 32]);
        // Secp cert verifies via verify_agg even on a dual-key vset.
        let secp_votes: Vec<_> = kps
            .iter()
            .take(3)
            .map(|k| (k.node_id(), k.sign(Domain::Vote, &msg.0)))
            .collect();
        let secp = SecpMultiSig::aggregate(&secp_votes);
        assert!(verify_agg(&secp, &msg, Domain::Vote, &vs).is_ok());
        // BLS cert verifies via verify_agg.
        let bls = BlsMultiSig::aggregate(&bls_votes(&kps, &blss, &msg, 3));
        assert!(verify_agg(&bls, &msg, Domain::Vote, &vs).is_ok());
    }

    #[test]
    fn cross_scheme_verifier_rejects_wrong_variant() {
        let (kps, blss, vs) = setup_bls(4);
        let msg = Hash([7u8; 32]);
        let secp = SecpMultiSig::aggregate(
            &kps.iter()
                .take(3)
                .map(|k| (k.node_id(), k.sign(Domain::Vote, &msg.0)))
                .collect::<Vec<_>>(),
        );
        let bls = BlsMultiSig::aggregate(&bls_votes(&kps, &blss, &msg, 3));
        // Calling the BLS verifier on a Secp cert (or vice-versa) -> Malformed.
        assert!(matches!(
            BlsMultiSig::verify(&secp, &msg, Domain::Vote, &vs),
            Err(AggError::Malformed)
        ));
        assert!(matches!(
            SecpMultiSig::verify(&bls, &msg, Domain::Vote, &vs),
            Err(AggError::Malformed)
        ));
    }

    // Proof-of-possession registration.

    #[test]
    fn vset_pops_accept_valid_and_reject_forged() {
        let (_kps, _blss, vs) = setup_bls(4);
        assert!(verify_vset_pops(&vs));

        // Forge: replace one member's PoP with a PoP from a different BLS key.
        let mut members = vs.members().to_vec();
        let rogue = BlsSecretKey::from_seed(9999);
        members[0].bls_pop = rogue.prove_possession().to_bytes().to_vec();
        let bad = ValidatorSet::new_members(members);
        assert!(!verify_vset_pops(&bad));
    }

    #[test]
    fn vset_pops_skip_secp_only_members() {
        // A secp-only vset (no BLS columns) trivially passes PoP verification.
        let (_kps, vs) = setup(4);
        assert!(verify_vset_pops(&vs));
    }
}
