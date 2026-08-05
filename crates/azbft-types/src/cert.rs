use crate::ids::{Hash, NodeId, Round};
use borsh::{BorshDeserialize, BorshSerialize};

/// A BLS aggregate signature carried by a QC/cert.
///
/// `agg_sig` is a single fixed-length (96-byte, min-pk G2 compressed) aggregate
/// of the per-validator vote signatures; `signers` lists exactly which
/// validators contributed, **sorted ascending by `NodeId` and deduplicated**.
/// The verifier re-derives each signer's BLS public key from the validator set
/// and runs a single fast-aggregate-verify.
///
/// Determinism (load-bearing): `signers` MUST be sorted, because this struct is
/// borsh-serialized into `QuorumCert.agg` → `Block.parent_qc` → `Block::id()`.
/// Two honest formers that pick the same signer set must produce byte-identical
/// `AggSig::Bls` or their `Block::id()`s would diverge (a fork). The aggregate
/// signature itself is order-independent (BLS aggregation is group addition), so
/// only `signers` ordering needs pinning. Sorting is enforced in
/// `BlsMultiSig::aggregate` (azbft-crypto).
///
/// `azbft-types` deliberately stores only **bytes** here — it does not depend on
/// `azbft-crypto`/`blst`. All aggregation/verification logic lives in azbft-crypto.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BlsAgg {
    /// BLS12-381 G2 aggregate signature, fixed 96-byte compressed encoding.
    pub agg_sig: [u8; 96],
    /// Contributing signers, sorted ascending by NodeId and deduplicated.
    pub signers: Vec<NodeId>,
}

/// Aggregated signature over a quorum of votes.
///
/// Two schemes coexist on the wire. Borsh's enum discriminant identifies the
/// signature variant, so verification dispatches on certificate bytes rather
/// than the node's QC forming scheme. Historical certificates therefore remain
/// verifiable after a configuration change.
///
/// `Default = Secp(vec![])` is the empty genesis representation used by
/// `QuorumCert::genesis()`; it does not select the scheme used for new QCs.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum AggSig {
    /// A sorted set of per-validator secp256k1 signatures.
    Secp(Vec<(NodeId, Vec<u8>)>),
    /// BLS aggregate: one constant-size signature + the signer set.
    Bls(BlsAgg),
}

impl Default for AggSig {
    fn default() -> Self {
        AggSig::Secp(Vec::new())
    }
}

impl AggSig {
    /// Construct a secp aggregate from already-collected per-validator sigs.
    /// (Convenience for the secp path; the bytes are NOT sorted here — callers
    /// that need determinism go through `SecpMultiSig::aggregate`.)
    pub fn secp(sigs: Vec<(NodeId, Vec<u8>)>) -> Self {
        AggSig::Secp(sigs)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct QuorumCert {
    pub block_id: Hash,
    pub round: Round,
    pub agg: AggSig,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TimeoutCert {
    pub round: Round,
    pub agg: AggSig,
    pub high_qc: QuorumCert,
}

impl QuorumCert {
    /// Genesis QC: round 0, empty agg.
    pub fn genesis() -> Self {
        Self {
            block_id: Hash::default(),
            round: Round(0),
            agg: AggSig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::{from_slice, to_vec};

    #[test]
    fn default_is_empty_secp() {
        assert_eq!(AggSig::default(), AggSig::Secp(Vec::new()));
    }

    #[test]
    fn secp_variant_tag_is_zero() {
        // borsh enum discriminant: first variant (Secp) => leading byte 0x00.
        let bytes = to_vec(&AggSig::Secp(Vec::new())).unwrap();
        assert_eq!(bytes[0], 0x00);
    }

    #[test]
    fn bls_variant_tag_is_one_and_fixed_len() {
        let agg = AggSig::Bls(BlsAgg {
            agg_sig: [7u8; 96],
            signers: vec![NodeId([1; 20]), NodeId([2; 20])],
        });
        let bytes = to_vec(&agg).unwrap();
        assert_eq!(bytes[0], 0x01);
        // roundtrip
        let back: AggSig = from_slice(&bytes).unwrap();
        assert_eq!(agg, back);
    }

    #[test]
    fn aggsig_borsh_roundtrip_both_variants() {
        let secp = AggSig::Secp(vec![(NodeId([3; 20]), vec![9, 9, 9])]);
        let secp2: AggSig = from_slice(&to_vec(&secp).unwrap()).unwrap();
        assert_eq!(secp, secp2);

        let bls = AggSig::Bls(BlsAgg {
            agg_sig: [0xab; 96],
            signers: vec![NodeId([0; 20])],
        });
        let bls2: AggSig = from_slice(&to_vec(&bls).unwrap()).unwrap();
        assert_eq!(bls, bls2);
    }
}
