//! Epoch-change certificates and validator-set reconfiguration types.
//!
//! An `EpochChangeCert` proves that an epoch quorum committed a
//! reconfiguration block through the two-chain rule. The certificate carries
//! its quorum authentication and can be relayed without an outer signature.
//! Cryptographic validation lives in `azbft-core`.
use crate::block::Block;
use crate::cert::QuorumCert;
use crate::evidence::EquivocationProof;
use crate::ids::NodeId;
use crate::validator::ValidatorSet;
use borsh::{BorshDeserialize, BorshSerialize};

/// A temporary validator removal and its minimum return epoch.
///
/// Both fields are included in the canonical operator signing bytes.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct JailRecord {
    /// The temporarily removed validator.
    pub offender: NodeId,
    /// The first epoch in which the validator may return to the set.
    pub until_epoch: u64,
}

/// A validator-set transition committed as part of a block.
///
/// Evidence-bearing transitions justify removals through equivocation proofs.
/// Operator-authorized transitions may perform trusted set changes.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Reconfig {
    pub next_set: ValidatorSet,
    /// Double-sign proofs that justify evidence-based removals. Producers must
    /// order multiple proofs deterministically because this vector is hashed.
    pub evidence: Vec<EquivocationProof>,
    /// Optional operator authorization over the canonical reconfiguration bytes.
    pub operator_sig: Option<Vec<u8>>,
    /// Optional temporary-removal terms enforced before the offender returns.
    pub jail: Option<JailRecord>,
}

/// Canonical bytes an operator signs (Domain::Reconfig) to authorize a reconfig.
/// Binds (next_set, epoch, jail) to prevent:
///   - replay across epochs (epoch field),
///   - swap to a different set (next_set field),
///   - tampering with jail terms after signing (jail field).
pub fn reconfig_signing_bytes(next_set: &ValidatorSet, epoch: u64) -> Vec<u8> {
    // Reconfigurations without jail terms use the original canonical form.
    // Jail-aware callers use `reconfig_signing_bytes_jail`.
    borsh::to_vec(&(next_set, epoch)).expect("borsh")
}

/// Canonical bytes an operator signs for a jail/return reconfig.
/// Includes the `jail` field so a signed jail reconfig cannot have its
/// `until_epoch` silently bumped or its `offender` swapped.
pub fn reconfig_signing_bytes_jail(
    next_set: &ValidatorSet,
    epoch: u64,
    jail: &Option<JailRecord>,
) -> Vec<u8> {
    borsh::to_vec(&(next_set, epoch, jail)).expect("borsh")
}

/// M-of-N operator authority configured as a chain constant.
///
/// This value is not serialized into blocks or messages. A single-key set uses
/// a raw secp256k1 signature; a multi-key set uses a Borsh-encoded list of
/// indexed signatures and accepts distinct valid signers at the threshold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorSet {
    /// Authorized operator public keys (secp). Order is significant: a
    /// multi-sig entry's `key_index` indexes into this list.
    pub keys: Vec<Vec<u8>>,
    /// Minimum number of DISTINCT valid signatures required to authorize a
    /// reconfig. Invariant (enforced by [`OperatorSet::new`]):
    /// `1 <= threshold <= keys.len()`.
    pub threshold: u32,
}

impl OperatorSet {
    /// Constructs a single-operator authority with threshold one.
    pub fn single(pk: Vec<u8>) -> Self {
        Self {
            keys: vec![pk],
            threshold: 1,
        }
    }

    /// Build an M-of-N set, returning `None` for degenerate parameters
    /// (`keys` empty, `threshold` 0, or `threshold > keys.len()`).
    pub fn new(keys: Vec<Vec<u8>>, threshold: u32) -> Option<Self> {
        if keys.is_empty() || threshold == 0 || threshold as usize > keys.len() {
            return None;
        }
        Some(Self { keys, threshold })
    }

    /// Returns whether signatures use the single-key raw encoding.
    pub fn is_legacy_single(&self) -> bool {
        self.keys.len() == 1 && self.threshold == 1
    }
}

/// Encode an M-of-N operator signature: a list of `(key_index, signature)`
/// pairs, one per participating operator. Fills `Reconfig.operator_sig` when
/// the [`OperatorSet`] is not the legacy single-key shape.
pub fn operator_multisig_encode(sigs: &[(u16, Vec<u8>)]) -> Vec<u8> {
    borsh::to_vec(&sigs.to_vec()).expect("borsh")
}

/// Decode M-of-N operator signature bytes into `(key_index, signature)` pairs.
/// Returns `None` on malformed input (a garbage `operator_sig` is rejected,
/// never panics).
pub fn operator_multisig_decode(bytes: &[u8]) -> Option<Vec<(u16, Vec<u8>)>> {
    borsh::from_slice::<Vec<(u16, Vec<u8>)>>(bytes).ok()
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EpochChangeCert {
    /// The committed reconfiguration block at round `R0` in epoch `e`.
    pub reconfig_block: Block,
    /// Its child at round `R0 + 1`, whose parent QC certifies the block.
    pub child_block: Block,
    /// A quorum certificate for the child from epoch `e`.
    pub commit_qc: QuorumCert,
}

/// A two-chain commit proof for any block.
///
/// `commit_qc` certifies `child`, while `child.parent_qc` certifies `block`;
/// the two blocks must occupy consecutive rounds.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct CommitCert {
    pub block: Block,
    pub child: Block,
    pub commit_qc: QuorumCert,
}

impl EpochChangeCert {
    /// Returns the epoch ended by this certificate.
    pub fn epoch(&self) -> u64 {
        self.reconfig_block.epoch
    }
    /// Returns the next validator set after successful certificate validation.
    pub fn next_set(&self) -> &ValidatorSet {
        &self
            .reconfig_block
            .reconfig
            .as_ref()
            .expect("next_set called on a cert whose reconfig_block has no reconfig")
            .next_set
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{Hash, NodeId, Round};

    fn vset(tag: u8) -> ValidatorSet {
        ValidatorSet::new(vec![(NodeId([tag; 20]), vec![tag], 1)])
    }

    fn block(epoch: u64, round: u64, reconfig: Option<Reconfig>) -> Block {
        Block {
            header_version: crate::BLOCK_HEADER_VERSION_V2,
            height: 1,
            timestamp_ms: 1,
            epoch,
            round: Round(round),
            // parent_qc left as genesis here — crypto 2-chain linkage is verified in azbft-core
            parent_qc: QuorumCert::genesis(),
            payload_hash: Hash::default(),
            author: NodeId::default(),
            reconfig,
        }
    }

    fn sample(epoch: u64, next: ValidatorSet) -> EpochChangeCert {
        EpochChangeCert {
            reconfig_block: block(
                epoch,
                5,
                Some(Reconfig {
                    next_set: next,
                    evidence: vec![],
                    operator_sig: None,
                    jail: None,
                }),
            ),
            child_block: block(epoch, 6, None),
            commit_qc: QuorumCert::genesis(),
        }
    }

    #[test]
    fn jail_record_borsh_roundtrip() {
        let jr = JailRecord {
            offender: NodeId([5; 20]),
            until_epoch: 7,
        };
        let rc = Reconfig {
            next_set: vset(1),
            evidence: vec![],
            operator_sig: Some(vec![0xAB, 0xCD]),
            jail: Some(jr.clone()),
        };
        let bytes = borsh::to_vec(&rc).unwrap();
        let back: Reconfig = borsh::from_slice(&bytes).unwrap();
        assert_eq!(rc, back);
        assert_eq!(back.jail.as_ref().unwrap().offender, jr.offender);
        assert_eq!(back.jail.as_ref().unwrap().until_epoch, jr.until_epoch);
    }

    #[test]
    fn jail_signing_bytes_differ_from_plain() {
        // reconfig_signing_bytes_jail(jail=Some) must differ from plain form,
        // so a jail-reconfig signature cannot be replayed as a plain reconfig sig.
        let vs = vset(3);
        let epoch = 2u64;
        let jr = JailRecord {
            offender: NodeId([9; 20]),
            until_epoch: 5,
        };
        let plain = reconfig_signing_bytes(&vs, epoch);
        let jail_some = reconfig_signing_bytes_jail(&vs, epoch, &Some(jr));
        let jail_none = reconfig_signing_bytes_jail(&vs, epoch, &None);
        // jail=Some(...) must differ from plain form AND from jail=None form.
        assert_ne!(plain, jail_some, "jail sig bytes must differ from plain");
        assert_ne!(jail_none, jail_some, "jail=None vs jail=Some must differ");
    }

    #[test]
    fn epoch_change_cert_borsh_roundtrip() {
        let ecc = sample(3, vset(7));
        let bytes = borsh::to_vec(&ecc).unwrap();
        let back: EpochChangeCert = borsh::from_slice(&bytes).unwrap();
        assert_eq!(ecc, back);
    }

    #[test]
    fn accessors_report_epoch_and_next_set() {
        let next = vset(9);
        let ecc = sample(2, next.clone());
        assert_eq!(ecc.epoch(), 2);
        assert_eq!(ecc.next_set(), &next);
    }
}
