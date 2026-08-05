//! App-hash voting for periodic execution-state commitments.
//!
//! Every configured interval, a validator signs its deterministic execution-state
//! commitment. Validators tally votes by stake; quorum stake on the same
//! `(height, app_hash)` forms an [`AppHashCert`]. Conflicting app hashes at the
//! same height are detectable execution divergence.

use crate::cert::AggSig;
use crate::ids::{blake3_id, Hash, NodeId};
use crate::validator::ValidatorSet;
use borsh::{BorshDeserialize, BorshSerialize};

/// One node's vote on the execution state commitment at a given height.
/// Signed under `Domain::AppHash`; `voter` is inside the signed bytes so it
/// cannot be swapped, and tells a verifier whose pubkey to check.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AppHashVote {
    pub epoch: u64,
    pub height: u64,
    pub app_hash: Hash,
    pub voter: NodeId,
}

/// 2f+1-by-stake certificate that the cluster agreed on `app_hash` at `height`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AppHashCert {
    pub epoch: u64,
    pub height: u64,
    pub app_hash: Hash,
    pub voters: Vec<NodeId>,
}

/// Portable statement of an execution-state commitment, bound to its historical
/// validator set. This is additive to the driver-only AppHash messages above.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AppHashStatementV1 {
    pub chain_id: u64,
    pub epoch: u64,
    pub validator_set_hash: Hash,
    pub height: u64,
    pub app_hash: Hash,
}

impl AppHashStatementV1 {
    /// Deterministic Borsh identity signed under `Domain::AppHash`.
    pub fn id(&self) -> Hash {
        blake3_id(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AppHashVoteV1 {
    pub statement: AppHashStatementV1,
    pub voter: NodeId,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AppHashCertV1 {
    pub statement: AppHashStatementV1,
    pub agg: AggSig,
}

/// Maximum certificates an app-hash retrieval response may carry.
pub const APP_HASH_CERT_RESPONSE_LIMIT: u16 = 64;

/// A bounded request for consecutive app-hash certificates.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AppHashCertRequestV1 {
    pub start_height: u64,
    pub limit: u16,
}

/// Request validation failure for AppHashCertRequestV1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppHashCertRequestV1Error {
    InvalidLimit(u16),
}

impl AppHashCertRequestV1 {
    /// Creates a retrieval request whose limit is in 1..=64.
    pub fn new(start_height: u64, limit: u16) -> Result<Self, AppHashCertRequestV1Error> {
        let request = Self {
            start_height,
            limit,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the request limit after decoding untrusted wire bytes.
    pub fn validate(&self) -> Result<(), AppHashCertRequestV1Error> {
        if (1..=APP_HASH_CERT_RESPONSE_LIMIT).contains(&self.limit) {
            Ok(())
        } else {
            Err(AppHashCertRequestV1Error::InvalidLimit(self.limit))
        }
    }
}

/// A bounded response carrying independently verifiable app-hash certificates.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AppHashCertResponseV1 {
    pub certificates: Vec<AppHashCertV1>,
}

/// Response validation failure for AppHashCertResponseV1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppHashCertResponseV1Error {
    TooManyCertificates(usize),
}

impl AppHashCertResponseV1 {
    /// Creates a response containing at most 64 certificates.
    pub fn new(certificates: Vec<AppHashCertV1>) -> Result<Self, AppHashCertResponseV1Error> {
        let response = Self { certificates };
        response.validate()?;
        Ok(response)
    }

    /// Validates the response bound after decoding untrusted wire bytes.
    pub fn validate(&self) -> Result<(), AppHashCertResponseV1Error> {
        if self.certificates.len() <= usize::from(APP_HASH_CERT_RESPONSE_LIMIT) {
            Ok(())
        } else {
            Err(AppHashCertResponseV1Error::TooManyCertificates(
                self.certificates.len(),
            ))
        }
    }
}

pub fn validator_set_hash(vset: &ValidatorSet) -> Hash {
    blake3_id(vset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_hash_types_roundtrip_borsh() {
        let v = AppHashVote {
            epoch: 2,
            height: 40,
            app_hash: crate::ids::blake3_id(b"state@40"),
            voter: NodeId([7; 20]),
        };
        assert_eq!(
            borsh::from_slice::<AppHashVote>(&borsh::to_vec(&v).unwrap()).unwrap(),
            v
        );
        let cert = AppHashCert {
            epoch: 2,
            height: 40,
            app_hash: v.app_hash,
            voters: vec![NodeId([7; 20]), NodeId([8; 20])],
        };
        assert_eq!(
            borsh::from_slice::<AppHashCert>(&borsh::to_vec(&cert).unwrap()).unwrap(),
            cert
        );
    }
}
