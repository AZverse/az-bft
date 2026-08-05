use crate::{Block, ChainAnchorV2, CommitCert, ValidatorSet};
use borsh::{BorshDeserialize, BorshSerialize};

/// A recent epoch-boundary checkpoint whose trust is carried by its commit
/// certificate and the validator-set transition chain leading to it.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Checkpoint {
    pub height: u64,
    pub epoch: u64,
    pub validator_set: ValidatorSet,
    pub chain_anchor: ChainAnchorV2,
    pub commit_cert: CommitCert,
}

impl Checkpoint {
    pub fn anchor_block(&self) -> &Block {
        &self.commit_cert.block
    }
}
