use azbft_types::{Block, CommitCert, Hash, ValidatorSet};
use borsh::{BorshDeserialize, BorshSerialize};

pub const TRANSCRIPT_VERSION: u16 = 1;

/// One finalized block, its linked proof, and the deterministic application state.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct FinalizedRecord {
    pub block: Block,
    pub certificate: CommitCert,
    pub two_chain: bool,
    pub application_commitment: Hash,
}

/// Portable output of a deterministic AZBFT devnet run.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct DevnetTranscript {
    pub version: u16,
    pub seed: u64,
    pub validator_set: ValidatorSet,
    pub finalized: Vec<FinalizedRecord>,
    pub view_changes: u64,
    pub processed_events: u64,
}
