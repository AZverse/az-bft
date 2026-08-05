use crate::consensus_message::Signed;
use crate::vote::Vote;
use borsh::{BorshDeserialize, BorshSerialize};

/// Self-contained proof that one validator double-signed: two votes with the
/// same (voter, epoch, round) but different block_id, both validly signed.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EquivocationProof {
    pub vote_a: Signed<Vote>,
    pub vote_b: Signed<Vote>,
}

impl EquivocationProof {
    /// Canonicalize by block_id so the same double-sign always serializes
    /// identically (basis for content-dedup in the gossip slice, Evidence gossip).
    pub fn new(x: Signed<Vote>, y: Signed<Vote>) -> Self {
        if x.inner.block_id <= y.inner.block_id {
            Self {
                vote_a: x,
                vote_b: y,
            }
        } else {
            Self {
                vote_a: y,
                vote_b: x,
            }
        }
    }
}
