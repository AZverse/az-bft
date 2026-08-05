use crate::block::Block;
use crate::cert::{QuorumCert, TimeoutCert};
use crate::ids::{blake3_id, Hash, NodeId, Round};
use borsh::{BorshDeserialize, BorshSerialize};

/// The message a vote signs over. Binds the block id AND its round so a QC's
/// `round` field is cryptographically authenticated: a valid QC (a real
/// aggregate over `block_id`) can no longer be relabelled to a higher round to
/// bypass the safety lock (`make_vote`'s `parent_qc.round >= preferred_round`
/// check). Every vote sign-site and every vote-aggregate verify-site MUST use
/// this digest, not the bare `block_id`, or signatures will not match.
///
pub fn vote_digest(block_id: &Hash, round: Round) -> Hash {
    blake3_id(&(*block_id, round))
}

/// The message a timeout signs over. Binds the EPOCH as well as the round so a
/// TimeoutCert cannot be replayed across an epoch boundary: an epoch roll resets
/// the round counter to 1, so without the epoch a real TC from a past epoch would
/// re-verify in a new epoch and let a Byzantine leader re-open the round-jump
/// (view-stall) griefing that the proposal round-proof closes. Every timeout
/// sign-site and every TC-aggregate verify-site MUST use this digest, not the
/// bare round.
pub fn timeout_digest(epoch: u64, round: Round) -> Hash {
    blake3_id(&(epoch, round))
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Vote {
    pub epoch: u64,
    pub block_id: Hash,
    pub round: Round,
    pub voter: NodeId,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Timeout {
    pub epoch: u64,
    pub round: Round,
    pub high_qc: QuorumCert,
    pub sender: NodeId,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Proposal {
    pub block: Block,
    pub last_round_tc: Option<TimeoutCert>,
}
