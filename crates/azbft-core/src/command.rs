use crate::event::Duration;
use azbft_types::{
    evidence::EquivocationProof, Block, CommitCert, ConsensusMessage, NodeId, QuorumCert, Round,
};

/// The payload of `Command::Commit`: a committed block and its linked
/// certificate, assembled together in `process_qc`.
///
/// Carrying the proof with the block prevents the host from reconstructing it
/// from mutable high-QC state.
///
/// `two_chain == true` iff this is the batch tail (highest round in the commit
/// chain), whose `cert` is a real adjacent-round 2-chain: `block ← child`, with
/// `commit_qc` certifying `child`. Middle blocks of a multi-block commit carry a
/// *linkage-level* cert instead — still `commit_qc` certifies `child` and
/// `child.parent_qc` certifies `block`, but the rounds need not be adjacent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommittedBlock {
    pub block: Block,
    pub cert: CommitCert,
    pub two_chain: bool,
}

/// A durable snapshot of the safety-critical state a node must persist before
/// emitting any message that depends on it. Persisting `{epoch,
/// last_voted_round, preferred_round}` is the necessary-and-sufficient quantity
/// for cross-crash safety. Restoring these monotone watermarks prevents both
/// double voting and lock violations. `high_qc` and the block tree are
/// deliberately excluded because they are
/// re-synced (block sync), keeping this the minimal safety slice.
///
/// borsh-serializable so the driver can atomically write it to a small file
/// (no RocksDB) and `load` it back on startup.
#[derive(Clone, Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct SafetySnapshot {
    pub epoch: u64,
    pub last_voted_round: Round,
    pub preferred_round: Round,
}

/// Immutable leader context chosen before external proposal preparation.
///
/// The full parent certificate is the freshness token. A prepared payload is
/// usable only while this exact epoch/round/parent remains current.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalBuildContext {
    pub epoch: u64,
    pub round: Round,
    pub parent: QuorumCert,
    pub height: u64,
    pub timestamp_ms: u64,
    pub proposer: NodeId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Broadcast(ConsensusMessage),
    Send(NodeId, ConsensusMessage),
    SetTimer(Round, Duration),
    CancelTimer,
    CreatePayload {
        round: Round,
        parent: QuorumCert,
    },
    /// Boxed: `CommittedBlock` (block + linked cert = up to 3 blocks + 2 QCs)
    /// is far larger than every other variant, so inlining it would bloat every
    /// `Vec<Command>` slot to that size (`clippy::large_enum_variant`).
    Commit(Box<CommittedBlock>),
    /// Persist the safety state durably (fsync) before any later command in the
    /// same `handle()` batch is executed. The core *prepends* this whenever a
    /// `handle()` call changed the safety snapshot, so every dependent outbound
    /// message in that batch is sequenced after the snapshot is durable. The
    /// driver performs the atomic write+fsync; the deterministic devnet treats it
    /// as a no-op.
    Persist(SafetySnapshot),
    /// A validator was caught double-signing: two conflicting votes for the
    /// same (voter, epoch, round) with distinct block_ids, both validly signed.
    /// Emitted by `on_vote` when the equivocation-detection side branch fires.
    /// Hosts are responsible for durable retention or forwarding; the
    /// deterministic devnet acknowledges this effect as a no-op.
    Equivocation(EquivocationProof),
}
