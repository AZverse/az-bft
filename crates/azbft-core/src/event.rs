use crate::command::ProposalBuildContext;
use azbft_types::{
    evidence::EquivocationProof,
    vote::{Proposal, Timeout, Vote},
    Block, JailRecord, NodeId, QuorumCert, Round, Signed, ValidatorSet,
};

pub type Duration = u64;
pub type LogicalTime = u64;

// A proposal carries its parent certificate, including any BLS aggregate and
// signer list. Keeping the event inline avoids an allocation on the main
// proposal path, so the size difference is accepted explicitly.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
pub enum Event {
    Proposal(Signed<Proposal>),
    Vote(Signed<Vote>),
    RemoteTimeout(Signed<Timeout>),
    LocalTimeout(Round),
    PayloadReady {
        context: ProposalBuildContext,
        payload: Vec<u8>,
    },
    RequestReconfig(ValidatorSet, Vec<u8>),
    /// Operator-submitted, evidence-justified removal of a single misbehaving
    /// validator. The core validates (target in current set + proof names it +
    /// proof verifies) before staging a `Reconfig`; invalid submissions are
    /// silently dropped.
    RequestRemoval(NodeId, EquivocationProof),
    /// Stages an operator-authorized temporary removal. The supplied set must
    /// exclude the offender and the jail terms are covered by the signature.
    RequestJail(ValidatorSet, Vec<u8>, JailRecord),
    /// Applies an already verified committed chain segment through the normal
    /// QC-processing path.
    SyncApply {
        blocks: Vec<Block>,
        commit_qc: QuorumCert,
    },
}
