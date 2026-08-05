use crate::{Proposal, Timeout, Vote};
use borsh::{BorshDeserialize, BorshSerialize};

/// A value paired with its consensus-domain signature bytes.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Signed<T>
where
    T: BorshSerialize + BorshDeserialize,
{
    pub inner: T,
    pub sig: Vec<u8>,
}

/// The complete message surface accepted or emitted by the sans-IO core.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[allow(
    clippy::large_enum_variant,
    reason = "boxing the proposal variant would change the public API and Borsh encoding"
)]
pub enum ConsensusMessage {
    Proposal(Signed<Proposal>),
    Vote(Signed<Vote>),
    Timeout(Signed<Timeout>),
}
