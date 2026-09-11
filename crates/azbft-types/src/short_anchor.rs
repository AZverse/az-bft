//! Ops-trusted short anchor for catch-up without a genesis-anchored ECC spine.
//!
//! A short anchor answers "where to resume" (height + tip commit cert + at most
//! two locked epochs). Validator membership for those epochs comes from an
//! out-of-band ops file and is checked by the caller — this type does not carry
//! a genesis-anchored transition chain.

use crate::{ChainAnchorV2, CommitCert};
use borsh::{BorshDeserialize, BorshSerialize};

/// Maximum locked epochs carried by a short anchor (wire + validation).
pub const SHORT_ANCHOR_MAX_LOCKED: usize = 2;

/// One locked epoch: membership for `epoch` becomes active at `start_height`.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct LockedEpoch {
    pub epoch: u64,
    pub start_height: u64,
}

/// Tip-proximate recovery anchor. Trust is carried by `tip_commit` under the
/// validator set supplied out-of-band for `locked[0]`, not by an ECC spine.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ShortAnchor {
    pub height: u64,
    pub epoch: u64,
    pub tip_commit: CommitCert,
    /// 1..=[`SHORT_ANCHOR_MAX_LOCKED`] entries; first is the tip epoch.
    pub locked: Vec<LockedEpoch>,
}

impl ShortAnchor {
    pub fn tip_block(&self) -> &crate::Block {
        &self.tip_commit.block
    }

    pub fn certified_height(&self) -> u64 {
        ChainAnchorV2::from_block(&self.tip_commit.block).height
    }
}
