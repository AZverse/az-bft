use crate::cert::QuorumCert;
use crate::ids::{blake3_id, Hash, NodeId, Round};
use crate::reconfig::Reconfig;
use borsh::{BorshDeserialize, BorshSerialize};

pub const BLOCK_HEADER_VERSION_V2: u16 = 2;
pub const MAX_BLOCK_TIME_STEP_MS: u64 = 60_000;
pub const MAX_FUTURE_DRIFT_MS: u64 = 5_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChainAnchorV2 {
    pub height: u64,
    pub timestamp_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockHeaderV2Error {
    UnsupportedVersion {
        actual: u16,
    },
    HeightOverflow,
    HeightMismatch {
        expected: u64,
        actual: u64,
    },
    TimestampOverflow,
    TimestampNotMonotonic {
        parent_timestamp_ms: u64,
        timestamp_ms: u64,
    },
    TimestampStepTooLarge {
        parent_timestamp_ms: u64,
        timestamp_ms: u64,
    },
    FutureTimestamp {
        timestamp_ms: u64,
        local_wall_clock_ms: u64,
    },
    ClockBehind {
        proposed_timestamp_ms: u64,
        local_wall_clock_ms: u64,
    },
}

impl ChainAnchorV2 {
    pub fn from_block(block: &Block) -> Self {
        Self {
            height: block.height,
            timestamp_ms: block.timestamp_ms,
        }
    }

    pub fn next_for_proposal(self, local_wall_clock_ms: u64) -> Result<Self, BlockHeaderV2Error> {
        let height = self
            .height
            .checked_add(1)
            .ok_or(BlockHeaderV2Error::HeightOverflow)?;
        let minimum = self
            .timestamp_ms
            .checked_add(1)
            .ok_or(BlockHeaderV2Error::TimestampOverflow)?;
        let maximum = self.timestamp_ms.saturating_add(MAX_BLOCK_TIME_STEP_MS);
        let timestamp_ms = local_wall_clock_ms.max(minimum).min(maximum);
        if timestamp_ms > local_wall_clock_ms.saturating_add(MAX_FUTURE_DRIFT_MS) {
            return Err(BlockHeaderV2Error::ClockBehind {
                proposed_timestamp_ms: timestamp_ms,
                local_wall_clock_ms,
            });
        }
        Ok(Self {
            height,
            timestamp_ms,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Block {
    pub header_version: u16,
    pub height: u64,
    pub timestamp_ms: u64,
    pub epoch: u64,
    pub round: Round,
    pub parent_qc: QuorumCert,
    pub payload_hash: Hash,
    pub author: NodeId,
    pub reconfig: Option<Reconfig>,
}

impl Block {
    pub fn id(&self) -> Hash {
        blake3_id(self)
    }
}

pub fn validate_block_header_v2(
    block: &Block,
    parent: ChainAnchorV2,
    local_wall_clock_ms: Option<u64>,
) -> Result<(), BlockHeaderV2Error> {
    if block.header_version != BLOCK_HEADER_VERSION_V2 {
        return Err(BlockHeaderV2Error::UnsupportedVersion {
            actual: block.header_version,
        });
    }
    let expected_height = parent
        .height
        .checked_add(1)
        .ok_or(BlockHeaderV2Error::HeightOverflow)?;
    if block.height != expected_height {
        return Err(BlockHeaderV2Error::HeightMismatch {
            expected: expected_height,
            actual: block.height,
        });
    }
    if block.timestamp_ms <= parent.timestamp_ms {
        return Err(BlockHeaderV2Error::TimestampNotMonotonic {
            parent_timestamp_ms: parent.timestamp_ms,
            timestamp_ms: block.timestamp_ms,
        });
    }
    if block.timestamp_ms - parent.timestamp_ms > MAX_BLOCK_TIME_STEP_MS {
        return Err(BlockHeaderV2Error::TimestampStepTooLarge {
            parent_timestamp_ms: parent.timestamp_ms,
            timestamp_ms: block.timestamp_ms,
        });
    }
    if let Some(local_wall_clock_ms) = local_wall_clock_ms {
        if block.timestamp_ms > local_wall_clock_ms.saturating_add(MAX_FUTURE_DRIFT_MS) {
            return Err(BlockHeaderV2Error::FutureTimestamp {
                timestamp_ms: block.timestamp_ms,
                local_wall_clock_ms,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    #[test]
    fn block_id_changes_with_round() {
        let qc = QuorumCert {
            block_id: Hash::default(),
            round: Round(0),
            agg: AggSig::default(),
        };
        let b1 = Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 1,
            timestamp_ms: 1,
            epoch: 0,
            round: Round(1),
            parent_qc: qc.clone(),
            payload_hash: Hash::default(),
            author: NodeId::default(),
            reconfig: None,
        };
        let mut b2 = b1.clone();
        b2.round = Round(2);
        assert_ne!(b1.id(), b2.id());
    }
}
