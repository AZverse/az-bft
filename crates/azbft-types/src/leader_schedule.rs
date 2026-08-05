//! Chain-constant leader-schedule selector.
//!
//! This type's `u8` encoding occupies a stable slot in `GenesisCanonical` (the
//! genesis hash preimage). `RoundRobin` preserves the original schedule, while
//! `StakeWeighted` provides deterministic integer stake-weighted selection (see
//! `ValidatorSet::leader_weighted`). Both `"round_robin"` and
//! `"stake_weighted"` are canonical encodings; the chosen mode is
//! chain-authoritative, so every validator on the same genesis selects the same
//! leader for every round — a mismatch would fork.
//!
//! The reserved enum slot allows both schedules without changing the genesis
//! canonical version.

use borsh::{BorshDeserialize, BorshSerialize};

/// Deterministic leader-selection schedule (a chain constant). Only ever
/// borsh-encoded as part of `GenesisCanonical`; it is deliberately NOT part of
/// `ValidatorSet` (which rides into `Block::id()` via `Reconfig.next_set`), so
/// adding it here is not a wire break.
///
/// `RoundRobin = 0`, `StakeWeighted = 1` — this ordinal is load-bearing for the
/// genesis hash and MUST NOT be reordered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum LeaderSchedule {
    /// `members[round % n]` — deterministic round-robin selection.
    #[default]
    RoundRobin,
    /// Stake-weighted deterministic selection: a `blake3(round)`-derived
    /// integer point over the cumulative-stake buckets. A member with stake `S`
    /// leads with probability `S / total_stake`. Opt-in via genesis.
    StakeWeighted,
}

impl LeaderSchedule {
    /// The stable ordinal used in the `GenesisCanonical` borsh preimage.
    /// `RoundRobin = 0`, `StakeWeighted = 1`.
    pub fn to_u8(self) -> u8 {
        match self {
            LeaderSchedule::RoundRobin => 0,
            LeaderSchedule::StakeWeighted => 1,
        }
    }
}

/// Parse the canonical leader-schedule string.
impl std::str::FromStr for LeaderSchedule {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "round_robin" => Ok(LeaderSchedule::RoundRobin),
            "stake_weighted" => Ok(LeaderSchedule::StakeWeighted),
            other => Err(format!(
                "unknown leader_schedule '{other}' (expected: round_robin | stake_weighted)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn from_str_round_trips_both_variants() {
        assert_eq!(
            LeaderSchedule::from_str("round_robin").unwrap(),
            LeaderSchedule::RoundRobin
        );
        assert_eq!(
            LeaderSchedule::from_str("stake_weighted").unwrap(),
            LeaderSchedule::StakeWeighted
        );
        assert!(LeaderSchedule::from_str("bogus").is_err());
    }

    #[test]
    fn to_u8_ordinal_is_stable() {
        // This ordinal is baked into GenesisCanonical; reordering would silently
        // change every chain's genesis hash.
        assert_eq!(LeaderSchedule::RoundRobin.to_u8(), 0);
        assert_eq!(LeaderSchedule::StakeWeighted.to_u8(), 1);
    }

    #[test]
    fn default_is_round_robin() {
        assert_eq!(LeaderSchedule::default(), LeaderSchedule::RoundRobin);
    }
}
