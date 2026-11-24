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
//!
//! `RoundRobinSkipAbsent` and `StakeWeightedSkipAbsent` (blockchain#95) keep the
//! base schedule but hand a round away from a validator that did not sign the
//! liveness QC — the QC carried by the parent of the block being proposed. See
//! `ValidatorSet::leader_after`.
//!
//! `RoundRobinSkipAbsentParent` and `StakeWeightedSkipAbsentParent` (blockchain#174) also
//! count the parent block's author as present. That author's own vote usually arrives after
//! the quorum, so the liveness QC leaves it out; counted absent, it lost every round it was
//! the base leader of, and one hand-over kept the whole schedule one place off.

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
    /// `RoundRobin`, skipping ahead past members absent from the liveness QC.
    RoundRobinSkipAbsent,
    /// `StakeWeighted`, re-mapping the same point over the stakes of the members
    /// present in the liveness QC when the base leader is absent from it.
    StakeWeightedSkipAbsent,
    /// `RoundRobinSkipAbsent`, with the parent block's author present too (blockchain#174).
    RoundRobinSkipAbsentParent,
    /// `StakeWeightedSkipAbsent`, with the parent block's author present too (blockchain#174).
    StakeWeightedSkipAbsentParent,
}

impl LeaderSchedule {
    /// The stable ordinal used in the `GenesisCanonical` borsh preimage.
    /// `RoundRobin = 0`, `StakeWeighted = 1`.
    pub fn to_u8(self) -> u8 {
        match self {
            LeaderSchedule::RoundRobin => 0,
            LeaderSchedule::StakeWeighted => 1,
            LeaderSchedule::RoundRobinSkipAbsent => 2,
            LeaderSchedule::StakeWeightedSkipAbsent => 3,
            LeaderSchedule::RoundRobinSkipAbsentParent => 4,
            LeaderSchedule::StakeWeightedSkipAbsentParent => 5,
        }
    }

    /// True for the schedules that skip validators absent from the liveness QC.
    pub fn skips_absent(self) -> bool {
        matches!(
            self,
            LeaderSchedule::RoundRobinSkipAbsent
                | LeaderSchedule::StakeWeightedSkipAbsent
                | LeaderSchedule::RoundRobinSkipAbsentParent
                | LeaderSchedule::StakeWeightedSkipAbsentParent
        )
    }

    /// True for the schedules that count the parent block's author as present (blockchain#174).
    pub fn counts_parent_author(self) -> bool {
        matches!(
            self,
            LeaderSchedule::RoundRobinSkipAbsentParent
                | LeaderSchedule::StakeWeightedSkipAbsentParent
        )
    }

    /// The schedule a host switches a skip-absent chain to once the parent author counts as
    /// present; every other schedule is returned as it is.
    pub fn with_parent_present(self) -> LeaderSchedule {
        match self {
            LeaderSchedule::RoundRobinSkipAbsent => LeaderSchedule::RoundRobinSkipAbsentParent,
            LeaderSchedule::StakeWeightedSkipAbsent => {
                LeaderSchedule::StakeWeightedSkipAbsentParent
            }
            other => other,
        }
    }

    /// The schedule a skip-absent mode falls back to (and itself for the others).
    pub fn base(self) -> LeaderSchedule {
        match self {
            LeaderSchedule::RoundRobin
            | LeaderSchedule::RoundRobinSkipAbsent
            | LeaderSchedule::RoundRobinSkipAbsentParent => LeaderSchedule::RoundRobin,
            LeaderSchedule::StakeWeighted
            | LeaderSchedule::StakeWeightedSkipAbsent
            | LeaderSchedule::StakeWeightedSkipAbsentParent => LeaderSchedule::StakeWeighted,
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
            "round_robin_skip_absent" => Ok(LeaderSchedule::RoundRobinSkipAbsent),
            "stake_weighted_skip_absent" => Ok(LeaderSchedule::StakeWeightedSkipAbsent),
            "round_robin_skip_absent_parent" => Ok(LeaderSchedule::RoundRobinSkipAbsentParent),
            "stake_weighted_skip_absent_parent" => {
                Ok(LeaderSchedule::StakeWeightedSkipAbsentParent)
            }
            other => Err(format!(
                "unknown leader_schedule '{other}' (expected: round_robin | stake_weighted | \
                 round_robin_skip_absent | stake_weighted_skip_absent | \
                 round_robin_skip_absent_parent | stake_weighted_skip_absent_parent)"
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
        assert_eq!(
            LeaderSchedule::from_str("round_robin_skip_absent").unwrap(),
            LeaderSchedule::RoundRobinSkipAbsent
        );
        assert_eq!(
            LeaderSchedule::from_str("stake_weighted_skip_absent").unwrap(),
            LeaderSchedule::StakeWeightedSkipAbsent
        );
        assert!(LeaderSchedule::from_str("bogus").is_err());
    }

    #[test]
    fn to_u8_ordinal_is_stable() {
        // This ordinal is baked into GenesisCanonical; reordering would silently
        // change every chain's genesis hash.
        assert_eq!(LeaderSchedule::RoundRobin.to_u8(), 0);
        assert_eq!(LeaderSchedule::StakeWeighted.to_u8(), 1);
        assert_eq!(LeaderSchedule::RoundRobinSkipAbsent.to_u8(), 2);
        assert_eq!(LeaderSchedule::StakeWeightedSkipAbsent.to_u8(), 3);
    }

    #[test]
    fn skip_absent_modes_fall_back_to_their_base() {
        assert!(!LeaderSchedule::RoundRobin.skips_absent());
        assert!(!LeaderSchedule::StakeWeighted.skips_absent());
        assert_eq!(
            LeaderSchedule::RoundRobinSkipAbsent.base(),
            LeaderSchedule::RoundRobin
        );
        assert_eq!(
            LeaderSchedule::StakeWeightedSkipAbsent.base(),
            LeaderSchedule::StakeWeighted
        );
        assert!(LeaderSchedule::RoundRobinSkipAbsent.skips_absent());
    }

    #[test]
    fn parent_present_modes_parse_and_keep_their_ordinals() {
        // blockchain#174: genesis values 4 and 5. Only a chain that names them carries them in
        // its genesis preimage, so the hashes of existing chains are unchanged.
        assert_eq!(
            LeaderSchedule::from_str("round_robin_skip_absent_parent").unwrap(),
            LeaderSchedule::RoundRobinSkipAbsentParent
        );
        assert_eq!(
            LeaderSchedule::from_str("stake_weighted_skip_absent_parent").unwrap(),
            LeaderSchedule::StakeWeightedSkipAbsentParent
        );
        assert_eq!(LeaderSchedule::RoundRobinSkipAbsentParent.to_u8(), 4);
        assert_eq!(LeaderSchedule::StakeWeightedSkipAbsentParent.to_u8(), 5);
    }

    #[test]
    fn parent_present_modes_skip_absent_over_their_base() {
        assert!(LeaderSchedule::RoundRobinSkipAbsentParent.skips_absent());
        assert!(LeaderSchedule::StakeWeightedSkipAbsentParent.skips_absent());
        assert_eq!(
            LeaderSchedule::RoundRobinSkipAbsentParent.base(),
            LeaderSchedule::RoundRobin
        );
        assert_eq!(
            LeaderSchedule::StakeWeightedSkipAbsentParent.base(),
            LeaderSchedule::StakeWeighted
        );
    }

    #[test]
    fn only_parent_present_modes_count_the_parent_author() {
        for mode in [
            LeaderSchedule::RoundRobin,
            LeaderSchedule::StakeWeighted,
            LeaderSchedule::RoundRobinSkipAbsent,
            LeaderSchedule::StakeWeightedSkipAbsent,
        ] {
            assert!(!mode.counts_parent_author(), "{mode:?}");
        }
        assert!(LeaderSchedule::RoundRobinSkipAbsentParent.counts_parent_author());
        assert!(LeaderSchedule::StakeWeightedSkipAbsentParent.counts_parent_author());
    }

    #[test]
    fn with_parent_present_moves_only_the_skip_absent_modes() {
        // What a host switches a chain to once its rule revision takes effect.
        assert_eq!(
            LeaderSchedule::RoundRobinSkipAbsent.with_parent_present(),
            LeaderSchedule::RoundRobinSkipAbsentParent
        );
        assert_eq!(
            LeaderSchedule::StakeWeightedSkipAbsent.with_parent_present(),
            LeaderSchedule::StakeWeightedSkipAbsentParent
        );
        for mode in [
            LeaderSchedule::RoundRobin,
            LeaderSchedule::StakeWeighted,
            LeaderSchedule::RoundRobinSkipAbsentParent,
            LeaderSchedule::StakeWeightedSkipAbsentParent,
        ] {
            assert_eq!(mode.with_parent_present(), mode, "{mode:?}");
        }
    }

    #[test]
    fn default_is_round_robin() {
        assert_eq!(LeaderSchedule::default(), LeaderSchedule::RoundRobin);
    }
}
