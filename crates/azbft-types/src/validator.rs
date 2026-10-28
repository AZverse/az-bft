use crate::cert::QuorumCert;
use crate::ids::{blake3_id, NodeId, Round};
use crate::leader_schedule::LeaderSchedule;
use borsh::{BorshDeserialize, BorshSerialize};

pub type Stake = u64;
pub type PubKeyBytes = Vec<u8>;
/// 48-byte compressed min-pk BLS public key bytes (BLS validator-key column).
/// Empty `Vec` = "no BLS key registered for this member" (secp-only network /
/// legacy member): such a member cannot participate in a BLS aggregate, so a
/// BLS QC naming it fails `bls_pubkey_of` → `UnknownSigner` (no forgery surface).
pub type BlsPubKeyBytes = Vec<u8>;
/// 96-byte BLS proof-of-possession over the member's own BLS public key. Empty
/// when no BLS key is registered. Verified (`pop_verify`) when a vset is adopted
/// from an untrusted source (reconfig next_set / sync / checkpoint).
pub type BlsPopBytes = Vec<u8>;

/// One validator-set member: a **dual-key** identity (BLS wire format).
///
/// `node_id` stays secp-derived (`blake3(secp_pubkey)[..20]`) — unchanged from
/// secp-compatible baseline. `bls_pubkey` (+ its `bls_pop`) is the additional BLS column used
/// only for QC aggregation; it is empty on a secp-only network. The struct is
/// borsh-serialized (it rides into `Block::id()` via `Reconfig.next_set`), so
/// adding the BLS columns is part of the BLS wire format wire break.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Member {
    pub node_id: NodeId,
    pub pubkey: PubKeyBytes, // secp SEC1
    pub bls_pubkey: BlsPubKeyBytes,
    pub bls_pop: BlsPopBytes,
    pub stake: Stake,
}

impl Member {
    /// Full dual-key member.
    pub fn new(
        node_id: NodeId,
        pubkey: PubKeyBytes,
        bls_pubkey: BlsPubKeyBytes,
        bls_pop: BlsPopBytes,
        stake: Stake,
    ) -> Self {
        Self {
            node_id,
            pubkey,
            bls_pubkey,
            bls_pop,
            stake,
        }
    }
    /// A secp-only member (no BLS column). For secp-default networks / tests
    /// that never exercise the BLS aggregation path.
    pub fn secp_only(node_id: NodeId, pubkey: PubKeyBytes, stake: Stake) -> Self {
        Self {
            node_id,
            pubkey,
            bls_pubkey: Vec::new(),
            bls_pop: Vec::new(),
            stake,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ValidatorSet {
    members: Vec<Member>, // invariant: sorted by NodeId, deduped
}

impl ValidatorSet {
    /// Build a set from `(NodeId, secp pubkey, stake)` tuples with **empty BLS
    /// columns** (secp-only members). This keeps the secp-compatible baseline call signature, so
    /// secp-default networks and every existing test compile unchanged. Use
    /// [`ValidatorSet::new_members`] to register BLS keys.
    pub fn new(members: Vec<(NodeId, PubKeyBytes, Stake)>) -> Self {
        Self::new_members(
            members
                .into_iter()
                .map(|(id, pk, s)| Member::secp_only(id, pk, s))
                .collect(),
        )
    }
    /// Build a set from full dual-key [`Member`]s (BLS wire format). Sorts by NodeId
    /// and dedups (invariant).
    pub fn new_members(mut members: Vec<Member>) -> Self {
        members.sort_by_key(|m| m.node_id);
        members.dedup_by(|a, b| a.node_id == b.node_id);
        Self { members }
    }
    pub fn members(&self) -> &[Member] {
        &self.members
    }
    pub fn len(&self) -> usize {
        self.members.len()
    }
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
    pub fn total_stake(&self) -> Stake {
        self.members.iter().map(|m| m.stake).sum()
    }
    /// 2f+1 by stake: floor(2*total/3) + 1. Computed in u128 so `2 * total` cannot
    /// overflow at wei-scale stake — a validly-loaded vset's `total_stake()` can
    /// approach `u64::MAX`, and `2 * total` in u64 would wrap. The threshold
    /// is always `<= total_stake()`, so it fits back into `Stake`.
    pub fn quorum(&self) -> Stake {
        let total = self.total_stake() as u128;
        (2 * total / 3 + 1) as Stake
    }
    /// Returns whether `id` is a member of this validator set.
    pub fn contains(&self, id: &NodeId) -> bool {
        self.members.iter().any(|m| &m.node_id == id)
    }
    pub fn stake_of(&self, id: &NodeId) -> Option<Stake> {
        self.members
            .iter()
            .find(|m| &m.node_id == id)
            .map(|m| m.stake)
    }
    pub fn pubkey_of(&self, id: &NodeId) -> Option<&[u8]> {
        self.members
            .iter()
            .find(|m| &m.node_id == id)
            .map(|m| m.pubkey.as_slice())
    }
    /// The member's BLS public-key bytes, or `None` if absent / empty (no BLS
    /// key registered). Used by `BlsMultiSig::verify` to resolve signers.
    pub fn bls_pubkey_of(&self, id: &NodeId) -> Option<&[u8]> {
        self.members
            .iter()
            .find(|m| &m.node_id == id)
            .map(|m| m.bls_pubkey.as_slice())
            .filter(|b| !b.is_empty())
    }
    /// The member's BLS proof-of-possession bytes, or `None` if absent / empty.
    pub fn bls_pop_of(&self, id: &NodeId) -> Option<&[u8]> {
        self.members
            .iter()
            .find(|m| &m.node_id == id)
            .map(|m| m.bls_pop.as_slice())
            .filter(|b| !b.is_empty())
    }
    pub fn leader(&self, round: Round) -> NodeId {
        let i = (round.0 as usize) % self.members.len();
        self.members[i].node_id
    }
    pub fn upcoming_leaders(&self, from: Round, count: usize) -> Vec<NodeId> {
        (0..count)
            .map(|k| self.leader(Round(from.0 + k as u64)))
            .collect()
    }

    /// stake-weighted leader for `round`. Deterministic and integer-only (CORE
    /// determinism rule — no floats): a `blake3(round)`-derived point in `[0, total_stake)`
    /// selects the member whose cumulative-stake bucket contains it, so a member with
    /// stake `S` leads with probability `S / total_stake`. `blake3_id(&round.0)` and the
    /// borsh-ordered `members` are identical on every node ⇒ every node picks the SAME
    /// leader (a mismatch would fork). All-zero stake degenerates to round-robin.
    pub fn leader_weighted(&self, round: Round) -> NodeId {
        let total: u128 = self.members.iter().map(|m| m.stake as u128).sum();
        if total == 0 {
            return self.leader(round);
        }
        let h = blake3_id(&round.0);
        let point = u128::from_le_bytes(h.0[..16].try_into().expect("32-byte hash")) % total;
        let mut cum: u128 = 0;
        for m in &self.members {
            cum += m.stake as u128;
            if point < cum {
                return m.node_id;
            }
        }
        // Unreachable when total > 0 (point < total <= final cum); last member as a guard.
        self.members[self.members.len() - 1].node_id
    }

    /// leader for `round` under `mode`. `RoundRobin` is byte-identical to
    /// [`leader`](Self::leader) (the opt-out); `StakeWeighted` uses
    /// [`leader_weighted`](Self::leader_weighted). The `mode` is a shared chain constant
    /// passed in by the caller — it is never stored on the wire `ValidatorSet`.
    pub fn leader_with_mode(&self, round: Round, mode: LeaderSchedule) -> NodeId {
        match mode.base() {
            LeaderSchedule::StakeWeighted => self.leader_weighted(round),
            _ => self.leader(round),
        }
    }

    /// Leader for `round` given the **liveness QC** — the QC carried by the
    /// parent of the block proposed at `round` (blockchain#95). For the base
    /// schedules, and when there is no liveness QC (`None`, or the genesis QC), this
    /// is [`leader_with_mode`](Self::leader_with_mode).
    ///
    /// For the skip-absent schedules, let `E` be the members of this set that
    /// signed the liveness QC. An empty `E` (genesis, an epoch start, a QC from
    /// another set) keeps the base schedule. Otherwise:
    /// - round robin: the base leader leads if it is in `E`, else the first
    ///   `members[(round + k) mod n]` in `E`, so only the turns of absent members
    ///   move;
    /// - stake weighted: the base leader leads if it is in `E`, else the same
    ///   `blake3(round)` point is mapped over the cumulative stakes of `E`.
    ///
    /// Deterministic: the inputs are the round, this set and a QC fixed by the
    /// proposed block's ancestry, so every node verifying the same proposal
    /// computes the same leader.
    pub fn leader_after(
        &self,
        round: Round,
        mode: LeaderSchedule,
        liveness: Option<&QuorumCert>,
    ) -> NodeId {
        let base = self.leader_with_mode(round, mode);
        let Some(qc) = liveness.filter(|q| mode.skips_absent() && q.round.0 != 0) else {
            return base;
        };
        let signers = qc.agg.signers();
        let eligible = |id: &NodeId| signers.contains(id);
        if !self.members.iter().any(|m| eligible(&m.node_id)) || eligible(&base) {
            return base;
        }
        match mode.base() {
            LeaderSchedule::StakeWeighted => {
                let total: u128 = self
                    .members
                    .iter()
                    .filter(|m| eligible(&m.node_id))
                    .map(|m| m.stake as u128)
                    .sum();
                if total > 0 {
                    let h = blake3_id(&round.0);
                    let point =
                        u128::from_le_bytes(h.0[..16].try_into().expect("32-byte hash")) % total;
                    let mut cum: u128 = 0;
                    for m in self.members.iter().filter(|m| eligible(&m.node_id)) {
                        cum += m.stake as u128;
                        if point < cum {
                            return m.node_id;
                        }
                    }
                }
                self.skip_ahead(round, &eligible)
            }
            _ => self.skip_ahead(round, &eligible),
        }
    }

    fn skip_ahead(&self, round: Round, eligible: &impl Fn(&NodeId) -> bool) -> NodeId {
        let n = self.members.len();
        let start = (round.0 % n as u64) as usize;
        (0..n)
            .map(|k| self.members[(start + k) % n].node_id)
            .find(|id| eligible(id))
            .unwrap_or_else(|| self.leader(round))
    }

    /// [`upcoming_leaders`](Self::upcoming_leaders) under `mode`.
    pub fn upcoming_leaders_with_mode(
        &self,
        from: Round,
        count: usize,
        mode: LeaderSchedule,
    ) -> Vec<NodeId> {
        (0..count)
            .map(|k| self.leader_with_mode(Round(from.0 + k as u64), mode))
            .collect()
    }

    /// Return the set with `id` removed (other members' columns unchanged).
    pub fn without(&self, id: &NodeId) -> ValidatorSet {
        ValidatorSet::new_members(
            self.members
                .iter()
                .filter(|m| &m.node_id != id)
                .cloned()
                .collect(),
        )
    }

    /// Stake slashing: Return a new set with `offender`'s stake reduced by `slash_bps`
    /// basis-points (10_000 bps = 100%). All other members are copied unchanged.
    ///
    /// Integer arithmetic only (no floating point):
    /// `new_stake = stake * (10_000 - slash_bps) / 10_000`
    ///
    /// Example: `slash_bps = 5_000` → 50% slash (stake halved).
    ///
    /// Panics if `slash_bps > 10_000` (would underflow stake) or if `offender`
    /// is not a member of this set.
    pub fn with_slashed_stake(&self, offender: &NodeId, slash_bps: u64) -> ValidatorSet {
        assert!(
            slash_bps <= 10_000,
            "slash_bps={slash_bps} > 10_000 — would underflow stake"
        );
        assert!(
            self.contains(offender),
            "offender {offender:?} is not in this ValidatorSet"
        );
        ValidatorSet::new_members(
            self.members
                .iter()
                .map(|m| {
                    if &m.node_id == offender {
                        let mut m2 = m.clone();
                        // Integer slash: new = stake * (10_000 - bps) / 10_000.
                        // Use u128 intermediate to avoid overflow for large stakes
                        // (e.g. wei-denominated stake where stake ≈ 2e15 would
                        // overflow u64 when multiplied by up-to-10_000).
                        // The result is always ≤ original stake, so the cast back
                        // to u64 is lossless.
                        m2.stake =
                            (m2.stake as u128 * (10_000 - slash_bps as u128) / 10_000) as u64;
                        m2
                    } else {
                        m.clone()
                    }
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::NodeId;
    fn vs(n: u8) -> ValidatorSet {
        let m = (0..n)
            .map(|i| Member::secp_only(NodeId([i; 20]), vec![i], 1u64))
            .collect();
        ValidatorSet::new_members(m)
    }
    /// build a set whose members have the given stakes (member i = NodeId([i;20])).
    fn vs_staked(stakes: &[u64]) -> ValidatorSet {
        let m = stakes
            .iter()
            .enumerate()
            .map(|(i, &s)| Member::secp_only(NodeId([i as u8; 20]), vec![i as u8], s))
            .collect();
        ValidatorSet::new_members(m)
    }

    #[test]
    fn leader_weighted_is_deterministic() {
        // Two identical sets must pick the SAME weighted leader every round (all nodes
        // agree — a mismatch would fork).
        let a = vs_staked(&[3, 1, 4, 1, 5]);
        let b = vs_staked(&[3, 1, 4, 1, 5]);
        for r in 0..50u64 {
            assert_eq!(a.leader_weighted(Round(r)), b.leader_weighted(Round(r)));
        }
    }

    #[test]
    fn leader_with_mode_roundrobin_equals_leader() {
        // The opt-out (RoundRobin) is byte-identical to the existing round-robin leader().
        let v = vs_staked(&[7, 2, 1]);
        for r in 0..20u64 {
            assert_eq!(
                v.leader_with_mode(Round(r), LeaderSchedule::RoundRobin),
                v.leader(Round(r))
            );
        }
    }

    #[test]
    fn leader_weighted_is_stake_proportional() {
        // {A:1, B:9}: B (90% of stake) must lead ~90% of rounds — round-robin would give
        // ~50/50. This positive control fails unless the weighting is real.
        let v = vs_staked(&[1, 9]);
        let b = NodeId([1u8; 20]); // member index 1 = B (stake 9)
        let n = 10_000u64;
        let b_count = (0..n).filter(|&r| v.leader_weighted(Round(r)) == b).count();
        assert!(
            (8500..=9500).contains(&b_count),
            "B (stake 9/10) led {b_count}/{n}, expected ~9000 (round-robin would be ~5000)"
        );
    }

    #[test]
    fn sorted_and_quorum() {
        let v = vs(4); // n=4, f=1 -> quorum stake = 2f+1 = 3
        assert_eq!(v.quorum(), 3);
        assert_eq!(v.total_stake(), 4);
    }
    #[test]
    fn quorum_no_overflow_at_wei_scale() {
        // Overflow regression: 10 validators each staking 1e18 wei → total = 1e19, which
        // exceeds u64::MAX/2 (~9.2e18). In u64, `2 * total` overflows (panics in debug,
        // wraps in release) and quorum() is wrong; computed in u128 it is the correct
        // floor(2e19/3)+1. This positive control fails against u64 arithmetic.
        const WEI: u64 = 1_000_000_000_000_000_000; // 1e18
        let m = (0..10u8)
            .map(|i| Member::secp_only(NodeId([i; 20]), vec![i], WEI))
            .collect();
        let v = ValidatorSet::new_members(m);
        assert_eq!(v.total_stake(), 10 * WEI); // 1e19 still fits u64
        let total = 10u128 * WEI as u128;
        assert_eq!(v.quorum() as u128, 2 * total / 3 + 1);
    }
    #[test]
    fn leader_round_robin() {
        let v = vs(4);
        assert_eq!(v.leader(crate::Round(0)), v.members()[0].node_id);
        assert_eq!(v.leader(crate::Round(5)), v.members()[1].node_id);
    }
    #[test]
    fn contains_membership() {
        let v = vs(4);
        assert!(v.contains(&v.members()[0].node_id));
        assert!(!v.contains(&NodeId([0xff; 20])));
    }
    #[test]
    fn upcoming_leaders_dedup_len() {
        let v = vs(4);
        let ups = v.upcoming_leaders(crate::Round(0), 3);
        assert_eq!(ups.len(), 3);
        assert_eq!(
            ups,
            vec![
                v.leader(crate::Round(0)),
                v.leader(crate::Round(1)),
                v.leader(crate::Round(2))
            ]
        );
    }
    #[test]
    fn bls_columns_empty_for_secp_only() {
        let v = vs(2);
        assert!(v.bls_pubkey_of(&v.members()[0].node_id).is_none());
        assert!(v.bls_pop_of(&v.members()[0].node_id).is_none());
    }
    #[test]
    fn with_slashed_stake_reduces_offender_only() {
        // 50% slash of member 0, member 1 unchanged.
        let v = vs(2);
        let offender = v.members()[0].node_id;
        let slashed = v.with_slashed_stake(&offender, 5_000);
        // offender: 1 * (10_000 - 5_000) / 10_000 = 0 (integer truncation at stake=1).
        // Use stake=100 for a clearer test.
        let m2 = vec![
            Member::secp_only(NodeId([0; 20]), vec![0], 100u64),
            Member::secp_only(NodeId([1; 20]), vec![1], 100u64),
        ];
        let v2 = ValidatorSet::new_members(m2);
        let slashed2 = v2.with_slashed_stake(&NodeId([0; 20]), 5_000);
        assert_eq!(slashed2.stake_of(&NodeId([0; 20])), Some(50)); // 50% slash
        assert_eq!(slashed2.stake_of(&NodeId([1; 20])), Some(100)); // unchanged
                                                                    // Offender still in set.
        assert!(slashed2.contains(&NodeId([0; 20])));
        assert!(slashed2.contains(&NodeId([1; 20])));
        // Total stake changed.
        assert_eq!(slashed2.total_stake(), 150);
        // Slashed is different from the original.
        assert_ne!(
            v2.stake_of(&NodeId([0; 20])),
            slashed2.stake_of(&NodeId([0; 20]))
        );
        // Unchanged member's stake.
        assert_eq!(
            v2.stake_of(&NodeId([1; 20])),
            slashed2.stake_of(&NodeId([1; 20]))
        );
        let _ = slashed; // suppress unused warning for the original test
    }

    #[test]
    fn with_slashed_stake_100pct_zeros_stake() {
        let m = vec![Member::secp_only(NodeId([5; 20]), vec![5], 1000u64)];
        let v = ValidatorSet::new_members(m);
        let slashed = v.with_slashed_stake(&NodeId([5; 20]), 10_000); // 100% slash
        assert_eq!(slashed.stake_of(&NodeId([5; 20])), Some(0));
        assert!(slashed.contains(&NodeId([5; 20]))); // still a member
    }

    #[test]
    fn with_slashed_stake_bps_10_pct() {
        let m = vec![Member::secp_only(NodeId([7; 20]), vec![7], 1000u64)];
        let v = ValidatorSet::new_members(m);
        let slashed = v.with_slashed_stake(&NodeId([7; 20]), 1_000); // 10% slash
        assert_eq!(slashed.stake_of(&NodeId([7; 20])), Some(900)); // 1000 * 9000/10000
    }

    /// Overflow regression: large stake (wei-scale, ~2e15) must not overflow u64
    /// when multiplied by up-to-10_000 inside `with_slashed_stake`.
    #[test]
    fn with_slashed_stake_large_stake_no_overflow() {
        // 2e15 is a realistic wei-denominated stake; u64::MAX/2 is the extreme edge.
        for &big_stake in &[2_000_000_000_000_000u64, u64::MAX / 2] {
            let m = vec![
                Member::secp_only(NodeId([0xab; 20]), vec![0xab], big_stake),
                Member::secp_only(NodeId([0xcd; 20]), vec![0xcd], 1_000u64),
            ];
            let v = ValidatorSet::new_members(m);
            let offender = NodeId([0xab; 20]);

            // 50% slash: result must be exactly big_stake / 2 (no panic, no overflow).
            let slashed = v.with_slashed_stake(&offender, 5_000);
            let expected = (big_stake as u128 * 5_000 / 10_000) as u64;
            assert_eq!(
                slashed.stake_of(&offender),
                Some(expected),
                "50% slash of {big_stake} should be {expected}"
            );
            // Result must be <= original stake (slash only reduces).
            assert!(slashed.stake_of(&offender).unwrap() <= big_stake);
            // Non-offender unchanged.
            assert_eq!(slashed.stake_of(&NodeId([0xcd; 20])), Some(1_000));
        }
    }

    #[test]
    fn with_slashed_stake_u64_max_no_overflow() {
        // u64::MAX is the most extreme value — any slash_bps > 0 reduces it.
        let m = vec![Member::secp_only(NodeId([0xff; 20]), vec![0xff], u64::MAX)];
        let v = ValidatorSet::new_members(m);
        let offender = NodeId([0xff; 20]);

        // 1 bps slash: result = u64::MAX * 9999 / 10000 — would overflow u64 * u64.
        let slashed = v.with_slashed_stake(&offender, 1);
        let expected = (u64::MAX as u128 * 9_999 / 10_000) as u64;
        assert_eq!(slashed.stake_of(&offender), Some(expected));
        // The previous line already asserts the exact expected value; no need to
        // additionally check <= u64::MAX (always true for a u64 — overflow guard).
        assert!(slashed.stake_of(&offender).is_some());
    }

    #[test]
    fn bls_columns_roundtrip() {
        let m = vec![Member::new(
            NodeId([1; 20]),
            vec![0xaa],
            vec![0xbb; 48],
            vec![0xcc; 96],
            1,
        )];
        let v = ValidatorSet::new_members(m);
        let bytes = borsh::to_vec(&v).unwrap();
        let v2: ValidatorSet = borsh::from_slice(&bytes).unwrap();
        assert_eq!(v, v2);
        assert_eq!(
            v.bls_pubkey_of(&NodeId([1; 20])),
            Some([0xbb; 48].as_slice())
        );
        assert_eq!(v.bls_pop_of(&NodeId([1; 20])), Some([0xcc; 96].as_slice()));
    }

    /// A liveness QC at `round` signed by exactly `signers` (signatures are not
    /// checked by `leader_after`; only the named signer set matters).
    fn liveness(round: u64, signers: &[u8]) -> QuorumCert {
        QuorumCert {
            block_id: blake3_id(&round),
            round: Round(round),
            agg: crate::cert::AggSig::Secp(
                signers.iter().map(|&i| (NodeId([i; 20]), vec![])).collect(),
            ),
        }
    }

    #[test]
    fn round_robin_skip_absent_moves_only_the_absent_members_turns() {
        let v = vs(4);
        let mode = LeaderSchedule::RoundRobinSkipAbsent;
        for absent in 0..4u8 {
            let present: Vec<u8> = (0..4).filter(|&i| i != absent).collect();
            let qc = liveness(7, &present);
            for r in 1..40u64 {
                let base = v.leader(Round(r));
                let got = v.leader_after(Round(r), mode, Some(&qc));
                if base == NodeId([absent; 20]) {
                    // the next member in schedule order takes the turn
                    assert_eq!(got, v.leader(Round(r + 1)), "round {r}, absent {absent}");
                } else {
                    assert_eq!(got, base, "a present base leader keeps its round {r}");
                }
            }
        }
    }

    #[test]
    fn round_robin_skip_absent_skips_several_absent_members_in_order() {
        let v = vs(7);
        // members 2 and 3 absent: round 2 and round 3 both go to member 4
        let qc = liveness(9, &[0, 1, 4, 5, 6]);
        let mode = LeaderSchedule::RoundRobinSkipAbsent;
        assert_eq!(v.leader_after(Round(2), mode, Some(&qc)), NodeId([4; 20]));
        assert_eq!(v.leader_after(Round(3), mode, Some(&qc)), NodeId([4; 20]));
        assert_eq!(v.leader_after(Round(4), mode, Some(&qc)), NodeId([4; 20]));
        assert_eq!(v.leader_after(Round(1), mode, Some(&qc)), NodeId([1; 20]));
    }

    #[test]
    fn skip_absent_without_a_usable_liveness_qc_keeps_the_base_schedule() {
        let v = vs_staked(&[1, 2, 3, 4]);
        let unknown_signers = QuorumCert {
            agg: crate::cert::AggSig::Secp(vec![(NodeId([99; 20]), vec![])]),
            ..liveness(5, &[])
        };
        for (mode, base) in [
            (
                LeaderSchedule::RoundRobinSkipAbsent,
                LeaderSchedule::RoundRobin,
            ),
            (
                LeaderSchedule::StakeWeightedSkipAbsent,
                LeaderSchedule::StakeWeighted,
            ),
        ] {
            for r in 0..30u64 {
                let want = v.leader_with_mode(Round(r), base);
                assert_eq!(v.leader_with_mode(Round(r), mode), want);
                assert_eq!(v.leader_after(Round(r), mode, None), want, "no liveness QC");
                assert_eq!(
                    v.leader_after(Round(r), mode, Some(&QuorumCert::genesis())),
                    want,
                    "the genesis QC names no signers"
                );
                assert_eq!(
                    v.leader_after(Round(r), mode, Some(&unknown_signers)),
                    want,
                    "signers from another set leave E empty"
                );
            }
        }
    }

    #[test]
    fn base_schedules_ignore_the_liveness_qc() {
        let v = vs_staked(&[1, 2, 3, 4]);
        let qc = liveness(3, &[0]);
        for r in 0..30u64 {
            assert_eq!(
                v.leader_after(Round(r), LeaderSchedule::RoundRobin, Some(&qc)),
                v.leader(Round(r))
            );
            assert_eq!(
                v.leader_after(Round(r), LeaderSchedule::StakeWeighted, Some(&qc)),
                v.leader_weighted(Round(r))
            );
        }
    }

    #[test]
    fn stake_weighted_skip_absent_never_picks_an_absent_member_and_keeps_present_ones() {
        let v = vs_staked(&[5, 1, 3, 2]);
        let mode = LeaderSchedule::StakeWeightedSkipAbsent;
        let qc = liveness(11, &[1, 2, 3]); // the heaviest member 0 is absent
        let mut moved = 0;
        let mut counts = [0u32; 4];
        for r in 0..600u64 {
            let base = v.leader_weighted(Round(r));
            let got = v.leader_after(Round(r), mode, Some(&qc));
            assert_ne!(got, NodeId([0; 20]), "round {r} went to the absent member");
            if base != NodeId([0; 20]) {
                assert_eq!(got, base, "a present base leader keeps round {r}");
            } else {
                moved += 1;
            }
            counts[got.0[0] as usize] += 1;
        }
        assert!(moved > 0, "the absent member led some base rounds");
        // remapped rounds follow the present stakes 1:3:2, so member 2 leads most
        assert!(counts[2] > counts[3] && counts[3] > counts[1], "{counts:?}");
    }
}
