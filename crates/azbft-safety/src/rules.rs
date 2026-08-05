use azbft_types::{Block, Hash, NodeId, Round, Vote};

/// The two safety rules of 2-chain HotStuff/Jolteon. No IO. Only azbft-types.
#[derive(Clone, Debug)]
pub struct SafetyRules {
    pub last_voted_round: Round,
    pub preferred_round: Round,
}

impl Default for SafetyRules {
    /// Both rounds start at genesis (Round(0)). `azbft-types::Round` does not derive
    /// `Default`, so this is written by hand rather than derived.
    fn default() -> Self {
        Self {
            last_voted_round: Round(0),
            preferred_round: Round(0),
        }
    }
}

impl SafetyRules {
    /// Rule 1 (voting): vote iff round-monotone AND extends at least the locked round.
    pub fn make_vote(&mut self, b: &Block, voter: NodeId) -> Option<Vote> {
        if b.round <= self.last_voted_round {
            return None;
        } // ① monotone
        if b.parent_qc.round < self.preferred_round {
            return None;
        } // ② lock
        self.last_voted_round = b.round;
        Some(Vote {
            epoch: b.epoch,
            block_id: b.id(),
            round: b.round,
            voter,
        })
    }

    /// A timeout is a promise not to vote in that round afterwards. Advancing
    /// the same durable watermark used by votes prevents one validator from
    /// contributing to both a timeout certificate and a conflicting QC.
    pub fn mark_timeout(&mut self, round: Round) {
        self.last_voted_round = self.last_voted_round.max(round);
    }

    /// Raise the lock to the grandparent round (used by Rule 2 and tests).
    pub fn update_on_qc_parent_round(&mut self, parent_qc_round: Round) {
        if parent_qc_round > self.preferred_round {
            self.preferred_round = parent_qc_round;
        }
    }

    /// 2-chain commit rule: QC(b) with b.parent in the immediately-preceding round commits b's parent.
    pub fn commit_target(&self, b: &Block) -> Option<Hash> {
        if b.parent_qc.round.0 + 1 == b.round.0 {
            Some(b.parent_qc.block_id)
        } else {
            None
        }
    }

    /// Rule 2: on QC(b) — raise lock to parent round, return commit target (if any).
    pub fn update_on_qc(&mut self, b: &Block) -> Option<Hash> {
        self.update_on_qc_parent_round(b.parent_qc.round);
        self.commit_target(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azbft_types::*;
    fn block(round: u64, parent_round: u64) -> Block {
        Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 1,
            timestamp_ms: 1,
            epoch: 0,
            round: Round(round),
            parent_qc: QuorumCert {
                block_id: Hash([round as u8; 32]),
                round: Round(parent_round),
                agg: AggSig::default(),
            },
            payload_hash: Hash::default(),
            author: NodeId::default(),
            reconfig: None,
        }
    }
    fn v() -> NodeId {
        NodeId([7u8; 20])
    }
    #[test]
    fn votes_then_monotone_blocks() {
        let mut s = SafetyRules::default();
        assert!(s.make_vote(&block(1, 0), v()).is_some());
        assert!(
            s.make_vote(&block(1, 0), v()).is_none(),
            "no double vote same round"
        );
        assert!(
            s.make_vote(&block(0, 0), v()).is_none(),
            "no vote lower round"
        );
        assert!(s.make_vote(&block(2, 1), v()).is_some());
    }
    #[test]
    fn vote_carries_voter_and_block_id() {
        let mut s = SafetyRules::default();
        let b = block(1, 0);
        let vote = s.make_vote(&b, v()).unwrap();
        assert_eq!(vote.voter, v());
        assert_eq!(vote.block_id, b.id());
        assert_eq!(vote.round, Round(1));
    }
    #[test]
    fn lock_rule_blocks_old_extension() {
        let mut s = SafetyRules::default();
        s.update_on_qc_parent_round(Round(5)); // raise preferred_round to 5
        assert!(
            s.make_vote(&block(7, 4), v()).is_none(),
            "parent_qc.round 4 < preferred 5 -> no vote"
        );
        assert!(
            s.make_vote(&block(7, 5), v()).is_some(),
            "parent_qc.round 5 >= preferred 5 -> vote"
        );
    }
    #[test]
    fn two_chain_commit_rule() {
        let s = SafetyRules::default();
        let consecutive = block(6, 5); // r=6, parent round=5 (consecutive)
        assert_eq!(
            s.commit_target(&consecutive),
            Some(consecutive.parent_qc.block_id)
        );
        let gap = block(6, 4); // r=6, parent round=4 (gap) -> no commit
        assert_eq!(s.commit_target(&gap), None);
    }
    #[test]
    fn update_on_qc_raises_lock_and_returns_commit() {
        let mut s = SafetyRules::default();
        let b = block(6, 5);
        let committed = s.update_on_qc(&b);
        assert_eq!(s.preferred_round, Round(5)); // lock raised to parent round
        assert_eq!(committed, Some(b.parent_qc.block_id));
    }

    proptest::proptest! {
        #[test]
        fn last_voted_round_never_decreases(rounds in proptest::collection::vec(0u64..50, 1..40)) {
            let mut s = SafetyRules::default();
            for r in rounds {
                let before = s.last_voted_round;
                let _ = s.make_vote(&block(r, r.saturating_sub(1)), v());
                proptest::prop_assert!(s.last_voted_round >= before);
            }
        }
    }

    proptest::proptest! {
        #[test]
        fn preferred_round_monotone_and_commit_only_consecutive(
            pairs in proptest::collection::vec((1u64..50, 0u64..50), 1..40)
        ) {
            let mut s = SafetyRules::default();
            for (r, pr) in pairs {
                if pr >= r { continue; }
                let before = s.preferred_round;
                let b = block(r, pr);
                let committed = s.update_on_qc(&b);
                proptest::prop_assert!(s.preferred_round >= before);        // lock monotone
                proptest::prop_assert_eq!(committed.is_some(), pr + 1 == r); // commit only consecutive
            }
        }
    }
}
