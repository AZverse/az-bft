use crate::{next_application_commitment, payload_for_round};
use azbft_types::{Hash, Round};

/// Minimal deterministic application used only by the in-memory devnet.
#[derive(Clone, Default)]
pub(crate) struct MockExecutor {
    state: Hash,
}

impl MockExecutor {
    pub(crate) fn build_payload(&self, round: Round) -> Vec<u8> {
        payload_for_round(round)
    }

    pub(crate) fn execute_round(&mut self, round: Round) -> Hash {
        self.state = next_application_commitment(self.state, round);
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::MockExecutor;
    use azbft_types::Round;

    #[test]
    fn state_commitments_chain_deterministically() {
        let mut left = MockExecutor::default();
        let mut right = MockExecutor::default();

        assert_eq!(left.execute_round(Round(1)), right.execute_round(Round(1)));
        assert_eq!(left.execute_round(Round(2)), right.execute_round(Round(2)));
    }
}
