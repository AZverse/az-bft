use azbft_safety::SafetyRules;
use azbft_types::{AggSig, Block, Hash, NodeId, QuorumCert, Round, BLOCK_HEADER_VERSION_V2};

fn block(round: u64, parent_round: u64) -> Block {
    Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: round,
        timestamp_ms: round,
        epoch: 0,
        round: Round(round),
        parent_qc: QuorumCert {
            block_id: Hash([parent_round as u8; 32]),
            round: Round(parent_round),
            agg: AggSig::default(),
        },
        payload_hash: Hash([round as u8; 32]),
        author: NodeId([1; 20]),
        reconfig: None,
    }
}

#[test]
fn safety_rules_prevent_double_vote_and_locked_parent_regression() {
    let voter = NodeId([9; 20]);
    let mut rules = SafetyRules::default();

    assert!(rules.make_vote(&block(1, 0), voter).is_some());
    assert!(rules.make_vote(&block(1, 0), voter).is_none());

    rules.update_on_qc_parent_round(Round(5));
    assert!(rules.make_vote(&block(7, 4), voter).is_none());
    assert!(rules.make_vote(&block(7, 5), voter).is_some());
}
