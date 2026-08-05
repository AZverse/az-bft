use azbft_types::{
    Block, ChainAnchorV2, Checkpoint, CommitCert, Hash, NodeId, QuorumCert, Round, ValidatorSet,
    BLOCK_HEADER_VERSION_V2,
};

fn block(height: u64, timestamp_ms: u64, round: u64) -> Block {
    Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height,
        timestamp_ms,
        epoch: 2,
        round: Round(round),
        parent_qc: QuorumCert::genesis(),
        payload_hash: Hash([height as u8; 32]),
        author: NodeId::default(),
        reconfig: None,
    }
}

#[test]
fn checkpoint_carries_the_exact_cross_epoch_chain_anchor() {
    let anchor_block = block(77, 8_000_000, 9);
    let checkpoint = Checkpoint {
        height: 77,
        epoch: 3,
        validator_set: ValidatorSet::new(vec![]),
        commit_cert: CommitCert {
            block: anchor_block.clone(),
            child: block(78, 8_000_001, 10),
            commit_qc: QuorumCert::genesis(),
        },
        chain_anchor: ChainAnchorV2::from_block(&anchor_block),
    };

    let bytes = borsh::to_vec(&checkpoint).unwrap();
    let decoded: Checkpoint = borsh::from_slice(&bytes).unwrap();
    assert_eq!(
        decoded.chain_anchor,
        ChainAnchorV2 {
            height: 77,
            timestamp_ms: 8_000_000,
        }
    );
    assert_eq!(
        decoded.chain_anchor,
        ChainAnchorV2::from_block(&decoded.commit_cert.block)
    );
    assert_eq!(decoded.height, decoded.chain_anchor.height);
}
