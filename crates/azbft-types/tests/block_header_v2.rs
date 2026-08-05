use azbft_types::{
    validate_block_header_v2, Block, BlockHeaderV2Error, ChainAnchorV2, Hash, NodeId, QuorumCert,
    Round, BLOCK_HEADER_VERSION_V2,
};

fn block(height: u64, timestamp_ms: u64) -> Block {
    Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height,
        timestamp_ms,
        epoch: 3,
        round: Round(4),
        parent_qc: QuorumCert::genesis(),
        payload_hash: Hash([0x22; 32]),
        author: NodeId([0x33; 20]),
        reconfig: None,
    }
}

#[test]
fn signed_header_fields_are_borsh_and_block_id_material() {
    let original = block(7, 1_001);
    let bytes = borsh::to_vec(&original).unwrap();
    assert_eq!(
        &bytes[..26],
        &[
            0x02, 0x00, // header_version
            0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // height
            0xe9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp_ms
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // epoch
        ]
    );

    let mut changed = original.clone();
    changed.header_version += 1;
    assert_ne!(changed.id(), original.id());
    changed = original.clone();
    changed.height += 1;
    assert_ne!(changed.id(), original.id());
    changed = original.clone();
    changed.timestamp_ms += 1;
    assert_ne!(changed.id(), original.id());
}

#[test]
fn proposer_height_and_timestamp_are_derived_from_parent_anchor() {
    let parent = ChainAnchorV2 {
        height: 9,
        timestamp_ms: 100_000,
    };

    assert_eq!(
        parent.next_for_proposal(120_000).unwrap(),
        ChainAnchorV2 {
            height: 10,
            timestamp_ms: 120_000,
        }
    );
    assert_eq!(
        parent.next_for_proposal(200_000).unwrap(),
        ChainAnchorV2 {
            height: 10,
            timestamp_ms: 160_000,
        },
        "a proposer may advance at most sixty seconds from its parent"
    );
    assert_eq!(
        parent.next_for_proposal(94_999),
        Err(BlockHeaderV2Error::ClockBehind {
            proposed_timestamp_ms: 100_001,
            local_wall_clock_ms: 94_999,
        }),
        "a node more than five seconds behind the parent must abstain"
    );
}

#[test]
fn live_validation_enforces_future_drift_but_replay_does_not() {
    let parent = ChainAnchorV2 {
        height: 40,
        timestamp_ms: 1_000_000,
    };
    let candidate = block(41, 1_000_001);

    assert_eq!(
        validate_block_header_v2(&candidate, parent, Some(995_000)),
        Err(BlockHeaderV2Error::FutureTimestamp {
            timestamp_ms: 1_000_001,
            local_wall_clock_ms: 995_000,
        })
    );
    assert_eq!(
        validate_block_header_v2(&candidate, parent, None),
        Ok(()),
        "historical replay must not depend on the replaying host clock"
    );
}

#[test]
fn validation_rejects_wrong_version_height_and_time_step() {
    let parent = ChainAnchorV2 {
        height: 8,
        timestamp_ms: 10_000,
    };

    let mut candidate = block(9, 10_001);
    candidate.header_version = 1;
    assert!(matches!(
        validate_block_header_v2(&candidate, parent, None),
        Err(BlockHeaderV2Error::UnsupportedVersion { .. })
    ));

    candidate = block(10, 10_001);
    assert!(matches!(
        validate_block_header_v2(&candidate, parent, None),
        Err(BlockHeaderV2Error::HeightMismatch { .. })
    ));

    candidate = block(9, 70_001);
    assert!(matches!(
        validate_block_header_v2(&candidate, parent, None),
        Err(BlockHeaderV2Error::TimestampStepTooLarge { .. })
    ));
}
