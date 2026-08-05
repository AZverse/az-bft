use azbft_types::{
    Block, ConsensusMessage, Hash, NodeId, Proposal, QuorumCert, Round, Signed, Timeout, Vote,
    BLOCK_HEADER_VERSION_V2,
};

fn sample_block() -> Block {
    Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 0,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: Hash([7; 32]),
        author: NodeId([3; 20]),
        reconfig: None,
    }
}

#[test]
fn consensus_messages_round_trip_without_host_envelopes() {
    let messages = [
        ConsensusMessage::Proposal(Signed {
            inner: Proposal {
                block: sample_block(),
                last_round_tc: None,
            },
            sig: vec![1, 2, 3],
        }),
        ConsensusMessage::Vote(Signed {
            inner: Vote {
                epoch: 0,
                block_id: Hash([4; 32]),
                round: Round(1),
                voter: NodeId([5; 20]),
            },
            sig: vec![4, 5, 6],
        }),
        ConsensusMessage::Timeout(Signed {
            inner: Timeout {
                epoch: 0,
                round: Round(2),
                high_qc: QuorumCert::genesis(),
                sender: NodeId([6; 20]),
            },
            sig: vec![7, 8, 9],
        }),
    ];

    for message in messages {
        let encoded = borsh::to_vec(&message).expect("encode consensus message");
        let decoded: ConsensusMessage =
            borsh::from_slice(&encoded).expect("decode consensus message");
        assert_eq!(decoded, message);
    }
}
