use azbft_core::{
    command::Command,
    event::Event,
    state::{ConsensusCore, Signer},
};
use azbft_crypto::{domain::Domain, keypair::Keypair};
use azbft_types::{
    Block, ChainAnchorV2, ConsensusMessage, Hash, Member, NodeId, QuorumCert, Round, ValidatorSet,
    BLOCK_HEADER_VERSION_V2,
};

#[derive(Clone)]
struct TestSigner(Keypair);

impl Signer for TestSigner {
    fn sign(&self, domain: Domain, message: &[u8]) -> Vec<u8> {
        self.0.sign(domain, message)
    }

    fn node_id(&self) -> NodeId {
        self.0.node_id()
    }
}

fn setup(epoch: u64, anchor: ChainAnchorV2) -> (Keypair, ConsensusCore) {
    let keypair = Keypair::from_seed(912_044);
    let vset = ValidatorSet::new_members(vec![Member::new(
        keypair.node_id(),
        keypair.pubkey_bytes(),
        vec![],
        vec![],
        1,
    )]);
    let core = ConsensusCore::with_signer(
        epoch,
        vset,
        70,
        Box::new(TestSigner(keypair.clone())),
        vec![],
    )
    .with_chain_anchor(anchor);
    (keypair, core)
}

fn proposal_from(commands: Vec<Command>) -> azbft_types::Signed<azbft_types::Proposal> {
    commands
        .into_iter()
        .find_map(|command| match command {
            Command::Broadcast(ConsensusMessage::Proposal(proposal)) => Some(proposal),
            _ => None,
        })
        .expect("proposal broadcast")
}

fn payload_ready(core: &mut ConsensusCore, payload: Vec<u8>, now: u64) -> Vec<Command> {
    let parent = core.high_qc().clone();
    let Some(context) = core.proposal_build_context(Round(1), &parent, now) else {
        return Vec::new();
    };
    core.handle(Event::PayloadReady { context, payload }, now)
}

#[test]
fn first_block_of_a_new_epoch_extends_the_carried_anchor() {
    let anchor = ChainAnchorV2 {
        height: 80,
        timestamp_ms: 1_000_000,
    };
    let (_, mut core) = setup(7, anchor);

    let proposal = proposal_from(payload_ready(&mut core, vec![1, 2, 3], 1_020_000));
    assert_eq!(proposal.inner.block.header_version, BLOCK_HEADER_VERSION_V2);
    assert_eq!(proposal.inner.block.height, 81);
    assert_eq!(proposal.inner.block.timestamp_ms, 1_020_000);
    assert_eq!(proposal.inner.block.epoch, 7);
}

#[test]
fn proposer_abstains_when_its_wall_clock_is_too_far_behind() {
    let (_, mut core) = setup(
        2,
        ChainAnchorV2 {
            height: 5,
            timestamp_ms: 100_000,
        },
    );
    let commands = payload_ready(&mut core, vec![4], 94_999);
    assert!(!commands
        .iter()
        .any(|command| matches!(command, Command::Broadcast(ConsensusMessage::Proposal(_)))));
}

#[test]
fn live_proposal_future_drift_is_rejected_before_tree_insertion() {
    let anchor = ChainAnchorV2 {
        height: 5,
        timestamp_ms: 100_000,
    };
    let (_, mut leader) = setup(2, anchor);
    let proposal = proposal_from(payload_ready(&mut leader, vec![5], 100_000));
    let block_id = proposal.inner.block.id();

    let (_, mut receiver) = setup(2, anchor);
    let commands = receiver.handle(Event::Proposal(proposal), 94_999);
    assert!(commands.is_empty());
    assert!(!receiver.contains_block(&block_id));
}

#[test]
fn sync_replay_rejects_a_non_contiguous_height_without_partial_insertion() {
    let anchor = ChainAnchorV2 {
        height: 20,
        timestamp_ms: 200_000,
    };
    let (_, mut core) = setup(4, anchor);
    let invalid = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 22,
        timestamp_ms: 200_001,
        epoch: 4,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: Hash([7; 32]),
        author: core.me(),
        reconfig: None,
    };
    let invalid_id = invalid.id();
    let commands = core.handle(
        Event::SyncApply {
            blocks: vec![invalid],
            commit_qc: QuorumCert::genesis(),
        },
        0,
    );
    assert!(commands.is_empty());
    assert!(!core.contains_block(&invalid_id));
}
