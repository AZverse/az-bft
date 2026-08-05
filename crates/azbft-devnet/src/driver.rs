use crate::mock_executor::MockExecutor;
use crate::transcript::FinalizedRecord;
use azbft_core::{CommittedBlock, ConsensusCore, Event, Signer};
use azbft_crypto::bls::BlsSecretKey;
use azbft_crypto::domain::Domain;
use azbft_crypto::keypair::Keypair;
use azbft_types::{ConsensusMessage, NodeId};

pub(crate) struct DeterministicSigner {
    secp: Keypair,
    bls: BlsSecretKey,
}

impl DeterministicSigner {
    pub(crate) fn from_seed(seed: u64) -> Self {
        Self {
            secp: Keypair::from_seed(seed),
            bls: BlsSecretKey::from_seed(seed),
        }
    }
}

impl Signer for DeterministicSigner {
    fn sign(&self, domain: Domain, message: &[u8]) -> Vec<u8> {
        self.secp.sign(domain, message)
    }

    fn node_id(&self) -> NodeId {
        self.secp.node_id()
    }

    fn sign_bls_vote(&self, message: &[u8]) -> Vec<u8> {
        self.bls.sign(Domain::Vote, message).to_bytes().to_vec()
    }
}

pub(crate) struct NodeDriver {
    pub(crate) core: ConsensusCore,
    executor: MockExecutor,
    pub(crate) finalized: Vec<FinalizedRecord>,
    pub(crate) unavailable: bool,
}

impl NodeDriver {
    pub(crate) fn new(core: ConsensusCore, unavailable: bool) -> Self {
        Self {
            core,
            executor: MockExecutor::default(),
            finalized: Vec::new(),
            unavailable,
        }
    }

    pub(crate) fn build_payload(&self, round: azbft_types::Round) -> Vec<u8> {
        self.executor.build_payload(round)
    }

    pub(crate) fn on_commit(&mut self, committed: CommittedBlock) {
        let application_commitment = self.executor.execute_round(committed.block.round);
        self.finalized.push(FinalizedRecord {
            block: committed.block,
            certificate: committed.cert,
            two_chain: committed.two_chain,
            application_commitment,
        });
    }
}

pub(crate) fn message_to_event(message: ConsensusMessage) -> Event {
    match message {
        ConsensusMessage::Proposal(proposal) => Event::Proposal(proposal),
        ConsensusMessage::Vote(vote) => Event::Vote(vote),
        ConsensusMessage::Timeout(timeout) => Event::RemoteTimeout(timeout),
    }
}
