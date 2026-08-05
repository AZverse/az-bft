#![forbid(unsafe_code)]

//! Deterministic, in-memory harness for running the real AZBFT consensus core.

mod adversary;
mod clock;
mod conformance;
mod driver;
mod invariant;
mod mock_executor;
mod net;
mod transcript;
mod world;

pub use adversary::DevnetFault;
pub use conformance::{build_fixture_set, FixtureArtifact, FixtureError};
pub use transcript::{DevnetTranscript, FinalizedRecord, TRANSCRIPT_VERSION};

/// Canonical mock payload for a logical consensus round.
pub fn payload_for_round(round: azbft_types::Round) -> Vec<u8> {
    round.0.to_le_bytes().to_vec()
}

/// Advance the deterministic application commitment by one round payload.
pub fn next_application_commitment(
    previous: azbft_types::Hash,
    round: azbft_types::Round,
) -> azbft_types::Hash {
    let mut input = previous.0.to_vec();
    input.extend_from_slice(&payload_for_round(round));
    azbft_types::blake3_id(&input)
}

/// Inputs for a bounded deterministic devnet run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevnetConfig {
    pub validators: usize,
    pub blocks: u64,
    pub seed: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DevnetError {
    #[error("invalid devnet configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("validator index {0} is outside the configured validator set")]
    InvalidValidatorIndex(usize),
    #[error(
        "devnet did not finalize the requested {requested} blocks; finalized {finalized} after {processed_events} events"
    )]
    NoFinality {
        requested: u64,
        finalized: u64,
        processed_events: u64,
    },
    #[error("validators produced conflicting finalized blocks")]
    AgreementViolation,
}

pub fn run_devnet(config: DevnetConfig) -> Result<DevnetTranscript, DevnetError> {
    run_devnet_with_fault(config, DevnetFault::None)
}

pub fn run_devnet_with_fault(
    config: DevnetConfig,
    fault: DevnetFault,
) -> Result<DevnetTranscript, DevnetError> {
    world::World::new(config, fault)?.run()
}
