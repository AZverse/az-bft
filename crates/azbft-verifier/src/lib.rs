#![forbid(unsafe_code)]

//! Offline verification for deterministic AZBFT finality transcripts.

use azbft_crypto::aggregator::{verify_agg, verify_vset_pops};
use azbft_crypto::domain::Domain;
use azbft_devnet::{
    next_application_commitment, payload_for_round, DevnetTranscript, FinalizedRecord,
    TRANSCRIPT_VERSION,
};
use azbft_types::{blake3_id, vote_digest, Block, Hash, QuorumCert, ValidatorSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationSummary {
    pub finalized_blocks: u64,
    pub first_height: u64,
    pub last_height: u64,
    pub last_block_id: Hash,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("unsupported transcript version {0}")]
    UnsupportedVersion(u16),
    #[error("validator set is empty or contains invalid proof-of-possession data")]
    InvalidValidatorSet,
    #[error("transcript contains no finalized blocks")]
    EmptyTranscript,
    #[error("record {index} does not match its commit certificate")]
    CertificateBlockMismatch { index: usize },
    #[error("record {index} has an invalid payload commitment")]
    PayloadMismatch { index: usize },
    #[error("record {index} has an invalid application commitment")]
    ApplicationCommitmentMismatch { index: usize },
    #[error("record {index} does not extend the preceding finalized block")]
    ChainLinkMismatch { index: usize },
    #[error("record {index} contains an invalid linked commit proof")]
    InvalidCommitProof { index: usize },
    #[error("transcript decoding failed: {0}")]
    Decode(String),
}

pub fn encode_transcript(transcript: &DevnetTranscript) -> Result<Vec<u8>, VerifyError> {
    borsh::to_vec(transcript).map_err(|error| VerifyError::Decode(error.to_string()))
}

pub fn decode_transcript(bytes: &[u8]) -> Result<DevnetTranscript, VerifyError> {
    borsh::from_slice(bytes).map_err(|error| VerifyError::Decode(error.to_string()))
}

/// Verify one strict adjacent-round two-chain commit.
pub fn verify_commit(
    block: &Block,
    child: &Block,
    commit_qc: &QuorumCert,
    validator_set: &ValidatorSet,
) -> Result<(), VerifyError> {
    verify_linked_commit(block, child, commit_qc, validator_set)?;
    if child.round.0 != block.round.0.saturating_add(1) {
        return Err(VerifyError::InvalidCommitProof { index: 0 });
    }
    Ok(())
}

pub fn verify_transcript(
    transcript: &DevnetTranscript,
) -> Result<VerificationSummary, VerifyError> {
    if transcript.version != TRANSCRIPT_VERSION {
        return Err(VerifyError::UnsupportedVersion(transcript.version));
    }
    if transcript.validator_set.is_empty() || !verify_vset_pops(&transcript.validator_set) {
        return Err(VerifyError::InvalidValidatorSet);
    }
    if transcript.finalized.is_empty() {
        return Err(VerifyError::EmptyTranscript);
    }

    let mut application = Hash::default();
    let mut previous: Option<&FinalizedRecord> = None;

    for (index, record) in transcript.finalized.iter().enumerate() {
        if record.block != record.certificate.block {
            return Err(VerifyError::CertificateBlockMismatch { index });
        }
        let payload = payload_for_round(record.block.round);
        if record.block.payload_hash != blake3_id(&payload) {
            return Err(VerifyError::PayloadMismatch { index });
        }
        application = next_application_commitment(application, record.block.round);
        if record.application_commitment != application {
            return Err(VerifyError::ApplicationCommitmentMismatch { index });
        }

        if let Some(parent) = previous {
            if record.block.height != parent.block.height.saturating_add(1)
                || record.block.timestamp_ms <= parent.block.timestamp_ms
                || record.block.epoch != parent.block.epoch
                || record.block.parent_qc.block_id != parent.block.id()
                || record.block.parent_qc.round != parent.block.round
                || verify_agg(
                    &record.block.parent_qc.agg,
                    &vote_digest(&parent.block.id(), parent.block.round),
                    Domain::Vote,
                    &transcript.validator_set,
                )
                .is_err()
            {
                return Err(VerifyError::ChainLinkMismatch { index });
            }
        } else if record.block.height != 1 {
            return Err(VerifyError::ChainLinkMismatch { index });
        }

        let proof_result = if record.two_chain {
            verify_commit(
                &record.block,
                &record.certificate.child,
                &record.certificate.commit_qc,
                &transcript.validator_set,
            )
        } else {
            verify_linked_commit(
                &record.block,
                &record.certificate.child,
                &record.certificate.commit_qc,
                &transcript.validator_set,
            )
        };
        if proof_result.is_err() {
            return Err(VerifyError::InvalidCommitProof { index });
        }
        previous = Some(record);
    }

    let first = &transcript.finalized[0].block;
    let last = &transcript.finalized[transcript.finalized.len() - 1].block;
    Ok(VerificationSummary {
        finalized_blocks: transcript.finalized.len() as u64,
        first_height: first.height,
        last_height: last.height,
        last_block_id: last.id(),
    })
}

fn verify_linked_commit(
    block: &Block,
    child: &Block,
    commit_qc: &QuorumCert,
    validator_set: &ValidatorSet,
) -> Result<(), VerifyError> {
    if child.height != block.height.saturating_add(1)
        || child.epoch != block.epoch
        || commit_qc.block_id != child.id()
        || commit_qc.round != child.round
        || child.parent_qc.block_id != block.id()
        || child.parent_qc.round != block.round
    {
        return Err(VerifyError::InvalidCommitProof { index: 0 });
    }
    if verify_agg(
        &commit_qc.agg,
        &vote_digest(&child.id(), child.round),
        Domain::Vote,
        validator_set,
    )
    .is_err()
        || verify_agg(
            &child.parent_qc.agg,
            &vote_digest(&block.id(), block.round),
            Domain::Vote,
            validator_set,
        )
        .is_err()
    {
        return Err(VerifyError::InvalidCommitProof { index: 0 });
    }
    Ok(())
}
