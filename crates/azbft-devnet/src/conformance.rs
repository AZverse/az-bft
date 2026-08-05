//! Deterministic public conformance artifacts for the alpha protocol.

use crate::{run_devnet, DevnetConfig, DevnetError};
use azbft_core::{verify_equivocation_proof, verify_reconfig_authorized};
use azbft_crypto::aggregator::{verify_agg, SecpMultiSig, VoteAggregator};
use azbft_crypto::domain::Domain;
use azbft_crypto::keypair::Keypair;
use azbft_types::{
    timeout_digest, vote_digest, AggSig, EquivocationProof, Hash, OperatorSet, QuorumCert,
    Reconfig, Round, Signed, TimeoutCert, ValidatorSet, Vote,
};
use borsh::BorshSerialize;
use std::fmt::Write as _;

/// One generated file relative to `fixtures/v0.1.0-alpha/`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixtureArtifact {
    pub relative_path: &'static str,
    pub bytes: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    #[error(transparent)]
    Devnet(#[from] DevnetError),
    #[error("failed to encode {0}")]
    Encoding(&'static str),
    #[error("fixture invariant failed: {0}")]
    Invariant(&'static str),
}

fn encode<T: BorshSerialize>(name: &'static str, value: &T) -> Result<Vec<u8>, FixtureError> {
    borsh::to_vec(value).map_err(|_| FixtureError::Encoding(name))
}

fn aggregate(keypairs: &[Keypair], signers: usize, domain: Domain, message: &[u8]) -> AggSig {
    let signatures = keypairs
        .iter()
        .take(signers)
        .map(|keypair| (keypair.node_id(), keypair.sign(domain, message)))
        .collect::<Vec<_>>();
    SecpMultiSig::aggregate(&signatures)
}

fn signed_vote(keypair: &Keypair, block_id: Hash, round: Round) -> Signed<Vote> {
    let vote = Vote {
        epoch: 0,
        block_id,
        round,
        voter: keypair.node_id(),
    };
    let digest = vote_digest(&vote.block_id, vote.round);
    Signed {
        inner: vote,
        sig: keypair.sign(Domain::Vote, &digest.0),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("write to String");
    }
    output
}

/// Build all generated files committed under `fixtures/v0.1.0-alpha/`.
///
/// Test identities are derived from low-entropy seeds and must never be used for
/// production keys.
pub fn build_fixture_set() -> Result<Vec<FixtureArtifact>, FixtureError> {
    let valid_transcript = run_devnet(DevnetConfig {
        validators: 4,
        blocks: 5,
        seed: 42,
    })?;
    if valid_transcript.finalized.len() != 5 {
        return Err(FixtureError::Invariant(
            "valid transcript must finalize five blocks",
        ));
    }
    let valid_transcript_bytes = encode("valid transcript", &valid_transcript)?;

    let mut invalid_transcript = valid_transcript.clone();
    let corrupted_aggregate = &mut invalid_transcript
        .finalized
        .last_mut()
        .ok_or(FixtureError::Invariant("transcript is empty"))?
        .certificate
        .commit_qc
        .agg;
    match corrupted_aggregate {
        AggSig::Secp(signatures) => {
            let signature = signatures
                .first_mut()
                .and_then(|(_, bytes)| bytes.first_mut())
                .ok_or(FixtureError::Invariant("final QC has no signature bytes"))?;
            *signature ^= 1;
        }
        AggSig::Bls(aggregate) => aggregate.agg_sig[0] ^= 1,
    }
    let invalid_transcript_bytes = encode("invalid transcript", &invalid_transcript)?;

    let keypairs = (1..=4).map(Keypair::from_seed).collect::<Vec<_>>();
    let validator_set = ValidatorSet::new(
        keypairs
            .iter()
            .map(|keypair| (keypair.node_id(), keypair.pubkey_bytes(), 1))
            .collect(),
    );
    if validator_set.quorum() != 3 {
        return Err(FixtureError::Invariant(
            "four equal validators must require three signatures",
        ));
    }

    let certified_block = Hash([0x42; 32]);
    let qc_round = Round(7);
    let qc_digest = vote_digest(&certified_block, qc_round);
    let valid_qc = QuorumCert {
        block_id: certified_block,
        round: qc_round,
        agg: aggregate(&keypairs, 3, Domain::Vote, &qc_digest.0),
    };
    let invalid_qc = QuorumCert {
        block_id: certified_block,
        round: qc_round,
        agg: aggregate(&keypairs, 2, Domain::Vote, &qc_digest.0),
    };
    if verify_agg(
        &valid_qc.agg,
        &vote_digest(&valid_qc.block_id, valid_qc.round),
        Domain::Vote,
        &validator_set,
    )
    .is_err()
    {
        return Err(FixtureError::Invariant("valid QC did not verify"));
    }
    if verify_agg(
        &invalid_qc.agg,
        &vote_digest(&invalid_qc.block_id, invalid_qc.round),
        Domain::Vote,
        &validator_set,
    )
    .is_ok()
    {
        return Err(FixtureError::Invariant("below-quorum QC verified"));
    }

    let tc_round = Round(9);
    let tc_digest = timeout_digest(0, tc_round);
    let valid_tc = TimeoutCert {
        round: tc_round,
        agg: aggregate(&keypairs, 3, Domain::Timeout, &tc_digest.0),
        high_qc: valid_qc.clone(),
    };
    let invalid_tc = TimeoutCert {
        round: tc_round,
        agg: aggregate(&keypairs, 2, Domain::Timeout, &tc_digest.0),
        high_qc: valid_qc.clone(),
    };
    if verify_agg(
        &valid_tc.agg,
        &timeout_digest(0, valid_tc.round),
        Domain::Timeout,
        &validator_set,
    )
    .is_err()
    {
        return Err(FixtureError::Invariant("valid TC did not verify"));
    }
    if verify_agg(
        &invalid_tc.agg,
        &timeout_digest(0, invalid_tc.round),
        Domain::Timeout,
        &validator_set,
    )
    .is_ok()
    {
        return Err(FixtureError::Invariant("below-quorum TC verified"));
    }

    let vote = Vote {
        epoch: 0,
        block_id: certified_block,
        round: qc_round,
        voter: keypairs[0].node_id(),
    };
    let vote_bytes = encode("vote", &vote)?;
    let vote_digest_bytes = vote_digest(&vote.block_id, vote.round).0.to_vec();
    let vote_signature = keypairs[0].sign(Domain::Vote, &vote_digest_bytes);

    let proof = EquivocationProof::new(
        signed_vote(&keypairs[0], Hash([0x11; 32]), Round(11)),
        signed_vote(&keypairs[0], Hash([0x22; 32]), Round(11)),
    );
    if !verify_equivocation_proof(&proof, &validator_set) {
        return Err(FixtureError::Invariant("equivocation proof did not verify"));
    }
    let reconfiguration = Reconfig {
        next_set: validator_set.without(&keypairs[0].node_id()),
        evidence: vec![proof.clone()],
        operator_sig: None,
        jail: None,
    };
    let unused_operator = OperatorSet::single(keypairs[3].pubkey_bytes());
    if !verify_reconfig_authorized(&validator_set, &reconfiguration, 0, &unused_operator) {
        return Err(FixtureError::Invariant(
            "evidence removal reconfiguration was rejected",
        ));
    }

    let mut manifest = String::new();
    writeln!(&mut manifest, "azbft_conformance_version=0.1.0-alpha").unwrap();
    writeln!(
        &mut manifest,
        "warning=low-entropy public test identities; never use in production"
    )
    .unwrap();
    writeln!(&mut manifest, "validator_count=4").unwrap();
    writeln!(&mut manifest, "stake_per_validator=1").unwrap();
    writeln!(&mut manifest, "quorum_stake=3").unwrap();
    for (index, keypair) in keypairs.iter().enumerate() {
        writeln!(&mut manifest, "validator_{}_seed={}", index + 1, index + 1).unwrap();
        writeln!(
            &mut manifest,
            "validator_{}_node_id={}",
            index + 1,
            hex(&keypair.node_id().0)
        )
        .unwrap();
        writeln!(
            &mut manifest,
            "validator_{}_secp_public_key={}",
            index + 1,
            hex(&keypair.pubkey_bytes())
        )
        .unwrap();
    }
    writeln!(&mut manifest, "finality-valid.azbft=valid").unwrap();
    writeln!(&mut manifest, "finality-invalid-qc.azbft=invalid").unwrap();
    writeln!(&mut manifest, "qc-valid.borsh=valid").unwrap();
    writeln!(&mut manifest, "qc-invalid-below-quorum.borsh=invalid").unwrap();
    writeln!(&mut manifest, "tc-valid-epoch-0.borsh=valid").unwrap();
    writeln!(
        &mut manifest,
        "tc-invalid-below-quorum-epoch-0.borsh=invalid"
    )
    .unwrap();
    writeln!(&mut manifest, "equivocation-proof.borsh=valid").unwrap();
    writeln!(
        &mut manifest,
        "reconfiguration-evidence-removal.borsh=valid"
    )
    .unwrap();

    let mut artifacts = vec![
        FixtureArtifact {
            relative_path: "finality-valid.azbft",
            bytes: valid_transcript_bytes,
        },
        FixtureArtifact {
            relative_path: "finality-invalid-qc.azbft",
            bytes: invalid_transcript_bytes,
        },
        FixtureArtifact {
            relative_path: "validator-set.borsh",
            bytes: encode("validator set", &validator_set)?,
        },
        FixtureArtifact {
            relative_path: "vote.borsh",
            bytes: vote_bytes,
        },
        FixtureArtifact {
            relative_path: "vote-digest.bin",
            bytes: vote_digest_bytes,
        },
        FixtureArtifact {
            relative_path: "vote-signature.bin",
            bytes: vote_signature,
        },
        FixtureArtifact {
            relative_path: "qc-valid.borsh",
            bytes: encode("valid QC", &valid_qc)?,
        },
        FixtureArtifact {
            relative_path: "qc-invalid-below-quorum.borsh",
            bytes: encode("invalid QC", &invalid_qc)?,
        },
        FixtureArtifact {
            relative_path: "tc-valid-epoch-0.borsh",
            bytes: encode("valid TC", &valid_tc)?,
        },
        FixtureArtifact {
            relative_path: "tc-invalid-below-quorum-epoch-0.borsh",
            bytes: encode("invalid TC", &invalid_tc)?,
        },
        FixtureArtifact {
            relative_path: "equivocation-proof.borsh",
            bytes: encode("equivocation proof", &proof)?,
        },
        FixtureArtifact {
            relative_path: "reconfiguration-evidence-removal.borsh",
            bytes: encode("evidence removal reconfiguration", &reconfiguration)?,
        },
        FixtureArtifact {
            relative_path: "MANIFEST.txt",
            bytes: manifest.into_bytes(),
        },
    ];

    let mut checksums = String::new();
    for artifact in &artifacts {
        writeln!(
            &mut checksums,
            "{}  {}",
            blake3::hash(&artifact.bytes).to_hex(),
            artifact.relative_path
        )
        .unwrap();
    }
    artifacts.push(FixtureArtifact {
        relative_path: "BLAKE3SUMS",
        bytes: checksums.into_bytes(),
    });
    Ok(artifacts)
}
