use azbft_devnet::{run_devnet, DevnetConfig};
use azbft_types::AggSig;
use azbft_verifier::verify_transcript;

#[test]
fn valid_transcript_verifies() {
    let transcript = run_devnet(DevnetConfig {
        validators: 4,
        blocks: 5,
        seed: 12,
    })
    .expect("devnet run");

    let summary = verify_transcript(&transcript).expect("valid finality proof");
    assert_eq!(summary.finalized_blocks, 5);
    assert_eq!(summary.last_height, 5);
}

#[test]
fn corrupted_final_qc_is_rejected() {
    let mut transcript = run_devnet(DevnetConfig {
        validators: 4,
        blocks: 3,
        seed: 13,
    })
    .expect("devnet run");

    let final_record = transcript.finalized.last_mut().expect("final record");
    match &mut final_record.certificate.commit_qc.agg {
        AggSig::Bls(aggregate) => aggregate.agg_sig[0] ^= 0x01,
        AggSig::Secp(signatures) => signatures[0].1[0] ^= 0x01,
    }

    assert!(verify_transcript(&transcript).is_err());
}
