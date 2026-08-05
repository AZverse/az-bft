use azbft_types::AggSig;
use azbft_verifier::{decode_transcript, encode_transcript};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn azbft(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_azbft"))
        .args(args)
        .output()
        .expect("run azbft")
}

fn path_text(path: &Path) -> &str {
    path.to_str().expect("temporary path is UTF-8")
}

#[test]
fn run_verify_and_inspect_round_trip() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let transcript = directory.path().join("devnet.azbft");

    let run = azbft(&[
        "devnet",
        "run",
        "--validators",
        "4",
        "--blocks",
        "3",
        "--seed",
        "5",
        "--output",
        path_text(&transcript),
    ]);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert!(transcript.is_file());

    let verify = azbft(&["verify", path_text(&transcript)]);
    assert!(verify.status.success());
    assert!(String::from_utf8_lossy(&verify.stdout).contains("verified 3 finalized blocks"));

    let inspect = azbft(&["inspect", path_text(&transcript), "--height", "2"]);
    assert!(inspect.status.success());
    assert!(String::from_utf8_lossy(&inspect.stdout).contains("height=2"));
}

#[test]
fn invalid_inputs_fail_closed() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let missing = directory.path().join("missing.azbft");
    assert!(!azbft(&["verify", path_text(&missing)]).status.success());

    let transcript_path = directory.path().join("valid.azbft");
    assert!(azbft(&[
        "devnet",
        "run",
        "--validators",
        "4",
        "--blocks",
        "2",
        "--output",
        path_text(&transcript_path),
    ])
    .status
    .success());
    assert!(
        !azbft(&["inspect", path_text(&transcript_path), "--height", "99",])
            .status
            .success()
    );

    let bytes = fs::read(&transcript_path).expect("read transcript");
    let mut transcript = decode_transcript(&bytes).expect("decode transcript");
    let proof = &mut transcript
        .finalized
        .last_mut()
        .expect("final record")
        .certificate
        .commit_qc
        .agg;
    match proof {
        AggSig::Bls(aggregate) => aggregate.agg_sig[0] ^= 1,
        AggSig::Secp(signatures) => signatures[0].1[0] ^= 1,
    }
    fs::write(
        &transcript_path,
        encode_transcript(&transcript).expect("encode transcript"),
    )
    .expect("write corrupted transcript");

    assert!(!azbft(&["verify", path_text(&transcript_path)])
        .status
        .success());
}

#[test]
fn committed_conformance_transcripts_have_expected_results() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let fixtures = root.join("fixtures/v0.1.0-alpha");
    let valid = fixtures.join("finality-valid.azbft");
    let invalid = fixtures.join("finality-invalid-qc.azbft");

    let verify = azbft(&["verify", path_text(&valid)]);
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    assert!(String::from_utf8_lossy(&verify.stdout).contains("verified 5 finalized blocks"));

    assert!(!azbft(&["verify", path_text(&invalid)]).status.success());
}
