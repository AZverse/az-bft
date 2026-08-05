use azbft_devnet::{run_devnet, DevnetConfig};

#[test]
fn same_seed_produces_identical_transcript() {
    let config = DevnetConfig {
        validators: 4,
        blocks: 6,
        seed: 99,
    };

    let first = run_devnet(config.clone()).expect("first deterministic run");
    let second = run_devnet(config).expect("second deterministic run");

    assert_eq!(first, second);
    assert_eq!(first.finalized.len(), 6);
}
