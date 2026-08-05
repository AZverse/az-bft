use azbft_devnet::{run_devnet, DevnetConfig};

#[test]
fn four_validators_finalize_the_requested_blocks() {
    let transcript = run_devnet(DevnetConfig {
        validators: 4,
        blocks: 5,
        seed: 42,
    })
    .expect("healthy devnet finalizes");

    assert_eq!(transcript.validator_set.len(), 4);
    assert_eq!(transcript.finalized.len(), 5);
    assert!(transcript
        .finalized
        .windows(2)
        .all(|pair| pair[0].block.height < pair[1].block.height));
    assert!(transcript
        .finalized
        .iter()
        .all(|record| record.block == record.certificate.block));
}
