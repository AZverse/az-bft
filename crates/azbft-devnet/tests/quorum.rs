use azbft_devnet::{run_devnet_with_fault, DevnetConfig, DevnetError, DevnetFault};

#[test]
fn fewer_than_quorum_participants_cannot_finalize() {
    let result = run_devnet_with_fault(
        DevnetConfig {
            validators: 4,
            blocks: 1,
            seed: 7,
        },
        DevnetFault::UnavailableValidators(vec![0, 1]),
    );

    assert!(matches!(
        result,
        Err(DevnetError::NoFinality { finalized: 0, .. })
    ));
}
