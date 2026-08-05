use azbft_devnet::{run_devnet_with_fault, DevnetConfig, DevnetFault};

#[test]
fn unavailable_initial_leader_causes_view_change_then_progress() {
    let transcript = run_devnet_with_fault(
        DevnetConfig {
            validators: 4,
            blocks: 4,
            seed: 31,
        },
        DevnetFault::UnavailableInitialLeader,
    )
    .expect("three available validators recover");

    assert_eq!(transcript.finalized.len(), 4);
    assert!(transcript.view_changes > 0);
}
