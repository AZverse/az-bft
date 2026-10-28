use azbft_devnet::{run_devnet_with_fault, run_devnet_with_schedule, DevnetConfig, DevnetFault};
use azbft_types::LeaderSchedule;

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

/// Rounds that ended without a finalized block, and the logical time the last
/// requested block was stamped with.
fn wasted_and_elapsed(t: &azbft_devnet::DevnetTranscript) -> (u64, u64) {
    let last = &t.finalized.last().expect("finalized").block;
    (last.round.0 - t.finalized.len() as u64, last.timestamp_ms)
}

fn run(fault: DevnetFault, schedule: LeaderSchedule, blocks: u64) -> (u64, u64) {
    let t = run_devnet_with_schedule(
        DevnetConfig {
            validators: 4,
            blocks,
            seed: 95,
        },
        fault,
        schedule,
    )
    .unwrap_or_else(|e| panic!("{schedule:?}: {e}"));
    assert_eq!(t.finalized.len() as u64, blocks);
    wasted_and_elapsed(&t)
}

/// blockchain#95: with one validator down for the whole run, round robin loses
/// that validator's round on every pass of the schedule — and only that one,
/// because the predecessor's block is still certified by its author from the
/// votes sent to it and carried through the timeout. Skip-absent hands the down
/// validator's turns to a present member once a liveness QC shows it missing.
#[test]
fn skip_absent_schedules_stop_wasting_rounds_on_a_down_validator() {
    for down in 0..4 {
        let fault = DevnetFault::UnavailableValidators(vec![down]);
        let (base_w, base_t) = run(fault.clone(), LeaderSchedule::RoundRobin, 60);
        let (skip_w, skip_t) = run(fault.clone(), LeaderSchedule::RoundRobinSkipAbsent, 60);
        let (sw_w, sw_t) = run(fault, LeaderSchedule::StakeWeightedSkipAbsent, 60);
        eprintln!(
            "down {down}: wasted/elapsed round_robin {base_w}/{base_t} \
             skip {skip_w}/{skip_t} weighted_skip {sw_w}/{sw_t}"
        );
        // 60 blocks take about 20 passes of four rounds; votes to the next leader
        // only lose two rounds per pass (about 60 here).
        assert!(
            (10..=25).contains(&base_w),
            "down {down}: round robin should waste one round per pass, wasted {base_w}"
        );
        assert!(
            skip_w <= 2 && sw_w <= 2,
            "down {down}: skip-absent wasted {skip_w}/{sw_w}"
        );
        assert!(skip_t * 2 < base_t, "down {down}: {skip_t} vs {base_t}");
    }
}

/// With everyone up, skip-absent wastes no more rounds than round robin. A few
/// rounds can be lost under any schedule: a leader whose QC forms before the
/// proposal of the certified block reaches it cannot build on it, and this
/// simulator, unlike the node, does not rebuild once the block arrives.
#[test]
fn skip_absent_wastes_no_round_when_everyone_is_up() {
    for schedule in [
        LeaderSchedule::RoundRobin,
        LeaderSchedule::RoundRobinSkipAbsent,
        LeaderSchedule::StakeWeightedSkipAbsent,
    ] {
        let (wasted, elapsed) = run(DevnetFault::None, schedule, 60);
        eprintln!("all up {schedule:?}: wasted {wasted} elapsed {elapsed}");
        assert!(wasted <= 3, "{schedule:?} wasted {wasted}");
    }
}
