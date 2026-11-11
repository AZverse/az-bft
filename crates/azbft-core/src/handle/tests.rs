use super::*;
use crate::command::Command;
use crate::state::{ConsensusCore, Signer};
use azbft_crypto::keypair::Keypair;

/// A `Signer` that wraps one validator keypair. Signing stays deterministic
/// (ECDSA-over-prehash), so the core remains a pure transition.
struct TestSigner(Keypair);
impl Signer for TestSigner {
    fn sign(&self, d: Domain, msg: &[u8]) -> Vec<u8> {
        self.0.sign(d, msg)
    }
    fn node_id(&self) -> NodeId {
        self.0.node_id()
    }
}

/// 4 validators (seeds 1..=4), each stake 1 -> quorum = 3.
fn validators() -> (Vec<Keypair>, ValidatorSet) {
    let kps: Vec<Keypair> = (1..=4u64).map(Keypair::from_seed).collect();
    let members = kps
        .iter()
        .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
        .collect();
    (kps, ValidatorSet::new(members))
}

/// Index into `kps` of the keypair whose node_id == `id`. (The validator
/// set sorts by NodeId, so leader(round) is *not* seed order — resolve the
/// real keypair this way.)
fn kp_of(kps: &[Keypair], id: NodeId) -> &Keypair {
    kps.iter().find(|k| k.node_id() == id).expect("known node")
}

/// Build a core whose identity is the validator at `me_idx` (validators are
/// seeded `1..=4`, so seed `1 + me_idx` reproduces that validator's key).
fn core_as(vset: &ValidatorSet, me_idx: usize) -> ConsensusCore {
    let signer = TestSigner(Keypair::from_seed(1 + me_idx as u64));
    let operator_pk = Keypair::from_seed(999_999).pubkey_bytes();
    ConsensusCore::with_signer(0, vset.clone(), 100, Box::new(signer), operator_pk)
}

fn handle_payload_ready(
    core: &mut ConsensusCore,
    round: Round,
    payload: Vec<u8>,
    now: LogicalTime,
) -> Vec<Command> {
    let parent = core.high_qc().clone();
    let context = core
        .proposal_build_context(round, &parent, now)
        .expect("leader has a current proposal context");
    core.handle(Event::PayloadReady { context, payload }, now)
}

/// `ConsensusCore::leader` dispatches on the configured mode — default
/// RoundRobin equals `vset.leader`; after `set_leader_mode(StakeWeighted)` it equals
/// `vset.leader_weighted` AND diverges from round-robin for at least one round
/// (a positive control proving the mode actually switched the algorithm).
#[test]
fn core_leader_dispatches_on_mode() {
    let (_kps, vset) = validators();
    let mut core = core_as(&vset, 0);
    for r in 0..10u64 {
        assert_eq!(
            core.leader(Round(r)),
            vset.leader(Round(r)),
            "default = round-robin"
        );
    }
    core.set_leader_mode(LeaderSchedule::StakeWeighted);
    assert_eq!(core.leader_mode(), LeaderSchedule::StakeWeighted);
    let mut diverges = false;
    for r in 0..30u64 {
        assert_eq!(
            core.leader(Round(r)),
            vset.leader_weighted(Round(r)),
            "StakeWeighted routes to leader_weighted"
        );
        if core.leader(Round(r)) != vset.leader(Round(r)) {
            diverges = true;
        }
    }
    assert!(
        diverges,
        "StakeWeighted must diverge from round-robin for some round"
    );
}

/// The duration of the `SetTimer` armed for `round`, if the batch armed one.
fn armed_timer(out: &[Command], round: Round) -> Option<u64> {
    out.iter().find_map(|command| match command {
        Command::SetTimer(r, duration) if *r == round => Some(*duration),
        _ => None,
    })
}

/// Drive `round` to a timeout certificate: the local timer fires, then a
/// quorum of peer timeouts for the same round forms the TC that carries us
/// into `round + 1`. Returns the commands emitted when entering that round.
fn time_out_round(core: &mut ConsensusCore, kps: &[Keypair], round: Round) -> Vec<Command> {
    core.handle(Event::LocalTimeout(round), 0);
    let mut out = Vec::new();
    for kp in kps.iter().take(3) {
        let timeout = Timeout {
            epoch: 0,
            round,
            high_qc: QuorumCert::genesis(),
            sender: kp.node_id(),
        };
        out = core.handle(Event::RemoteTimeout(sign_timeout(kp, &timeout)), 0);
    }
    assert_eq!(
        core.round(),
        Round(round.0 + 1),
        "a quorum of timeouts for {round:?} advances one round"
    );
    out
}

// ---- Pacemaker backoff across consecutive timed-out rounds ----

/// A round carried out by a TC produced no block, so leaving it is not
/// progress and must not clear the backoff. The timer therefore keeps
/// doubling for as long as rounds keep expiring, which is the only way a
/// chain whose rounds all expire before a proposal can be voted recovers:
/// the timer has to grow past however long the round actually needs.
///
/// Resetting on every advance capped the backoff at a single doubling,
/// because a stuck chain leaves every round by TC.
#[test]
fn consecutive_timed_out_rounds_keep_doubling_the_timer() {
    let (kps, vset) = validators();
    let mut core = core_as(&vset, 0);
    core.start();

    let mut armed = Vec::new();
    for round in 1..=8u64 {
        let out = time_out_round(&mut core, &kps, Round(round));
        armed.push(armed_timer(&out, Round(round + 1)).expect("entering a round arms its timer"));
    }
    assert_eq!(
        armed,
        vec![100, 200, 400, 800, 1600, 3200, 6400, 6400],
        "base 100 holds for the first timed-out round, then doubles once per further \
             consecutive one, up to the cap"
    );
}

/// blockchain#191: a leader whose rounds keep expiring without its proposal
/// is absent; once it has let three of its rounds expire, entering its round
/// arms a quarter of the timer the other leaders' rounds get at the same
/// backoff.
#[test]
fn an_absent_leaders_round_gets_a_shorter_timer() {
    let (kps, vset) = validators();
    let mut core = core_as(&vset, 0);
    core.start();
    let mut silent: std::collections::BTreeMap<NodeId, u32> = Default::default();
    let mut checked = 0;
    for round in 1..=16u64 {
        *silent.entry(vset.leader(Round(round))).or_default() += 1;
        // The re-armed timer fires again before the TC forms: the leader is
        // still counted once for the round.
        core.handle(Event::LocalTimeout(Round(round)), 0);
        let out = time_out_round(&mut core, &kps, Round(round));
        let next = Round(round + 1);
        let armed = armed_timer(&out, next).expect("entering a round arms its timer");
        if round >= 7 {
            // The backoff has reached its cap (6400 at base 100).
            let absent = silent.get(&vset.leader(next)).copied().unwrap_or(0) >= 3;
            assert_eq!(armed, if absent { 1600 } else { 6400 }, "round {}", next.0);
            checked += usize::from(absent);
        }
    }
    assert!(
        checked >= 4,
        "absent leaders' rounds were armed short {checked} times"
    );
}

/// The counterpart: a QC is progress, so the backoff returns to base even
/// after the previous round expired.
#[test]
fn a_certified_round_resets_the_backoff() {
    let (kps, vset) = validators();
    let leader2 = vset.leader(Round(2));
    let me_idx = kps.iter().position(|k| k.node_id() == leader2).unwrap();
    let mut core = core_as(&vset, me_idx);
    core.start();

    // Round 1 expires, so the backoff is one doubling deep.
    core.handle(Event::LocalTimeout(Round(1)), 0);

    // A quorum of votes for the round-1 block certifies it and advances us.
    let b1 = block_round1(vset.leader(Round(1)), b"payload-1");
    core.tree_insert_for_test(b1.clone());
    let mut out = Vec::new();
    for kp in kps.iter().take(3) {
        let vote = Vote {
            epoch: 0,
            block_id: b1.id(),
            round: Round(1),
            voter: kp.node_id(),
        };
        out = core.handle(Event::Vote(sign_vote(kp, &vote)), 0);
    }
    assert_eq!(
        core.round(),
        Round(2),
        "a QC for round 1 advances to round 2"
    );
    assert_eq!(
        armed_timer(&out, Round(2)),
        Some(100),
        "a certified advance returns the timer to base"
    );
}

/// A round-1 block extending genesis, authored by `leader`.
fn block_round1(leader: NodeId, payload: &[u8]) -> Block {
    Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 0,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: blake3_id(&payload.to_vec()),
        author: leader,
        reconfig: None,
    }
}

/// Sign a proposal as its author (Domain::Proposal over borsh(proposal)).
fn sign_proposal(author: &Keypair, prop: &Proposal) -> Signed<Proposal> {
    let sig = author.sign(Domain::Proposal, &borsh::to_vec(prop).expect("borsh"));
    Signed {
        inner: prop.clone(),
        sig,
    }
}

/// Sign a vote as its voter (Domain::Vote over vote_digest(block_id, round)).
fn sign_vote(voter: &Keypair, vote: &Vote) -> Signed<Vote> {
    let sig = voter.sign(Domain::Vote, &vote_digest(&vote.block_id, vote.round).0);
    Signed {
        inner: vote.clone(),
        sig,
    }
}

/// Sign a timeout as its sender (Domain::Timeout over timeout_digest(epoch, round)).
fn sign_timeout(sender: &Keypair, t: &Timeout) -> Signed<Timeout> {
    let sig = sender.sign(Domain::Timeout, &timeout_digest(t.epoch, t.round).0);
    Signed {
        inner: t.clone(),
        sig,
    }
}

// ---- Proposal path: proposal path -> rule-1 vote to next leader ----

#[test]
fn proposal_makes_replica_vote_to_next_leader_and_sets_timer() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let leader2 = vset.leader(Round(2));

    // `me` must be a replica, i.e. NOT the round-1 leader.
    let me_idx = kps
        .iter()
        .position(|k| k.node_id() != leader1)
        .expect("a non-leader exists");
    let mut core = core_as(&vset, me_idx);
    assert_ne!(core.me(), leader1, "test node should be a replica");

    // Leader proposes a round-1 block extending genesis.
    let b = block_round1(leader1, b"payload-1");
    let prop = Proposal {
        block: b.clone(),
        last_round_tc: None,
    };
    let signed = sign_proposal(kp_of(&kps, leader1), &prop);

    let out = core.handle(Event::Proposal(signed), 0);

    // Expect: a Vote Send to leader(2), and a SetTimer for round 1.
    let sent_vote = out.iter().any(|c| {
        matches!(c,
            Command::Send(to, ConsensusMessage::Vote(sv))
                if *to == leader2 && sv.inner.block_id == b.id() && sv.inner.round == Round(1)
        )
    });
    assert!(sent_vote, "expected Vote sent to leader(2); got {out:?}");

    let armed = out
        .iter()
        .any(|c| matches!(c, Command::SetTimer(r, _) if *r == Round(1)));
    assert!(armed, "expected SetTimer(Round(1), _); got {out:?}");
}

/// CRITICAL (qc-round-auth): a proposal whose parent_qc does not verify — here
/// a VALID QC relabelled to a higher round — must NOT be voted. Before the fix
/// `make_vote`'s lock check trusted the unverified `parent_qc.round`, so a
/// Byzantine leader could inflate it to bypass the lock and admit conflicting
/// commits; now `vote_digest` binds the round into the vote signature, the
/// relabel fails verification in `process_qc`, and `on_proposal` gates the
/// vote. A correctly-labelled parent_qc is voted as the positive control.
#[test]
fn round_relabelled_parent_qc_is_not_voted() {
    let (kps, vset) = validators();
    // A block id + a VALID QC certifying it AT ROUND 5 (votes sign
    // vote_digest(x_id, 5)).
    let x = block_round1(vset.leader(Round(1)), b"x");
    let x_id = x.id();
    let valid_qc = qc_over(x_id, Round(5), &kps);

    // Control: correctly-labelled parent_qc (round 5) -> child at round 6 IS voted.
    let l6 = vset.leader(Round(6));
    let me6 = kps.iter().position(|k| k.node_id() != l6).unwrap();
    let mut core6 = core_as(&vset, me6);
    core6.tree.insert(x.clone());
    let b6 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 2,
        timestamp_ms: 2,
        epoch: 0,
        round: Round(6),
        parent_qc: valid_qc.clone(),
        payload_hash: blake3_id(&b"p".to_vec()),
        author: l6,
        reconfig: None,
    };
    let out6 = core6.handle(
        Event::Proposal(sign_proposal(
            kp_of(&kps, l6),
            &Proposal {
                block: b6,
                last_round_tc: None,
            },
        )),
        0,
    );
    assert!(
        out6.iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "control: a correctly-labelled parent_qc must be voted; got {out6:?}"
    );

    // Attack: SAME aggregate, round relabelled 5 -> 100. Verification uses
    // vote_digest(x_id, 100), which the signers never signed -> fails.
    let l101 = vset.leader(Round(101));
    let me101 = kps.iter().position(|k| k.node_id() != l101).unwrap();
    let mut core101 = core_as(&vset, me101);
    core101.tree.insert(x);
    let relabelled = QuorumCert {
        block_id: x_id,
        round: Round(100),
        agg: valid_qc.agg.clone(),
    };
    let b101 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 2,
        timestamp_ms: 2,
        epoch: 0,
        round: Round(101),
        parent_qc: relabelled,
        payload_hash: blake3_id(&b"p".to_vec()),
        author: l101,
        reconfig: None,
    };
    let out101 = core101.handle(
        Event::Proposal(sign_proposal(
            kp_of(&kps, l101),
            &Proposal {
                block: b101,
                last_round_tc: None,
            },
        )),
        0,
    );
    assert!(
        !out101
            .iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "SECURITY: a round-relabelled (unverifiable) parent_qc must NOT be voted; got {out101:?}"
    );
}

/// HIGH (round-proof): a proposal whose round is NOT consecutive with its
/// parent_qc must carry a VALID TC for round-1; otherwise the round jump is
/// unjustified and the proposal is not voted. With a valid TC the jump is
/// voted as the positive control.
#[test]
fn nonconsecutive_round_needs_valid_tc() {
    let (kps, vset) = validators();
    let x = block_round1(vset.leader(Round(1)), b"x");
    let x_id = x.id();
    let pqc = qc_over(x_id, Round(3), &kps); // a valid QC at round 3

    // A valid TC for round 9: quorum of Domain::Timeout sigs over blake3(9).
    let tc_round = Round(9);
    let tc_sigs: Vec<(NodeId, Vec<u8>)> = kps
        .iter()
        .take(3)
        .map(|k| {
            (
                k.node_id(),
                k.sign(Domain::Timeout, &timeout_digest(0, tc_round).0),
            )
        })
        .collect();
    let valid_tc = TimeoutCert {
        round: tc_round,
        agg: SecpMultiSig::aggregate(&tc_sigs),
        high_qc: pqc.clone(),
    };

    // Non-consecutive proposal: parent_qc at round 3, block at round 10.
    let l10 = vset.leader(Round(10));
    let me10 = kps.iter().position(|k| k.node_id() != l10).unwrap();
    let b10 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 2,
        timestamp_ms: 2,
        epoch: 0,
        round: Round(10),
        parent_qc: pqc.clone(),
        payload_hash: blake3_id(&b"p".to_vec()),
        author: l10,
        reconfig: None,
    };

    // (1) No TC -> unjustified round jump -> no vote.
    let mut core1 = core_as(&vset, me10);
    core1.tree.insert(x.clone());
    let out1 = core1.handle(
        Event::Proposal(sign_proposal(
            kp_of(&kps, l10),
            &Proposal {
                block: b10.clone(),
                last_round_tc: None,
            },
        )),
        0,
    );
    assert!(
        !out1
            .iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "non-consecutive round without a TC must NOT be voted; got {out1:?}"
    );

    // (2) Positive control: a valid TC for round 9 justifies a vote.
    let mut core2 = core_as(&vset, me10);
    core2.tree.insert(x.clone());
    let out2 = core2.handle(
        Event::Proposal(sign_proposal(
            kp_of(&kps, l10),
            &Proposal {
                block: b10,
                last_round_tc: Some(valid_tc.clone()),
            },
        )),
        0,
    );
    assert!(
        out2.iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "non-consecutive round WITH a valid TC must be voted; got {out2:?}"
    );

    // (3) The same valid timeout aggregate cannot justify extending a QC
    // other than the TC's own high-QC. Before the parent-binding guard this
    // was voted and could finalize a sibling after a view change.
    let mismatched_tc = TimeoutCert {
        round: tc_round,
        agg: valid_tc.agg.clone(),
        high_qc: QuorumCert::genesis(),
    };
    let mut core3 = core_as(&vset, me10);
    core3.tree.insert(x);
    let out3 = core3.handle(
        Event::Proposal(sign_proposal(
            kp_of(&kps, l10),
            &Proposal {
                block: Block {
                    header_version: BLOCK_HEADER_VERSION_V2,
                    height: 2,
                    timestamp_ms: 2,
                    epoch: 0,
                    round: Round(10),
                    parent_qc: pqc,
                    payload_hash: blake3_id(&b"mismatched-parent".to_vec()),
                    author: l10,
                    reconfig: None,
                },
                last_round_tc: Some(mismatched_tc),
            },
        )),
        0,
    );
    assert!(
        !out3
            .iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "a timeout proposal not extending tc.high_qc must NOT be voted; got {out3:?}"
    );
}

/// Positive control for the round-proof check: a non-consecutive proposal carrying a TC whose
/// aggregate does NOT verify (here sub-quorum, 2 of 3) must NOT be voted —
/// proving the verify_agg(TC) branch is load-bearing.
#[test]
fn nonconsecutive_round_with_subquorum_tc_is_not_voted() {
    let (kps, vset) = validators();
    let x_id = block_round1(vset.leader(Round(1)), b"x").id();
    let pqc = qc_over(x_id, Round(3), &kps);
    let tc_round = Round(9);
    // Only 2 timeout sigs — below quorum (3) — so verify_agg fails.
    let tc_sigs: Vec<(NodeId, Vec<u8>)> = kps
        .iter()
        .take(2)
        .map(|k| {
            (
                k.node_id(),
                k.sign(Domain::Timeout, &timeout_digest(0, tc_round).0),
            )
        })
        .collect();
    let bad_tc = TimeoutCert {
        round: tc_round,
        agg: SecpMultiSig::aggregate(&tc_sigs),
        high_qc: pqc.clone(),
    };
    let l10 = vset.leader(Round(10));
    let me10 = kps.iter().position(|k| k.node_id() != l10).unwrap();
    let b10 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 0,
        round: Round(10),
        parent_qc: pqc,
        payload_hash: blake3_id(&b"p".to_vec()),
        author: l10,
        reconfig: None,
    };
    let mut core = core_as(&vset, me10);
    let out = core.handle(
        Event::Proposal(sign_proposal(
            kp_of(&kps, l10),
            &Proposal {
                block: b10,
                last_round_tc: Some(bad_tc),
            },
        )),
        0,
    );
    assert!(
        !out.iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "a sub-quorum (unverifiable) TC must NOT justify the round; got {out:?}"
    );
}

/// Cross-epoch TC replay: a TC whose timeouts were signed in epoch 0 must NOT
/// verify in epoch 1 (timeout_digest binds the epoch; an epoch roll resets the
/// round counter). The same TC re-signed for epoch 1 is accepted as the positive control.
#[test]
fn cross_epoch_tc_replay_is_rejected() {
    let (kps, vset) = validators();
    let mut x = block_round1(vset.leader(Round(1)), b"x");
    x.epoch = 1;
    let x_id = x.id();
    let pqc = qc_over(x_id, Round(3), &kps);
    let l10 = vset.leader(Round(10));
    let me10 = kps.iter().position(|k| k.node_id() != l10).unwrap();
    // A core running in EPOCH 1 (as a replica).
    let core_epoch1 = |me_idx: usize| {
        let signer = TestSigner(Keypair::from_seed(1 + me_idx as u64));
        let operator_pk = Keypair::from_seed(999_999).pubkey_bytes();
        ConsensusCore::with_signer(1, vset.clone(), 100, Box::new(signer), operator_pk)
    };
    let block_epoch1 = || Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 2,
        timestamp_ms: 2,
        epoch: 1,
        round: Round(10),
        parent_qc: pqc.clone(),
        payload_hash: blake3_id(&b"p".to_vec()),
        author: l10,
        reconfig: None,
    };
    let tc_for_epoch = |e: u64| {
        let sigs: Vec<(NodeId, Vec<u8>)> = kps
            .iter()
            .take(3)
            .map(|k| {
                (
                    k.node_id(),
                    k.sign(Domain::Timeout, &timeout_digest(e, Round(9)).0),
                )
            })
            .collect();
        TimeoutCert {
            round: Round(9),
            agg: SecpMultiSig::aggregate(&sigs),
            high_qc: pqc.clone(),
        }
    };

    // Replay an epoch-0 TC in epoch 1 -> rejected (no vote).
    let mut core = core_epoch1(me10);
    core.tree.insert(x.clone());
    let out = core.handle(
        Event::Proposal(sign_proposal(
            kp_of(&kps, l10),
            &Proposal {
                block: block_epoch1(),
                last_round_tc: Some(tc_for_epoch(0)),
            },
        )),
        0,
    );
    assert!(
        !out.iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "an epoch-0 TC replayed in epoch 1 must NOT be voted; got {out:?}"
    );

    // Positive control: a correctly epoch-1-signed TC IS voted.
    let mut core2 = core_epoch1(me10);
    core2.tree.insert(x);
    let out2 = core2.handle(
        Event::Proposal(sign_proposal(
            kp_of(&kps, l10),
            &Proposal {
                block: block_epoch1(),
                last_round_tc: Some(tc_for_epoch(1)),
            },
        )),
        0,
    );
    assert!(
        out2.iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "an epoch-1 TC in epoch 1 must be voted; got {out2:?}"
    );
}

#[test]
fn proposal_with_bad_author_sig_is_ignored() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() != leader1).unwrap();
    let mut core = core_as(&vset, me_idx);

    let b = block_round1(leader1, b"payload-1");
    let prop = Proposal {
        block: b,
        last_round_tc: None,
    };
    // Signed by the WRONG key (a non-leader), so author verification fails.
    let wrong = kp_of(&kps, vset.leader(Round(2)));
    let signed = sign_proposal(wrong, &prop);

    let out = core.handle(Event::Proposal(signed), 0);
    assert!(
        out.is_empty(),
        "bad-author proposal must produce nothing; got {out:?}"
    );
}

// ---- Vote aggregation: vote aggregation -> QC -> rule-2 -> advance round ----

#[test]
fn quorum_of_votes_forms_qc_and_advances_round() {
    let (kps, vset) = validators();
    let leader2 = vset.leader(Round(2));
    // Collector is leader(2).
    let me_idx = kps.iter().position(|k| k.node_id() == leader2).unwrap();
    let mut core = core_as(&vset, me_idx);
    assert_eq!(core.me(), leader2);

    // The block being certified must be known to the collector.
    let b1 = block_round1(vset.leader(Round(1)), b"payload-1");
    core.tree_insert_for_test(b1.clone());

    // Feed 3 (= quorum) valid votes for b1 from 3 distinct validators.
    let mut last_round = core.round();
    for k in kps.iter().take(3) {
        let vote = Vote {
            epoch: 0,
            block_id: b1.id(),
            round: Round(1),
            voter: k.node_id(),
        };
        let _ = core.handle(Event::Vote(sign_vote(k, &vote)), 0);
        last_round = core.round();
    }

    assert_eq!(core.high_qc().round, Round(1), "QC should be for round 1");
    assert_eq!(core.high_qc().block_id, b1.id(), "QC should certify b1");
    assert_eq!(last_round, Round(2), "core should have advanced to round 2");
}

#[test]
fn two_votes_below_quorum_do_not_advance() {
    let (kps, vset) = validators();
    let leader2 = vset.leader(Round(2));
    let me_idx = kps.iter().position(|k| k.node_id() == leader2).unwrap();
    let mut core = core_as(&vset, me_idx);

    let b1 = block_round1(vset.leader(Round(1)), b"payload-1");
    core.tree_insert_for_test(b1.clone());

    for k in kps.iter().take(2) {
        let vote = Vote {
            epoch: 0,
            block_id: b1.id(),
            round: Round(1),
            voter: k.node_id(),
        };
        let _ = core.handle(Event::Vote(sign_vote(k, &vote)), 0);
    }
    assert_eq!(
        core.round(),
        Round(1),
        "two votes (< quorum) must not advance"
    );
    assert_eq!(core.high_qc().round, Round(0), "no QC should have formed");
}

// ---- Leader proposal path: leader proposal path ----

#[test]
fn leader_start_requests_payload_then_payload_ready_broadcasts_proposal() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() == leader1).unwrap();
    let mut core = core_as(&vset, me_idx);
    assert_eq!(core.me(), leader1);

    // start(): leader -> CreatePayload{round:1}.
    let out = core.start();
    let asked = out
        .iter()
        .any(|c| matches!(c, Command::CreatePayload { round, .. } if *round == Round(1)));
    assert!(
        asked,
        "leader start should request a payload for round 1; got {out:?}"
    );

    // PayloadReady -> Broadcast(Proposal) for round 1, authored by me.
    let out = handle_payload_ready(&mut core, Round(1), b"payload-1".to_vec(), 0);
    let broadcast = out.iter().any(|c| {
        matches!(c,
            Command::Broadcast(ConsensusMessage::Proposal(sp))
                if sp.inner.block.round == Round(1) && sp.inner.block.author == leader1
        )
    });
    assert!(
        broadcast,
        "expected Broadcast(Proposal) for round 1; got {out:?}"
    );
}

#[test]
fn payload_ready_for_non_leader_is_ignored() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    // me is a replica for round 1.
    let me_idx = kps.iter().position(|k| k.node_id() != leader1).unwrap();
    let mut core = core_as(&vset, me_idx);

    let out = core.handle(
        Event::PayloadReady {
            context: ProposalBuildContext {
                epoch: 0,
                round: Round(1),
                parent: QuorumCert::genesis(),
                height: 1,
                timestamp_ms: 1,
                proposer: leader1,
            },
            payload: b"x".to_vec(),
        },
        0,
    );
    assert!(out.is_empty(), "non-leader must not propose; got {out:?}");
}

// ---- Timeout path: timeout -> TC -> advance round ----

#[test]
fn quorum_of_timeouts_forms_tc_and_advances_round() {
    let (kps, vset) = validators();
    let leader2 = vset.leader(Round(2));
    let me_idx = kps.iter().position(|k| k.node_id() == leader2).unwrap();
    let mut core = core_as(&vset, me_idx);

    // 3 valid round-1 timeouts, each carrying the genesis high_qc.
    for k in kps.iter().take(3) {
        let t = Timeout {
            epoch: 0,
            round: Round(1),
            high_qc: QuorumCert::genesis(),
            sender: k.node_id(),
        };
        let _ = core.handle(Event::RemoteTimeout(sign_timeout(k, &t)), 0);
    }
    assert_eq!(
        core.round(),
        Round(2),
        "quorum of timeouts should advance to round 2"
    );
}

/// A restart split the other way round: one validator holds the TC of a round
/// it has left, two others lost the timeouts they had collected for it and keep
/// timing it out; the fourth is down. The two lagging validators' timeouts are
/// answered with the leader's timeout for their round, they form the TC and
/// join it.
/// A stuck node answers a stale timeout only within STALE_ANSWER_WINDOW rounds of its
/// own: a faulty validator cannot make it sign one answer for every past round.
#[test]
fn a_stale_timeout_far_behind_is_not_answered() {
    let (_kps, vset) = validators();
    let mut ahead = core_as(&vset, 3);
    ahead.advance_round(Round(30), RoundExit::Certified, &mut Vec::new());
    let _ = ahead.handle(Event::LocalTimeout(Round(30)), 0);
    for (behind, answered) in [
        (30 - STALE_ANSWER_WINDOW, true),
        (30 - STALE_ANSWER_WINDOW - 1, false),
        (1, false),
    ] {
        let mut peer = core_as(&vset, 1);
        peer.advance_round(Round(behind), RoundExit::Certified, &mut Vec::new());
        let timeout = peer
            .handle(Event::LocalTimeout(Round(behind)), 0)
            .into_iter()
            .find_map(|command| match command {
                Command::Broadcast(ConsensusMessage::Timeout(timeout)) => Some(timeout),
                _ => None,
            })
            .expect("local timeout is broadcast");
        let sent = ahead
            .handle(Event::RemoteTimeout(timeout), 0)
            .iter()
            .any(|command| matches!(command, Command::Send(..)));
        assert_eq!(sent, answered, "a timeout for round {behind}");
    }
}

#[test]
fn validators_behind_a_round_another_left_catch_up_on_its_answer() {
    let (_kps, vset) = validators();
    let round = Round(20);
    let mut cores: Vec<_> = (0..4).map(|index| core_as(&vset, index)).collect();
    for core in &mut cores {
        core.advance_round(round, RoundExit::Certified, &mut Vec::new());
    }
    let timeout_of = |core: &mut ConsensusCore| {
        core.handle(Event::LocalTimeout(round), 0)
            .into_iter()
            .find_map(|command| match command {
                Command::Broadcast(ConsensusMessage::Timeout(timeout)) => Some(timeout),
                _ => None,
            })
            .expect("local timeout is broadcast")
    };
    let before: Vec<_> = (0..4).map(|index| timeout_of(&mut cores[index])).collect();
    // Validator 3 collects 0, 1 and 2: it forms the TC and moves on. Then the
    // others restart (they lose what they had collected) and validator 0 is down.
    for timeout in &before[0..3] {
        let _ = cores[3].handle(Event::RemoteTimeout(timeout.clone()), 0);
    }
    assert_eq!(cores[3].round(), Round(21));
    for index in [1, 2] {
        cores[index] = core_as(&vset, index);
        cores[index].advance_round(round, RoundExit::Certified, &mut Vec::new());
    }
    let again = [timeout_of(&mut cores[1]), timeout_of(&mut cores[2])];
    // 1 and 2 hear their own and each other's (the driver loops a broadcast back);
    // that is two of the three a TC needs.
    for index in [1, 2] {
        for timeout in &again {
            let _ = cores[index].handle(Event::RemoteTimeout(timeout.clone()), 0);
        }
    }
    assert_eq!((cores[1].round(), cores[2].round()), (round, round));
    // While validator 3 has not timed out round 21 it answers nothing.
    assert!(!cores[3]
        .handle(Event::RemoteTimeout(again[0].clone()), 0)
        .iter()
        .any(|command| matches!(command, Command::Send(..))));
    // Stuck in round 21 too, it answers each of them directly.
    let _ = cores[3].handle(Event::LocalTimeout(Round(21)), 0);
    for (index, timeout) in [(1usize, &again[0]), (2usize, &again[1])] {
        let commands = cores[3].handle(Event::RemoteTimeout(timeout.clone()), 0);
        let answer = commands
            .into_iter()
            .find_map(|command| match command {
                Command::Send(to, ConsensusMessage::Timeout(answer)) => {
                    assert_eq!(to, cores[index].me);
                    Some(answer)
                }
                _ => None,
            })
            .expect("the stale timeout is answered");
        assert_eq!(answer.inner.round, round);
        let _ = cores[index].handle(Event::RemoteTimeout(answer), 0);
        assert_eq!(
            cores[index].round(),
            Round(21),
            "validator {index} caught up"
        );
    }
    assert_eq!(
        cores[3].round(),
        Round(21),
        "answering does not move the leader"
    );
    // A timeout for the current round is not answered.
    let current = cores[1].handle(Event::LocalTimeout(Round(21)), 0);
    let current = current
        .into_iter()
        .find_map(|command| match command {
            Command::Broadcast(ConsensusMessage::Timeout(timeout)) => Some(timeout),
            _ => None,
        })
        .unwrap();
    assert!(!cores[3]
        .handle(Event::RemoteTimeout(current), 0)
        .iter()
        .any(|command| matches!(command, Command::Send(..))));
}

#[test]
fn split_restart_rounds_converge_after_f_plus_one_future_timeouts() {
    let (_kps, vset) = validators();
    let lower_round = Round(1_012);
    let higher_round = Round(1_013);
    let converged_round = Round(1_014);
    let mut cores: Vec<_> = (0..4).map(|index| core_as(&vset, index)).collect();

    // Model a restart split: validators 0/2 recovered one
    // round behind validators 1/3, and every validator timed out its local
    // restored round without forming a 3-of-4 TC.
    let mut initial_timeouts = Vec::new();
    for (index, core) in cores.iter_mut().enumerate() {
        let round = if index % 2 == 0 {
            lower_round
        } else {
            higher_round
        };
        core.advance_round(round, RoundExit::Certified, &mut Vec::new());
        let commands = core.handle(Event::LocalTimeout(round), 0);
        let timeout = commands
            .into_iter()
            .find_map(|command| match command {
                Command::Broadcast(ConsensusMessage::Timeout(timeout)) => Some(timeout),
                _ => None,
            })
            .expect("local timeout is broadcast");
        initial_timeouts.push(timeout);
    }

    // The lower round has only two signatures, so it cannot form a TC.
    for timeout in [initial_timeouts[0].clone(), initial_timeouts[2].clone()] {
        for core in &mut cores {
            let _ = core.handle(Event::RemoteTimeout(timeout.clone()), 0);
        }
    }
    assert_eq!(cores[0].round(), lower_round);
    assert_eq!(cores[2].round(), lower_round);
    assert_eq!(cores[1].round(), higher_round);
    assert_eq!(cores[3].round(), higher_round);

    // One future timeout is not enough to make any validator echo it.
    for core in &mut cores {
        let commands = core.handle(Event::RemoteTimeout(initial_timeouts[1].clone()), 0);
        assert!(
            !commands.iter().any(|command| matches!(
                command,
                Command::Broadcast(ConsensusMessage::Timeout(timeout))
                    if timeout.inner.round == higher_round
            )),
            "one future timeout must not pull a validator into its round: {commands:?}"
        );
    }

    // The second future timeout reaches weighted f+1 (=2 of 4). Only the
    // lower-round validators need to echo it, and their durable timeout
    // watermark must precede the broadcast.
    let mut echoes = Vec::new();
    for (index, core) in cores.iter_mut().enumerate() {
        let commands = core.handle(Event::RemoteTimeout(initial_timeouts[3].clone()), 0);
        let echo_index = commands.iter().position(|command| {
            matches!(
                command,
                Command::Broadcast(ConsensusMessage::Timeout(timeout))
                    if timeout.inner.round == higher_round
                        && timeout.inner.sender == core.me()
            )
        });
        if index % 2 == 0 {
            let echo_index =
                echo_index.expect("f+1 future timeouts must trigger a local timeout echo");
            let persist_index = commands
                .iter()
                .position(|command| {
                    matches!(
                        command,
                        Command::Persist(snapshot)
                            if snapshot.last_voted_round == higher_round
                    )
                })
                .expect("future timeout echo advances the durable vote watermark");
            assert!(
                persist_index < echo_index,
                "future timeout watermark must be durable before echo: {commands:?}"
            );
            let Command::Broadcast(ConsensusMessage::Timeout(echo)) = &commands[echo_index] else {
                unreachable!("echo index is a timeout broadcast")
            };
            echoes.push(echo.clone());
        } else {
            assert!(
                echo_index.is_none(),
                "a validator that already timed out the higher round must not echo twice"
            );
        }
    }
    assert_eq!(echoes.len(), 2);

    // Either echoed timeout is the third signature at the higher round.
    // Delivering the real core output forms the TC and converges all four
    // restored validators on the next round.
    for echo in echoes {
        for core in &mut cores {
            let _ = core.handle(Event::RemoteTimeout(echo.clone()), 0);
        }
    }
    for core in &cores {
        assert_eq!(
            core.round(),
            converged_round,
            "the split restart views must converge after the f+1 echo"
        );
    }
}

#[test]
fn local_timeout_for_current_round_broadcasts_timeout() {
    let (_kps, vset) = validators();
    let mut core = core_as(&vset, 0);
    // core starts in round 1; a LocalTimeout(1) should broadcast a Timeout.
    let out = core.handle(Event::LocalTimeout(Round(1)), 0);
    let bcast = out.iter().any(
            |c| matches!(c, Command::Broadcast(ConsensusMessage::Timeout(st)) if st.inner.round == Round(1)),
        );
    assert!(
        bcast,
        "expected Broadcast(Timeout) for round 1; got {out:?}"
    );

    // New contract: the core re-arms its own round timer with backed-off
    // duration, so hosts only deliver timers — they never re-arm.
    let cmds = &out;
    let round = Round(1);
    assert!(
        cmds.iter()
            .any(|c| matches!(c, Command::SetTimer(r2, _) if *r2 == round)),
        "local timeout must re-arm the round timer: {cmds:?}"
    );

    // A stale timer for a round we are not in is ignored.
    let out = core.handle(Event::LocalTimeout(Round(99)), 0);
    assert!(
        out.is_empty(),
        "stale LocalTimeout must be ignored; got {out:?}"
    );
}

#[test]
fn local_timeout_blocks_a_same_round_vote() {
    let (kps, vset) = validators();
    let leader = vset.leader(Round(1));
    let me_idx = kps
        .iter()
        .position(|key| key.node_id() != leader)
        .expect("non-leader validator");
    let mut core = core_as(&vset, me_idx);

    let _ = core.handle(Event::LocalTimeout(Round(1)), 0);
    let proposal = Proposal {
        block: block_round1(leader, b"late-round-1"),
        last_round_tc: None,
    };
    let out = core.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, leader), &proposal)),
        0,
    );

    assert!(
        !out.iter()
            .any(|command| matches!(command, Command::Send(_, ConsensusMessage::Vote(_)))),
        "a validator that timed out round 1 must not vote in round 1: {out:?}"
    );
}

#[test]
fn local_timeout_persists_the_vote_watermark_before_broadcast() {
    let (_kps, vset) = validators();
    let mut core = core_as(&vset, 0);

    let out = core.handle(Event::LocalTimeout(Round(1)), 0);
    let persist_index = out
        .iter()
        .position(|command| {
            matches!(
                command,
                Command::Persist(snapshot) if snapshot.last_voted_round == Round(1)
            )
        })
        .expect("timeout advances and persists the vote watermark");
    let timeout_index = out
        .iter()
        .position(|command| matches!(command, Command::Broadcast(ConsensusMessage::Timeout(_))))
        .expect("timeout is broadcast");

    assert!(
        persist_index < timeout_index,
        "the timeout watermark must be durable before its broadcast: {out:?}"
    );
}

// ---- (epoch-boundary safety): cross-epoch inbound guard ----

#[test]
fn proposal_from_wrong_epoch_is_dropped() {
    let (kps, vset) = validators();
    // any node as "me"; it will receive a round-1 proposal tagged epoch=1
    let mut core = core_as(&vset, 0);
    let leader = vset.leader(Round(1));
    let li = kps.iter().position(|k| k.node_id() == leader).unwrap();
    let mut b = block_round1(leader, b"x");
    b.epoch = 1; // wrong epoch (core is epoch 0)
    let prop = Proposal {
        block: b,
        last_round_tc: None,
    };
    let sig = kps[li].sign(Domain::Proposal, &borsh::to_vec(&prop).unwrap());
    let cmds = core.handle(Event::Proposal(Signed { inner: prop, sig }), 0);
    assert!(
        cmds.is_empty(),
        "a proposal from the wrong epoch must be dropped (no Commands)"
    );
}

// ---- (epoch-boundary safety): epoch-ending vote guard (anti-fork) ----

#[test]
fn epoch_ending_rejects_ordinary_blocks_past_plus_one() {
    let (kps, vset) = validators();
    // Pick a node and drive it to a state where it WOULD vote for a round-3
    // proposal, then assert the epoch-ending guard suppresses the vote.
    let mut core = core_as(&vset, 0);
    // Simulate "a reconfig block was certified at round 1". The locked
    // value is deliberately present, proving an ordinary proposal cannot
    // exploit the retry exception.
    let next = ValidatorSet::new(
        kps.iter()
            .take(3)
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect(),
    );
    let operator = Keypair::from_seed(999_999);
    core.pending_reconfig = Some(Reconfig {
        next_set: next.clone(),
        evidence: vec![],
        operator_sig: Some(operator.sign(
            Domain::Reconfig,
            &azbft_types::reconfig_signing_bytes(&next, 0),
        )),
        jail: None,
    });
    core.epoch_ending_round = Some(Round(1));

    // Build a round-3 proposal the core would otherwise act on: author it as
    // the real round-3 leader so the author/leader checks pass, and the only
    // thing standing between it and a Vote is the epoch-ending cap.
    let leader3 = vset.leader(Round(3));
    let l3i = kps.iter().position(|k| k.node_id() == leader3).unwrap();
    let mut b3 = block_round1(leader3, b"x");
    b3.round = Round(3);
    // Give it a valid TC for round 2 so it PASSES the round-proof (a
    // non-consecutive round needs a TC); otherwise the round-proof gate — not
    // the epoch-ending cap under test — would suppress the vote, making this
    // test vacuous.
    let tc2_sigs: Vec<(NodeId, Vec<u8>)> = kps
        .iter()
        .take(3)
        .map(|k| {
            (
                k.node_id(),
                k.sign(Domain::Timeout, &timeout_digest(0, Round(2)).0),
            )
        })
        .collect();
    let tc2 = TimeoutCert {
        round: Round(2),
        agg: SecpMultiSig::aggregate(&tc2_sigs),
        high_qc: QuorumCert::genesis(),
    };
    let prop = Proposal {
        block: b3,
        last_round_tc: Some(tc2),
    };
    let sig = kps[l3i].sign(Domain::Proposal, &borsh::to_vec(&prop).unwrap());
    let cmds = core.handle(Event::Proposal(Signed { inner: prop, sig }), 0);
    assert!(
        !cmds
            .iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "after a reconfig block at R0=1, an ordinary round-3 proposal must NOT be voted"
    );
}

#[test]
fn epoch_ending_votes_for_the_exact_locked_retry_after_timeout() {
    let (kps, vset) = validators();
    let mut core = core_as(&vset, 0);
    let next = ValidatorSet::new(
        kps.iter()
            .take(3)
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect(),
    );
    let operator = Keypair::from_seed(999_999);
    let locked = Reconfig {
        next_set: next.clone(),
        evidence: vec![],
        operator_sig: Some(operator.sign(
            Domain::Reconfig,
            &azbft_types::reconfig_signing_bytes(&next, 0),
        )),
        jail: None,
    };
    core.pending_reconfig = Some(locked.clone());
    core.epoch_ending_round = Some(Round(1));

    let leader3 = vset.leader(Round(3));
    let tc2_sigs: Vec<(NodeId, Vec<u8>)> = kps
        .iter()
        .take(3)
        .map(|key| {
            (
                key.node_id(),
                key.sign(Domain::Timeout, &timeout_digest(0, Round(2)).0),
            )
        })
        .collect();
    let proposal = Proposal {
        block: Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 1,
            timestamp_ms: 1,
            epoch: 0,
            round: Round(3),
            parent_qc: QuorumCert::genesis(),
            payload_hash: blake3_id(&b"locked-retry".to_vec()),
            author: leader3,
            reconfig: Some(locked),
        },
        last_round_tc: Some(TimeoutCert {
            round: Round(2),
            agg: SecpMultiSig::aggregate(&tc2_sigs),
            high_qc: QuorumCert::genesis(),
        }),
    };
    let commands = core.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, leader3), &proposal)),
        0,
    );
    assert!(
            commands
                .iter()
                .any(|command| matches!(command, Command::Send(_, ConsensusMessage::Vote(_)))),
            "the exact locked transition must remain live after the adjacent round timed out: {commands:?}"
        );
}

#[test]
fn timed_out_boundary_retry_produces_an_existing_wire_epoch_change_cert() {
    let (kps, vset) = validators();
    let me_idx = kps
        .iter()
        .position(|key| key.node_id() != vset.leader(Round(1)))
        .expect("a replica exists");
    let mut core = core_as(&vset, me_idx);
    let next = ValidatorSet::new(
        kps.iter()
            .take(3)
            .map(|key| (key.node_id(), key.pubkey_bytes(), 1u64))
            .collect(),
    );
    let operator = Keypair::from_seed(999_999);
    let locked = Reconfig {
        next_set: next.clone(),
        evidence: vec![],
        operator_sig: Some(operator.sign(
            Domain::Reconfig,
            &azbft_types::reconfig_signing_bytes(&next, 0),
        )),
        jail: None,
    };

    // R1: the first transition attempt obtains a QC.
    let first = make_reconfig_proposal(&kps, &vset, locked.clone(), b"first-boundary");
    let first_block = first.inner.block.clone();
    let first_delivery = core.handle(Event::Proposal(first), 1);
    assert!(first_delivery
        .iter()
        .any(|command| matches!(command, Command::Send(_, ConsensusMessage::Vote(_)))));
    let first_qc = qc_over(first_block.id(), Round(1), &kps);
    let mut first_qc_commands = Vec::new();
    assert!(core.process_qc(&first_qc, &mut first_qc_commands));
    assert_eq!(core.epoch_ending_round, Some(Round(1)));
    assert_eq!(core.pending_reconfig.as_ref(), Some(&locked));

    // R2 times out. R3 is justified by TC(R2), extends QC(R1), and carries
    // the exact same locked transition rather than an ordinary old-epoch block.
    let _ = core.handle(Event::LocalTimeout(Round(2)), 2);
    let timeout_signatures: Vec<(NodeId, Vec<u8>)> = kps
        .iter()
        .take(3)
        .map(|key| {
            (
                key.node_id(),
                key.sign(Domain::Timeout, &timeout_digest(0, Round(2)).0),
            )
        })
        .collect();
    let retry = Proposal {
        block: Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 2,
            timestamp_ms: 2,
            epoch: 0,
            round: Round(3),
            parent_qc: first_qc.clone(),
            payload_hash: blake3_id(&b"retry-boundary".to_vec()),
            author: vset.leader(Round(3)),
            reconfig: Some(locked.clone()),
        },
        last_round_tc: Some(TimeoutCert {
            round: Round(2),
            agg: SecpMultiSig::aggregate(&timeout_signatures),
            high_qc: first_qc,
        }),
    };
    let retry_block = retry.block.clone();
    let retry_delivery = core.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, retry.block.author), &retry)),
        2,
    );
    assert!(retry_delivery
        .iter()
        .any(|command| matches!(command, Command::Send(_, ConsensusMessage::Vote(_)))));
    let retry_qc = qc_over(retry_block.id(), Round(3), &kps);
    let mut retry_qc_commands = Vec::new();
    assert!(core.process_qc(&retry_qc, &mut retry_qc_commands));
    assert_eq!(core.epoch_ending_round, Some(Round(3)));

    // R4 is the adjacent commit vehicle for the retry. QC(R4) commits R3
    // through the unchanged two-chain rule. The original R1 transition is
    // an ancestor in the same commit batch, while R3 supplies an exact ECC.
    let child = Proposal {
        block: Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 3,
            timestamp_ms: 3,
            epoch: 0,
            round: Round(4),
            parent_qc: retry_qc,
            payload_hash: blake3_id(&b"retry-child".to_vec()),
            author: vset.leader(Round(4)),
            reconfig: Some(locked),
        },
        last_round_tc: None,
    };
    let child_block = child.block.clone();
    let child_delivery = core.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, child.block.author), &child)),
        3,
    );
    assert!(child_delivery
        .iter()
        .any(|command| matches!(command, Command::Send(_, ConsensusMessage::Vote(_)))));

    let commands = core.handle(
        Event::SyncApply {
            blocks: Vec::new(),
            commit_qc: qc_over(child_block.id(), Round(4), &kps),
        },
        3,
    );
    let inert = commands.iter().find_map(|command| match command {
        Command::Commit(committed) if committed.block.id() == first_block.id() => {
            Some(committed.two_chain)
        }
        _ => None,
    });
    assert_eq!(
        inert,
        Some(false),
        "the timed-out first attempt may become durable, but it is not the active boundary"
    );
    let exact = commands.iter().find_map(|command| match command {
        Command::Commit(committed)
            if committed.two_chain && committed.block.id() == retry_block.id() =>
        {
            Some(&committed.cert)
        }
        _ => None,
    });
    let exact = exact.expect("the retry must be the exact two-chain commit tail");
    let ecc = EpochChangeCert {
        reconfig_block: exact.block.clone(),
        child_block: exact.child.clone(),
        commit_qc: exact.commit_qc.clone(),
    };
    assert!(crate::verify_epoch_change_cert(&ecc, &vset, 0));
    assert!(
        commands.iter().all(|command| !matches!(
            command,
            Command::Send(_, _) | Command::Broadcast(_) | Command::CreatePayload { .. }
        )),
        "a batch that commits the transition must not publish old-epoch work: {commands:?}"
    );
}

#[test]
fn high_qc_block_is_the_certified_block() {
    let (kps, vset) = validators();
    let leader2 = vset.leader(Round(2));
    let me_idx = kps.iter().position(|k| k.node_id() == leader2).unwrap();
    let mut core = core_as(&vset, me_idx);

    let b1 = block_round1(vset.leader(Round(1)), b"payload-1");
    core.tree_insert_for_test(b1.clone());
    for k in kps.iter().take(3) {
        let vote = Vote {
            epoch: 0,
            block_id: b1.id(),
            round: Round(1),
            voter: k.node_id(),
        };
        let _ = core.handle(Event::Vote(sign_vote(k, &vote)), 0);
    }
    assert_eq!(core.high_qc().block_id, b1.id());
    assert_eq!(
        core.high_qc_block().expect("certified block in tree").id(),
        b1.id()
    );
}

#[test]
fn first_proposal_carries_staged_reconfig() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() == leader1).unwrap();
    let mut core = core_as(&vset, me_idx); // me = leader(1)
    let next = ValidatorSet::new(
        kps.iter()
            .take(3)
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect(),
    );
    let op = Keypair::from_seed(999_999);
    let sig = op.sign(
        Domain::Reconfig,
        &azbft_types::reconfig_signing_bytes(&next, 0),
    );
    let _ = core.handle(Event::RequestReconfig(next.clone(), sig), 0); // stage
    let _ = core.start();
    let out = handle_payload_ready(&mut core, Round(1), b"p".to_vec(), 0);
    let carried = out.iter().any(|c| {
        matches!(c,
            Command::Broadcast(ConsensusMessage::Proposal(sp))
                if sp.inner.block.reconfig.as_ref().map(|r| &r.next_set) == Some(&next))
    });
    assert!(
        carried,
        "the first proposal must carry the staged reconfiguration; got {out:?}"
    );
}

#[test]
fn uncertified_reconfig_proposal_keeps_pending_request_retryable() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps
        .iter()
        .position(|k| k.node_id() == leader1)
        .expect("round-1 leader belongs to the validator set");
    let mut core = core_as(&vset, me_idx);
    let next = ValidatorSet::new(
        kps.iter()
            .take(3)
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect(),
    );
    let operator = Keypair::from_seed(999_999);
    let signature = operator.sign(
        Domain::Reconfig,
        &azbft_types::reconfig_signing_bytes(&next, 0),
    );
    let _ = core.handle(Event::RequestReconfig(next.clone(), signature.clone()), 0);
    let _ = core.start();

    let first = handle_payload_ready(&mut core, Round(1), b"first-attempt".to_vec(), 0);
    let first_proposal = first
        .iter()
        .find_map(|command| match command {
            Command::Broadcast(ConsensusMessage::Proposal(proposal))
                if proposal.inner.block.reconfig.is_some() =>
            {
                Some(proposal.clone())
            }
            _ => None,
        })
        .expect("the first proposal carries the staged reconfiguration");

    assert!(
        core.pending_reconfig.is_some(),
        "building an uncertified proposal must retain the operator request"
    );
    let delivered = core.handle(Event::Proposal(first_proposal), 0);
    assert!(
        delivered
            .iter()
            .any(|command| matches!(command, Command::Send(_, ConsensusMessage::Vote(_)))),
        "the legal reconfiguration proposal must reach the vote path: {delivered:?}"
    );
    assert_eq!(
        core.epoch_ending_round, None,
        "seeing a legal proposal without its QC must not close the epoch"
    );
    assert!(
        core.pending_reconfig.is_some(),
        "an unconfirmed proposal must leave the request available for retry"
    );

    let retry = handle_payload_ready(&mut core, Round(1), b"retry-attempt".to_vec(), 0);
    assert!(
        retry.iter().any(|command| {
            matches!(
                command,
                Command::Broadcast(ConsensusMessage::Proposal(proposal))
                    if proposal
                        .inner
                        .block
                        .reconfig
                        .as_ref()
                        .map(|reconfig| &reconfig.next_set)
                        == Some(&next)
            )
        }),
        "the retained request must be available to a later proposal: {retry:?}"
    );
}

#[test]
fn only_certified_reconfig_sets_ending_guard_and_clears_pending() {
    let (kps, vset) = validators();
    let mut core = core_as(&vset, 0);
    let next = ValidatorSet::new(
        kps.iter()
            .take(3)
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect(),
    );
    let operator = Keypair::from_seed(999_999);
    let signature = operator.sign(
        Domain::Reconfig,
        &azbft_types::reconfig_signing_bytes(&next, 0),
    );
    let reconfig = Reconfig {
        next_set: next.clone(),
        evidence: Vec::new(),
        operator_sig: Some(signature.clone()),
        jail: None,
    };
    let proposal = make_reconfig_proposal(&kps, &vset, reconfig, b"certify-me");
    let reconfig_block = proposal.inner.block.clone();

    let _ = core.handle(Event::RequestReconfig(next, signature), 0);
    let delivered = core.handle(Event::Proposal(proposal), 0);
    assert!(
        delivered
            .iter()
            .any(|command| matches!(command, Command::Send(_, ConsensusMessage::Vote(_)))),
        "the authorized proposal must be accepted before certification: {delivered:?}"
    );
    assert_eq!(
        core.epoch_ending_round, None,
        "proposal acceptance alone must not close the epoch"
    );

    let unknown_qc = qc_over(blake3_id(&b"unknown-block".to_vec()), Round(1), &kps);
    let mut qc_out = Vec::new();
    assert!(core.process_qc(&unknown_qc, &mut qc_out));
    assert_eq!(
        core.epoch_ending_round, None,
        "a verified QC without a known reconfiguration block must not close the epoch"
    );
    assert!(
        core.pending_reconfig.is_some(),
        "a QC for an unknown block must not consume the pending request"
    );

    let certified_qc = qc_over(reconfig_block.id(), reconfig_block.round, &kps);
    assert!(core.process_qc(&certified_qc, &mut qc_out));
    assert_eq!(core.epoch_ending_round, Some(reconfig_block.round));
    assert_eq!(
        core.pending_reconfig.as_ref(),
        reconfig_block.reconfig.as_ref(),
        "certifying the transition must retain its exact value as the retry lock"
    );
}

#[test]
fn leader_reemits_locked_reconfig_once_epoch_is_ending() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() == leader1).unwrap();
    let mut core = core_as(&vset, me_idx);
    let next = ValidatorSet::new(
        kps.iter()
            .take(3)
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect(),
    );
    let op = Keypair::from_seed(999_999);
    let sig = op.sign(
        Domain::Reconfig,
        &azbft_types::reconfig_signing_bytes(&next, 0),
    );
    let _ = core.handle(Event::RequestReconfig(next, sig), 0);
    core.epoch_ending_round = Some(Round(1));
    let _ = core.start();
    let out = handle_payload_ready(&mut core, Round(1), b"p".to_vec(), 0);
    let carried = out.iter().any(|c| {
        matches!(c,
            Command::Broadcast(ConsensusMessage::Proposal(sp)) if sp.inner.block.reconfig.is_some())
    });
    assert!(
        carried,
        "an ending epoch must re-emit the locked reconfiguration until it commits; got {out:?}"
    );
}

// ---- Block sync application: SyncApply ----

fn qc_over(block_id: Hash, round: Round, kps: &[Keypair]) -> QuorumCert {
    let sigs: Vec<(NodeId, Vec<u8>)> = kps
        .iter()
        .take(3)
        .map(|k| {
            (
                k.node_id(),
                k.sign(Domain::Vote, &vote_digest(&block_id, round).0),
            )
        })
        .collect();
    QuorumCert {
        block_id,
        round,
        agg: SecpMultiSig::aggregate(&sigs),
    }
}

#[test]
fn live_ancestry_is_authenticated_atomic_and_does_not_advance_consensus() {
    let (keys, vset) = validators();
    let mut core = core_as(&vset, 0);
    let first = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 0,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: blake3_id(&b"ancestor-one".to_vec()),
        author: vset.leader(Round(1)),
        reconfig: None,
    };
    let second = Block {
        height: 2,
        timestamp_ms: 2,
        round: Round(2),
        parent_qc: qc_over(first.id(), first.round, &keys),
        author: vset.leader(Round(2)),
        ..first.clone()
    };
    let certificate = qc_over(second.id(), second.round, &keys);
    let before_round = core.round();
    let before_qc = core.high_qc().clone();
    let before_safety = core.safety_snapshot();
    let mut invalid = certificate.clone();
    invalid.agg = QuorumCert::genesis().agg;
    assert!(core
        .import_live_ancestors(&[first.clone(), second.clone()], &invalid)
        .is_err());
    assert!(
        !core.contains_block(&first.id()),
        "failed import must be atomic"
    );
    assert!(core
        .import_live_ancestors(std::slice::from_ref(&second), &certificate)
        .is_err());
    assert!(core.import_live_ancestors(&[], &certificate).is_err());
    assert!(core
        .import_live_ancestors(&vec![first.clone(); 65], &certificate)
        .is_err());
    let mut oversized = vec![first.clone()];
    for round in 2..=65 {
        let parent = oversized.last().unwrap();
        oversized.push(Block {
            height: round,
            timestamp_ms: round,
            round: Round(round),
            parent_qc: qc_over(parent.id(), parent.round, &keys),
            author: vset.leader(Round(round)),
            ..first.clone()
        });
    }
    let oversized_qc = qc_over(oversized.last().unwrap().id(), Round(65), &keys);
    assert!(core
        .import_live_ancestors(&oversized, &oversized_qc)
        .is_err());
    let mut wrong_height = second.clone();
    wrong_height.height += 1;
    let signed_wrong_height = qc_over(wrong_height.id(), wrong_height.round, &keys);
    assert!(core
        .import_live_ancestors(&[first.clone(), wrong_height], &signed_wrong_height)
        .is_err());
    let mut wrong_round = second.clone();
    wrong_round.round = first.round;
    wrong_round.author = first.author;
    let signed_wrong_round = qc_over(wrong_round.id(), wrong_round.round, &keys);
    assert!(core
        .import_live_ancestors(&[first.clone(), wrong_round], &signed_wrong_round)
        .is_err());
    assert!(!core.contains_block(&first.id()));
    core.import_live_ancestors(&[first.clone(), second.clone()], &certificate)
        .unwrap();
    assert!(core.contains_block(&first.id()));
    assert!(core.contains_block(&second.id()));
    assert_eq!(core.round(), before_round);
    assert_eq!(core.high_qc(), &before_qc);
    assert_eq!(core.safety_snapshot(), before_safety);
    assert_eq!(core.tree.last_committed_round(), 0);
    assert_eq!(
        core.live_ancestors(second.id(), 2),
        vec![first.clone(), second.clone()]
    );
    assert_eq!(core.live_ancestors(second.id(), 1), vec![second.clone()]);
    let mut bad_anchor = second.clone();
    bad_anchor.parent_qc.agg = QuorumCert::genesis().agg;
    let bad_anchor_id = bad_anchor.id();
    let signed_bad_anchor = qc_over(bad_anchor_id, bad_anchor.round, &keys);
    assert!(core
        .import_live_ancestors(&[bad_anchor], &signed_bad_anchor)
        .is_err());
    assert!(!core.contains_block(&bad_anchor_id));
    let mut wrong_anchor_round = second.clone();
    wrong_anchor_round.round = Round(4);
    wrong_anchor_round.author = vset.leader(Round(4));
    wrong_anchor_round.parent_qc = qc_over(first.id(), Round(2), &keys);
    let wrong_anchor_id = wrong_anchor_round.id();
    let signed_wrong_anchor = qc_over(wrong_anchor_id, Round(4), &keys);
    assert!(core
        .import_live_ancestors(&[wrong_anchor_round], &signed_wrong_anchor)
        .is_err());
    assert!(!core.contains_block(&wrong_anchor_id));
    core.import_live_ancestors(&[first.clone(), second.clone()], &certificate)
        .unwrap();
    assert_eq!(core.tree.last_committed_round(), 0);
    let mut committed = Vec::new();
    assert!(core.process_qc(&certificate, &mut committed));
    let commit = committed
        .iter()
        .find_map(|command| match command {
            Command::Commit(entry) => Some(entry),
            _ => None,
        })
        .expect("normal QC processing commits the certified parent");
    assert_eq!(commit.block.id(), first.id());
    assert!(core
        .import_live_ancestors(&[first.clone(), second.clone()], &certificate)
        .is_err());
    core.import_live_ancestors(std::slice::from_ref(&second), &certificate)
        .unwrap();
    let mut repeated = Vec::new();
    assert!(core.process_qc(&certificate, &mut repeated));
    assert!(!repeated
        .iter()
        .any(|command| matches!(command, Command::Commit(_))));
    let mut restored = core_as(&vset, 0).with_chain_anchor(ChainAnchorV2::from_block(&first));
    restored
        .restore_committed_tip(&CommitCert {
            block: first,
            child: second.clone(),
            commit_qc: certificate.clone(),
        })
        .unwrap();
    let restored_safety = restored.safety_snapshot();
    restored
        .import_live_ancestors(std::slice::from_ref(&second), &certificate)
        .unwrap();
    assert_eq!(restored.safety_snapshot(), restored_safety);
    let mut after_restart = Vec::new();
    assert!(restored.process_qc(&certificate, &mut after_restart));
    assert!(!after_restart
        .iter()
        .any(|command| matches!(command, Command::Commit(_))));
}

#[test]
fn sync_apply_ingests_and_commits_tip() {
    let (kps, vset) = validators();
    let mut core = core_as(&vset, 0);
    let b1 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 0,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: blake3_id(&b"s1".to_vec()),
        author: vset.leader(Round(1)),
        reconfig: None,
    };
    let b2 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 2,
        timestamp_ms: 2,
        epoch: 0,
        round: Round(2),
        parent_qc: qc_over(b1.id(), Round(1), &kps),
        payload_hash: blake3_id(&b"s2".to_vec()),
        author: vset.leader(Round(2)),
        reconfig: None,
    };
    let qc_b2 = qc_over(b2.id(), Round(2), &kps);
    let out = core.handle(
        Event::SyncApply {
            blocks: vec![b1.clone(), b2.clone()],
            commit_qc: qc_b2,
        },
        0,
    );
    assert!(
        out.iter()
            .any(|c| matches!(c, Command::Commit(cb) if cb.block.id() == b1.id())),
        "SyncApply must commit b1 through the two-chain rule; got {out:?}"
    );
    assert_eq!(core.high_qc().block_id, b2.id());
}

/// Every `Command::Commit` carries a linked commit certificate
/// assembled from the triggering QC inside `process_qc` — never
/// reconstructed from `high_qc` after the fact. Drives a 3-block commit and
/// checks each cert links (`child.parent_qc` certifies `block`, `commit_qc`
/// certifies `child`), that only the batch tail is a real 2-chain that
/// `verify_commit_cert` accepts, and — the anti-regression anchor — that the
/// tail's `commit_qc` is the *triggering* QC (round 4), NOT the higher,
/// stale `high_qc` (round 40) still pinned on the core. A future refactor
/// that rebuilds the cert from core state would put the round-40 QC in
/// `commit_qc` and fail the final assertion.
#[test]
fn commit_commands_carry_linked_certs() {
    let (kps, vset) = validators();
    let mut core = core_as(&vset, 0);

    // (1) Pin high_qc to a stale, HIGHER-round QC over a block absent from
    //     the tree: it verifies (round != 0, valid agg) but commits nothing.
    let unknown = blake3_id(&b"unknown-r40".to_vec());
    let qc_x = qc_over(unknown, Round(40), &kps);
    let mut scratch = Vec::new();
    core.process_qc(&qc_x, &mut scratch);
    assert_eq!(
        core.high_qc().round,
        Round(40),
        "setup: high_qc pinned at 40"
    );

    // (2) Four adjacent-round blocks b1←b2←b3←b4 (rounds 1..=4).
    let b1 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 0,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: blake3_id(&b"e1".to_vec()),
        author: vset.leader(Round(1)),
        reconfig: None,
    };
    let b2 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 2,
        timestamp_ms: 2,
        epoch: 0,
        round: Round(2),
        parent_qc: qc_over(b1.id(), Round(1), &kps),
        payload_hash: blake3_id(&b"e2".to_vec()),
        author: vset.leader(Round(2)),
        reconfig: None,
    };
    let b3 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 3,
        timestamp_ms: 3,
        epoch: 0,
        round: Round(3),
        parent_qc: qc_over(b2.id(), Round(2), &kps),
        payload_hash: blake3_id(&b"e3".to_vec()),
        author: vset.leader(Round(3)),
        reconfig: None,
    };
    let b4 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 4,
        timestamp_ms: 4,
        epoch: 0,
        round: Round(4),
        parent_qc: qc_over(b3.id(), Round(3), &kps),
        payload_hash: blake3_id(&b"e4".to_vec()),
        author: vset.leader(Round(4)),
        reconfig: None,
    };
    let commit_qc = qc_over(b4.id(), Round(4), &kps);

    // (3) SyncApply ingests b1..=b4 then process_qc(commit_qc).
    //     update_on_qc(b4) targets b3 (adjacent parent); tree.commit(b3)
    //     yields [b1,b2,b3] since nothing was committed yet ⇒ 3-block batch.
    let out = core.handle(
        Event::SyncApply {
            blocks: vec![b1.clone(), b2.clone(), b3.clone(), b4.clone()],
            commit_qc: commit_qc.clone(),
        },
        0,
    );

    let committed: Vec<_> = out
        .iter()
        .filter_map(|c| match c {
            Command::Commit(cb) => Some(cb),
            _ => None,
        })
        .collect();
    assert_eq!(
        committed.iter().map(|cb| cb.block.id()).collect::<Vec<_>>(),
        vec![b1.id(), b2.id(), b3.id()],
        "3-block commit chain, ancestors-first; got {out:?}"
    );

    // Every cert links structurally: `commit_qc` certifies `child`,
    // `child.parent_qc` certifies `block`, and `cert.block` is the committed
    // block.
    for cb in &committed {
        assert_eq!(cb.cert.block.id(), cb.block.id(), "cert.block == committed");
        assert_eq!(
            cb.cert.commit_qc.block_id,
            cb.cert.child.id(),
            "commit_qc certifies child"
        );
        assert_eq!(
            cb.cert.child.parent_qc.block_id,
            cb.cert.block.id(),
            "child.parent_qc certifies block"
        );
    }

    // Only the batch tail is a real (adjacent-round) 2-chain.
    assert!(
        !committed[0].two_chain && !committed[1].two_chain,
        "middle blocks carry linkage-level certs, not 2-chain"
    );
    let tail = committed[2];
    assert!(tail.two_chain, "batch tail is a real 2-chain");
    assert!(
        crate::verify_commit_cert(&tail.cert, &vset),
        "tail cert must verify as a 2-chain commit"
    );

    // Anti-regression: the tail cert's commit_qc is the *triggering* QC
    // (round 4), NOT the stale high_qc (round 40) — which is unchanged.
    assert_eq!(
        tail.cert.commit_qc, commit_qc,
        "tail commit_qc == triggering QC"
    );
    assert_eq!(tail.cert.commit_qc.round, Round(4));
    assert_ne!(tail.cert.commit_qc, qc_x, "must NOT be the stale high_qc");
    assert_eq!(
        core.high_qc().round,
        Round(40),
        "high_qc still stale — commit did not read it"
    );
}

#[test]
fn sync_apply_rejects_wrong_epoch_blocks() {
    let (kps, vset) = validators();
    let mut core = core_as(&vset, 0); // epoch 0
    let mut b1 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 1,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: blake3_id(&b"w1".to_vec()),
        author: vset.leader(Round(1)),
        reconfig: None,
    };
    let _ = &mut b1;
    let qc = qc_over(b1.id(), Round(1), &kps);
    let out = core.handle(
        Event::SyncApply {
            blocks: vec![b1],
            commit_qc: qc,
        },
        0,
    );
    assert!(
        out.is_empty(),
        "wrong-epoch SyncApply must be rejected (no commit); got {out:?}"
    );
}

// ---- Crash safety: SafetySnapshot + Command::Persist prepend + restore ----

use crate::command::SafetySnapshot;

/// Build a core with the given identity, optionally restoring safety state.
/// `me_idx` selects the validator (seeds `1..=4`, so seed `1 + me_idx`).
fn core_restored(
    vset: &ValidatorSet,
    me_idx: usize,
    restored: Option<(Round, Round)>,
) -> ConsensusCore {
    let signer = TestSigner(Keypair::from_seed(1 + me_idx as u64));
    let operator_pk = Keypair::from_seed(999_999).pubkey_bytes();
    ConsensusCore::with_signer_restored(
        0,
        vset.clone(),
        100,
        Box::new(signer),
        restored,
        operator_pk,
    )
}
#[test]
fn durable_tip_restores_tree_high_qc_and_start_round() {
    let (kps, vset) = validators();
    let b4 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 4,
        timestamp_ms: 4,
        epoch: 0,
        round: Round(4),
        parent_qc: QuorumCert::genesis(),
        payload_hash: blake3_id(&b"restart-b4".to_vec()),
        author: vset.leader(Round(4)),
        reconfig: None,
    };
    let b5 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 5,
        timestamp_ms: 5,
        epoch: 0,
        round: Round(5),
        parent_qc: qc_over(b4.id(), Round(4), &kps),
        payload_hash: blake3_id(&b"restart-b5".to_vec()),
        author: vset.leader(Round(5)),
        reconfig: None,
    };
    let commit_qc = qc_over(b5.id(), Round(5), &kps);
    let cert = CommitCert {
        block: b4.clone(),
        child: b5.clone(),
        commit_qc: commit_qc.clone(),
    };
    let start_round = Round(7);
    let me = vset.leader(start_round);
    let me_idx = kps.iter().position(|kp| kp.node_id() == me).unwrap();
    let mut core = core_restored(&vset, me_idx, Some((Round(6), Round(4))))
        .with_chain_anchor(ChainAnchorV2::from_block(&b4));

    core.restore_committed_tip(&cert)
        .expect("valid durable tip");

    assert_eq!(core.round(), start_round);
    assert_eq!(core.high_qc(), &commit_qc);
    assert!(core.contains_block(&b4.id()));
    assert!(core.contains_block(&b5.id()));
    assert_eq!(core.high_qc_block(), Some(b5));
    let commands = core.start();
    assert!(commands
        .iter()
        .any(|command| matches!(command, Command::SetTimer(round, _) if *round == start_round)));
    assert!(commands.iter().any(|command| matches!(
        command,
        Command::CreatePayload { round, parent }
            if *round == start_round && parent == &commit_qc
    )));
}

#[test]
fn durable_tip_rejects_an_invalid_certificate_without_mutating_core() {
    let (kps, vset) = validators();
    let b1 = block_round1(vset.leader(Round(1)), b"restart-invalid-b1");
    let b2 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 2,
        timestamp_ms: 2,
        epoch: 0,
        round: Round(2),
        parent_qc: qc_over(b1.id(), Round(1), &kps),
        payload_hash: blake3_id(&b"restart-invalid-b2".to_vec()),
        author: vset.leader(Round(2)),
        reconfig: None,
    };
    let mut bad_qc = qc_over(b2.id(), Round(2), &kps);
    bad_qc.block_id = blake3_id(&b"not-b2".to_vec());
    let cert = CommitCert {
        block: b1.clone(),
        child: b2,
        commit_qc: bad_qc,
    };
    let mut core = core_restored(&vset, 0, Some((Round(3), Round(1))))
        .with_chain_anchor(ChainAnchorV2::from_block(&b1));

    assert!(core.restore_committed_tip(&cert).is_err());
    assert_eq!(core.round(), Round(1));
    assert_eq!(core.high_qc(), &QuorumCert::genesis());
    assert!(!core.contains_block(&b1.id()));
}

/// Extract the `SafetySnapshot` from a `Command::Persist` in a batch (if any).
fn persist_snapshot(cmds: &[Command]) -> Option<SafetySnapshot> {
    cmds.iter().find_map(|c| match c {
        Command::Persist(snap) => Some(snap.clone()),
        _ => None,
    })
}

fn has_vote(cmds: &[Command]) -> bool {
    cmds.iter()
        .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_))))
}

/// When a `handle()` call changes the safety state, `Command::Persist(snap)`
/// is prepended (index 0) with the new snapshot, and the dependent Vote is
/// sequenced after it. A subsequent event that changes nothing emits no
/// Persist.
#[test]
fn prepend_persist_iff_safety_changed() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    // `me` is a replica (not the round-1 leader), so it votes on the proposal.
    let me_idx = kps
        .iter()
        .position(|k| k.node_id() != leader1)
        .expect("a non-leader exists");
    let mut core = core_restored(&vset, me_idx, None);

    let b = block_round1(leader1, b"payload-1");
    let prop = Proposal {
        block: b.clone(),
        last_round_tc: None,
    };
    let signed = sign_proposal(kp_of(&kps, leader1), &prop);

    let out = core.handle(Event::Proposal(signed), 0);

    // Voting set last_voted_round = R(1) -> safety changed -> Persist prepended.
    match &out[0] {
        Command::Persist(snap) => {
            assert_eq!(
                snap.last_voted_round,
                Round(1),
                "prepended snapshot must record the round just voted"
            );
            assert_eq!(snap.epoch, 0);
            assert_eq!(snap.preferred_round, Round(0));
        }
        other => panic!("cmds[0] must be Command::Persist; got {other:?}"),
    }
    // The Vote must appear *after* the prepended Persist.
    let persist_at = 0usize;
    let vote_at = out
        .iter()
        .position(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_))))
        .expect("a Vote must be emitted");
    assert!(
        vote_at > persist_at,
        "Vote must be sequenced after the Persist; got {out:?}"
    );
    // Exactly one Persist, and it is at the front.
    assert_eq!(
        out.iter()
            .filter(|c| matches!(c, Command::Persist(_)))
            .count(),
        1
    );

    // A second event that does NOT change safety state -> no Persist.
    // Re-feeding the same round-1 proposal: make_vote returns None (round
    // <= last_voted_round), so neither last_voted nor preferred move.
    let signed_again = sign_proposal(kp_of(&kps, leader1), &prop);
    let out2 = core.handle(Event::Proposal(signed_again), 0);
    assert!(
        persist_snapshot(&out2).is_none(),
        "no safety change must emit no Persist; got {out2:?}"
    );
    assert!(
        !has_vote(&out2),
        "the re-fed proposal must not be voted again; got {out2:?}"
    );
}

/// Command scheduling: a proposal may both commit its certified grandparent and make
/// this replica vote for the proposal itself. The safety snapshot must be
/// durable first, but the vote and its timer do not depend on the local
/// append of that already-certified ancestor.
///
/// This is deliberately an ordering assertion, not just a presence check:
/// the earlier command ordering emitted Commit before Send(Vote), so this
/// test is the red proof for the latency-critical contract being changed.
#[test]
fn persist_then_vote_precedes_coemitted_commit() {
    let (kps, vset) = validators();
    let leader3 = vset.leader(Round(3));
    let me_idx = kps
        .iter()
        .position(|k| k.node_id() != leader3)
        .expect("a non-leader replica exists");
    let mut core = core_restored(&vset, me_idx, None);

    let b1 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 0,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: blake3_id(&b"persist-order-b1".to_vec()),
        author: vset.leader(Round(1)),
        reconfig: None,
    };
    let b2 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 2,
        timestamp_ms: 2,
        epoch: 0,
        round: Round(2),
        parent_qc: qc_over(b1.id(), Round(1), &kps),
        payload_hash: blake3_id(&b"persist-order-b2".to_vec()),
        author: vset.leader(Round(2)),
        reconfig: None,
    };
    let b3 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 3,
        timestamp_ms: 3,
        epoch: 0,
        round: Round(3),
        parent_qc: qc_over(b2.id(), Round(2), &kps),
        payload_hash: blake3_id(&b"persist-order-b3".to_vec()),
        author: leader3,
        reconfig: None,
    };
    core.tree_insert_for_test(b1.clone());
    core.tree_insert_for_test(b2);

    let proposal = Proposal {
        block: b3,
        last_round_tc: None,
    };
    let out = core.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, leader3), &proposal)),
        0,
    );

    assert!(matches!(out.first(), Some(Command::Persist(_))), "{out:?}");
    let vote_at = out
        .iter()
        .position(|command| matches!(command, Command::Send(_, ConsensusMessage::Vote(_))))
        .expect("proposal must emit a vote");
    let commit_at = out
            .iter()
            .position(|command| {
                matches!(command, Command::Commit(committed) if committed.block.id() == b1.id())
            })
            .expect("proposal parent QC must commit b1");
    let timer_positions: Vec<usize> = out
        .iter()
        .enumerate()
        .filter_map(|(index, command)| matches!(command, Command::SetTimer(_, _)).then_some(index))
        .collect();

    assert!(
        timer_positions.iter().all(|index| *index < vote_at),
        "vote timers must be armed before outbound vote; got {out:?}"
    );
    assert!(
        vote_at < commit_at,
        "durable safety must precede Vote, but ancestor Commit must not delay Vote; got {out:?}"
    );
}

/// A1 — cross-crash no-double-vote: a core restored with `last_voted_round =
/// R` refuses to vote for a proposal at round R (rule ① monotone). Contrast:
/// a fresh core (`with_signer`, no restore) DOES vote for it — proving the
/// restored watermark is what blocks the re-vote.
#[test]
fn no_double_vote_after_restore() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps
        .iter()
        .position(|k| k.node_id() != leader1)
        .expect("a non-leader exists");

    let b = block_round1(leader1, b"payload-1");
    let prop = Proposal {
        block: b.clone(),
        last_round_tc: None,
    };

    // Core 1 votes for Proposal@R(1); capture the persisted snapshot.
    let mut core1 = core_restored(&vset, me_idx, None);
    let out1 = core1.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, leader1), &prop)),
        0,
    );
    let snap = persist_snapshot(&out1).expect("voting must persist a snapshot");
    assert_eq!(snap.last_voted_round, Round(1));

    // Core 2 restored from that snapshot: same identity, last_voted = R(1).
    let mut core2 = core_restored(
        &vset,
        me_idx,
        Some((snap.last_voted_round, snap.preferred_round)),
    );
    let out2 = core2.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, leader1), &prop)),
        0,
    );
    assert!(
        !has_vote(&out2),
        "restored core (last_voted=R) must NOT re-vote for Proposal@R; got {out2:?}"
    );
    // It also emits no Persist (no safety change happened).
    assert!(persist_snapshot(&out2).is_none());

    // Contrast: a FRESH core (no restore) DOES vote for the same proposal,
    // proving that restoration — not some other guard — is what blocked it.
    let mut fresh = core_restored(&vset, me_idx, None);
    let out_fresh = fresh.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, leader1), &prop)),
        0,
    );
    assert!(
        has_vote(&out_fresh),
        "a fresh (un-restored) core MUST vote for Proposal@R; got {out_fresh:?}"
    );
}

/// A2 — cross-crash no-lock-break: a core whose `preferred_round` was raised
/// to P (via processing a QC), then restored from that snapshot, refuses to
/// vote for a proposal whose `parent_qc.round < P` (rule ② lock).
#[test]
fn no_lock_break_after_restore() {
    let (kps, vset) = validators();
    // Collector = leader(2), so feeding round-1 votes forms QC(b1) and runs
    // process_qc, which raises preferred_round to b1.parent_qc.round... which
    // is genesis (0). To get a non-trivial lock we drive a 2-block chain via
    // SyncApply: committing QC(b2) calls update_on_qc(b2) -> preferred = 1.
    let me_idx = 0usize;
    let mut core = core_restored(&vset, me_idx, None);

    let b1 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 0,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: blake3_id(&b"l1".to_vec()),
        author: vset.leader(Round(1)),
        reconfig: None,
    };
    let b2 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 2,
        timestamp_ms: 2,
        epoch: 0,
        round: Round(2),
        parent_qc: qc_over(b1.id(), Round(1), &kps),
        payload_hash: blake3_id(&b"l2".to_vec()),
        author: vset.leader(Round(2)),
        reconfig: None,
    };
    let qc_b2 = qc_over(b2.id(), Round(2), &kps);
    let out = core.handle(
        Event::SyncApply {
            blocks: vec![b1.clone(), b2.clone()],
            commit_qc: qc_b2,
        },
        0,
    );
    // The lock raise (preferred_round 0 -> 1) is a safety change, so the
    // batch is prepended with a Persist carrying preferred_round = P = 1.
    let snap = persist_snapshot(&out).expect("lock raise must persist a snapshot");
    let p = snap.preferred_round;
    assert_eq!(p, Round(1), "preferred_round should have risen to 1");

    // Restore a core from `Some((_, P))`: last_voted fresh (0), preferred = P.
    // Feed a proposal whose parent_qc.round (0) < P (1): rule ② must block it.
    // Author it at the valid consecutive round 1 (> last_voted 0) so rule ①
    // and the round-proof are NOT the blockers.
    let mut restored = core_restored(&vset, me_idx, Some((Round(0), p)));
    let leader1 = vset.leader(Round(1));
    let b3 = block_round1(leader1, b"l3"); // parent_qc.round = 0 < P = 1
    let prop3 = Proposal {
        block: b3,
        last_round_tc: None,
    };
    let out3 = restored.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, leader1), &prop3)),
        0,
    );
    assert!(
        !has_vote(&out3),
        "restored core (preferred=P) must NOT vote for parent_qc.round < P; got {out3:?}"
    );
}

// ---- equivocation detection: equivocation detection in on_vote ----

/// Helper: extract an EquivocationProof from a command batch (if any).
fn find_equivocation(cmds: &[Command]) -> Option<azbft_types::evidence::EquivocationProof> {
    cmds.iter().find_map(|c| match c {
        Command::Equivocation(p) => Some(p.clone()),
        _ => None,
    })
}

/// Basic equivocation detection — one voter, two conflicting block_ids,
/// same (epoch, round). The proof must be emitted and must verify.
#[test]
fn equivocation_detected_emits_proof() {
    let (kps, vset) = validators();
    let leader2 = vset.leader(Round(2));
    // Collector is the round-2 leader.
    let me_idx = kps.iter().position(|k| k.node_id() == leader2).unwrap();
    let mut core = core_as(&vset, me_idx);

    // Pick any validator (not the collector itself) as the equivocator.
    let equivocator_kp = kps.iter().find(|k| k.node_id() != leader2).unwrap();
    let equivocator = equivocator_kp.node_id();

    let block_a = blake3_id(&b"block-a".to_vec());
    let block_b = blake3_id(&b"block-b".to_vec());
    // Ensure they are genuinely different (blake3 of distinct inputs — they are).
    assert_ne!(block_a, block_b);

    // Vote 1: vote for block_a.
    let vote_a = Vote {
        epoch: 0,
        block_id: block_a,
        round: Round(1),
        voter: equivocator,
    };
    let sv_a = sign_vote(equivocator_kp, &vote_a);
    let out1 = core.handle(Event::Vote(sv_a), 0);
    // First vote: no equivocation yet.
    assert!(
        find_equivocation(&out1).is_none(),
        "first vote must not emit equivocation; got {out1:?}"
    );

    // Vote 2: same voter, same round, DIFFERENT block_id → equivocation.
    let vote_b = Vote {
        epoch: 0,
        block_id: block_b,
        round: Round(1),
        voter: equivocator,
    };
    let sv_b = sign_vote(equivocator_kp, &vote_b);
    let out2 = core.handle(Event::Vote(sv_b), 0);
    let proof =
        find_equivocation(&out2).expect("second conflicting vote must emit Command::Equivocation");
    assert!(
        crate::evidence::verify_equivocation_proof(&proof, &vset),
        "emitted proof must verify against the validator set"
    );
}

/// Adversarial-order test — form the QC first, then feed the
/// equivocator's (late) vote. Proves that the verify-hoist is necessary:
/// under the old ordering the late vote would be skipped by `qc_formed`
/// early-return and the equivocation would be silently missed.
#[test]
fn equivocation_detected_under_adversarial_order() {
    let (kps, vset) = validators();
    let leader2 = vset.leader(Round(2));
    let me_idx = kps.iter().position(|k| k.node_id() == leader2).unwrap();
    let mut core = core_as(&vset, me_idx);

    // Build block X at round 1.
    let block_x = blake3_id(&b"block-x".to_vec());
    let block_y = blake3_id(&b"block-y".to_vec());
    assert_ne!(block_x, block_y);

    // Choose the equivocator as any validator not among the first-three (i.e.
    // outside the quorum that will form the QC for block X). We need at least
    // 4 validators (3 for quorum + 1 equivocator); our fixture has exactly 4.
    // The quorum voters are kps[0..3]; take a non-leader-2 from them for the
    // equivocator. Actually pick kps[3] as the equivocator and kps[0..3] for
    // the QC (kps[3] is one of the quorum members but we'll also use it to
    // equivocate — that's fine, it just makes the QC include its vote for X,
    // and the equivocation proof will carry its conflicting vote for Y).
    //
    // Simpler: use the first 3 validators (by index) to form the QC for X,
    // then feed the 4th validator's vote for X (first) and Y (second).
    // With 4 validators at stake=1 each and quorum=3, the QC forms after 3.
    let equivocator_kp = kps.iter().find(|k| k.node_id() != leader2).unwrap();
    let equivocator = equivocator_kp.node_id();

    // Use the OTHER 3 validators (not the equivocator) to form the QC for X.
    // We insert b1_actual into the tree so process_qc can commit against it.
    let b1_actual = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 0,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: blake3_id(&b"payload-x".to_vec()),
        author: vset.leader(Round(1)),
        reconfig: None,
    };
    core.tree_insert_for_test(b1_actual.clone());
    let block_x_id = b1_actual.id();
    let block_y_id = {
        // A genuinely different hash.
        let h = blake3_id(&b"block-y-distinct".to_vec());
        // Make sure it's different from block_x_id.
        if h == block_x_id {
            blake3_id(&b"block-y-alt".to_vec())
        } else {
            h
        }
    };

    // Feed votes for X from the 3 validators that are NOT the equivocator,
    // until the QC forms (quorum = 3, all stakes = 1).
    let non_equivocators: Vec<&Keypair> = kps
        .iter()
        .filter(|k| k.node_id() != equivocator)
        .take(3)
        .collect();
    for kp in &non_equivocators {
        let v = Vote {
            epoch: 0,
            block_id: block_x_id,
            round: Round(1),
            voter: kp.node_id(),
        };
        let sv = sign_vote(kp, &v);
        let _out = core.handle(Event::Vote(sv), 0);
    }
    // QC for block_x should have formed and advanced the round.
    assert!(
        core.high_qc().block_id == block_x_id,
        "QC for block_x must have formed"
    );
    assert!(
        core.qc_formed.contains_key(&(Round(1), block_x_id)),
        "qc_formed must be set for (round=1, block_x)"
    );

    // A late first vote must still enter equivocation tracking after the QC
    // for its block has formed.
    let ev_x = Vote {
        epoch: 0,
        block_id: block_x_id,
        round: Round(1),
        voter: equivocator,
    };
    let sv_x = sign_vote(equivocator_kp, &ev_x);
    let out_x = core.handle(Event::Vote(sv_x), 0);
    assert!(
        find_equivocation(&out_x).is_none(),
        "first (late) vote for X must not yet trigger equivocation; got {out_x:?}"
    );

    // A conflicting second vote now yields an equivocation proof.
    let ev_y = Vote {
        epoch: 0,
        block_id: block_y_id,
        round: Round(1),
        voter: equivocator,
    };
    let sv_y = sign_vote(equivocator_kp, &ev_y);
    let out_y = core.handle(Event::Vote(sv_y), 0);
    let proof = find_equivocation(&out_y).expect(
        "late conflicting vote must still trigger Command::Equivocation even after qc_formed",
    );
    assert!(
        crate::evidence::verify_equivocation_proof(&proof, &vset),
        "late-detected proof must verify"
    );
}

/// Honest validators (each voter votes at most once per round) must
/// never trigger equivocation detection.
#[test]
fn honest_votes_never_equivocate() {
    let (kps, vset) = validators();
    let leader2 = vset.leader(Round(2));
    let me_idx = kps.iter().position(|k| k.node_id() == leader2).unwrap();
    let mut core = core_as(&vset, me_idx);

    let block_id = blake3_id(&b"honest-block".to_vec());

    // Each validator votes exactly once for the same block.
    let mut all_cmds: Vec<Command> = Vec::new();
    for kp in &kps {
        let v = Vote {
            epoch: 0,
            block_id,
            round: Round(1),
            voter: kp.node_id(),
        };
        let mut out = core.handle(Event::Vote(sign_vote(kp, &v)), 0);
        all_cmds.append(&mut out);
    }
    assert!(
            all_cmds.iter().all(|c| !matches!(c, Command::Equivocation(_))),
            "honest pattern (one vote per voter per round) must never emit Equivocation; got {all_cmds:?}"
        );
}

/// Feeding the identical vote twice (same voter, same block_id, same
/// sig) must NOT produce an equivocation proof (it's a duplicate, not a
/// double-sign).
#[test]
fn duplicate_same_vote_no_proof() {
    let (kps, vset) = validators();
    let leader2 = vset.leader(Round(2));
    let me_idx = kps.iter().position(|k| k.node_id() == leader2).unwrap();
    let mut core = core_as(&vset, me_idx);

    let voter_kp = kps.iter().find(|k| k.node_id() != leader2).unwrap();
    let block_id = blake3_id(&b"dup-block".to_vec());
    let v = Vote {
        epoch: 0,
        block_id,
        round: Round(1),
        voter: voter_kp.node_id(),
    };
    let sv = sign_vote(voter_kp, &v);

    // Feed the SAME signed vote twice.
    let out1 = core.handle(Event::Vote(sv.clone()), 0);
    let out2 = core.handle(Event::Vote(sv), 0);
    assert!(
        find_equivocation(&out1).is_none(),
        "first delivery of a vote must not emit Equivocation; got {out1:?}"
    );
    assert!(
        find_equivocation(&out2).is_none(),
        "duplicate (same vote, same block_id) must NOT emit Equivocation; got {out2:?}"
    );
}

// ---- evidence authorization: on_proposal evidence gate ----

/// Build a valid EquivocationProof for `equivocator_kp` against `vset`,
/// using synthetic block hashes (not real blocks). This proves the equivocator
/// double-signed without needing a full block DAG.
fn make_equivocation_proof(equivocator_kp: &Keypair) -> EquivocationProof {
    use azbft_types::evidence::EquivocationProof;
    use azbft_types::{blake3_id, Vote};

    let id_a = blake3_id(&b"eq-block-a".to_vec());
    let id_b = blake3_id(&b"eq-block-b".to_vec());
    // Ensure canonical order required by EquivocationProof::new.
    let (id_a, id_b) = if id_a <= id_b {
        (id_a, id_b)
    } else {
        (id_b, id_a)
    };
    let voter = equivocator_kp.node_id();
    let vote_a = Signed {
        inner: Vote {
            epoch: 0,
            block_id: id_a,
            round: Round(1),
            voter,
        },
        sig: equivocator_kp.sign(Domain::Vote, &vote_digest(&id_a, Round(1)).0),
    };
    let vote_b = Signed {
        inner: Vote {
            epoch: 0,
            block_id: id_b,
            round: Round(1),
            voter,
        },
        sig: equivocator_kp.sign(Domain::Vote, &vote_digest(&id_b, Round(1)).0),
    };
    EquivocationProof::new(vote_a, vote_b)
}

/// Evidence-based removal: A proposal whose reconfig carries FORGED/IRRELEVANT evidence
/// must be rejected by the on_proposal gate — the node must NOT emit a Vote.
///
/// The block is authored and signed by the real round leader so it passes the
/// author-signature check; the gate (`verify_removal_justified`) is what
/// rejects it.
#[test]
fn forged_evidence_removal_not_voted() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    // `me` must be a replica (not the round-1 leader) so it votes on the proposal.
    let me_idx = kps.iter().position(|k| k.node_id() != leader1).unwrap();
    let mut core = core_as(&vset, me_idx);

    // Choose any validator as the purported equivocator.
    let equivocator_kp = kps.iter().find(|k| k.node_id() != leader1).unwrap();

    // Build a FORGED proof: valid sigs but the voter is NOT removed by the
    // reconfig (next_set keeps the equivocator in — so evidence is irrelevant).
    // `verify_removal_justified` catches: voter still in next_set → false.
    let proof = make_equivocation_proof(equivocator_kp);
    // next_set keeps ALL validators (equivocator NOT removed) → evidence irrelevant.
    let forged_rc = Reconfig {
        next_set: vset.clone(), // equivocator NOT removed → evidence irrelevant
        evidence: vec![proof],
        operator_sig: None,
        jail: None,
    };

    let b = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 0,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: blake3_id(&b"forged-payload".to_vec()),
        author: leader1,
        reconfig: Some(forged_rc),
    };
    let prop = Proposal {
        block: b,
        last_round_tc: None,
    };
    // Sign with the real leader key so the author-signature check passes.
    let signed = sign_proposal(kp_of(&kps, leader1), &prop);
    let out = core.handle(Event::Proposal(signed), 0);

    // The gate must have rejected: no Vote in output.
    assert!(
        !out.iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "forged-evidence removal proposal must NOT produce a Vote; got {out:?}"
    );
}

/// Evidence-based removal: A proposal whose reconfig carries VALID, RELEVANT evidence
/// (the equivocator is removed by the reconfig) MUST be voted on. This is
/// the control case proving the gate doesn't over-reject.
#[test]
fn valid_evidence_removal_voted() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    // `me` must be a replica (not the round-1 leader).
    let me_idx = kps.iter().position(|k| k.node_id() != leader1).unwrap();
    let mut core = core_as(&vset, me_idx);

    // Use one of the non-leader validators as the equivocator.
    let equivocator_kp = kps.iter().find(|k| k.node_id() != leader1).unwrap();
    let equivocator = equivocator_kp.node_id();

    // Build a VALID proof for the equivocator.
    let proof = make_equivocation_proof(equivocator_kp);

    // next_set removes the equivocator → evidence IS relevant.
    let next_set = vset.without(&equivocator);
    let valid_rc = Reconfig {
        next_set,
        evidence: vec![proof],
        operator_sig: None,
        jail: None,
    };

    let b = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 0,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: blake3_id(&b"valid-removal-payload".to_vec()),
        author: leader1,
        reconfig: Some(valid_rc),
    };
    let prop = Proposal {
        block: b,
        last_round_tc: None,
    };
    // Sign with the real leader key so the author-signature check passes.
    let signed = sign_proposal(kp_of(&kps, leader1), &prop);
    let out = core.handle(Event::Proposal(signed), 0);

    // The gate must pass: a Vote must be emitted.
    assert!(
        out.iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "valid evidence-justified removal proposal MUST produce a Vote; got {out:?}"
    );
}

/// Consumed-evidence replay protection: a reconfig reusing an ALREADY-CONSUMED equivocation act must
/// NOT be voted (the double-slash gate). As a positive control, the identical
/// proof shape IS voted when NOT pre-consumed — that is `valid_evidence_removal_voted`
/// above, so the ONLY difference here is the pre-seeded consumed ledger.
#[test]
fn consumed_evidence_reuse_removal_not_voted() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() != leader1).unwrap();
    let mut core = core_as(&vset, me_idx);
    let equivocator_kp = kps.iter().find(|k| k.node_id() != leader1).unwrap();
    let equivocator = equivocator_kp.node_id();
    let proof = make_equivocation_proof(equivocator_kp);
    // Pre-consume this exact act (as if an earlier reconfig already punished it).
    let v = proof.vote_a.inner.clone();
    let mut consumed = std::collections::BTreeSet::new();
    consumed.insert((v.voter, v.epoch, v.round.0));
    core.restore_consumed(consumed);
    // A second, otherwise-valid removal reusing the SAME proof → must be rejected.
    let rc = Reconfig {
        next_set: vset.without(&equivocator),
        evidence: vec![proof],
        operator_sig: None,
        jail: None,
    };
    let signed = make_reconfig_proposal(&kps, &vset, rc, b"reuse-consumed");
    let out = core.handle(Event::Proposal(signed), 0);
    assert!(
        !out.iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "reused (already-consumed) evidence must NOT produce a Vote; got {out:?}"
    );
}

/// Consumed-evidence replay protection: committing a reconfig block records its carried evidence as
/// consumed (the commit-apply record). Drives a real `SyncApply` commit (same
/// shape as `commit_commands_carry_linked_certs`) so the `process_qc`
/// commit-apply path runs. Positive control: the key is absent before, present after.
#[test]
fn committed_reconfig_records_consumed_evidence() {
    let (kps, vset) = validators();
    let mut core = core_as(&vset, 0);
    let equivocator_kp = &kps[1];
    let equivocator = equivocator_kp.node_id();
    let proof = make_equivocation_proof(equivocator_kp);
    let key = {
        let v = &proof.vote_a.inner;
        (v.voter, v.epoch, v.round.0)
    };
    assert!(
        !core.consumed_evidence().contains(&key),
        "not consumed before the commit"
    );
    // b1 carries a removal reconfig justified by the proof; its adjacent
    // child b2 makes b1 the exact two-chain commit target.
    let rc = Reconfig {
        next_set: vset.without(&equivocator),
        evidence: vec![proof],
        operator_sig: None,
        jail: None,
    };
    let b1 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 0,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: blake3_id(&b"reconfig-with-evidence".to_vec()),
        author: vset.leader(Round(1)),
        reconfig: Some(rc),
    };
    let b2 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 2,
        timestamp_ms: 2,
        epoch: 0,
        round: Round(2),
        parent_qc: qc_over(b1.id(), Round(1), &kps),
        payload_hash: blake3_id(&b"reconfig-descendant-two".to_vec()),
        author: vset.leader(Round(2)),
        reconfig: None,
    };
    let commit_qc = qc_over(b2.id(), Round(2), &kps);
    let _ = core.handle(
        Event::SyncApply {
            blocks: vec![b1, b2],
            commit_qc,
        },
        0,
    );
    assert!(
        core.consumed_evidence().contains(&key),
        "committing the reconfig must record its evidence as consumed"
    );
}

// ---- Operator-signature gate adversarial tests ----

/// Helper: build a proposal block with the given reconfig, signed by the
/// real round-1 leader (so the author-signature check always passes). The
/// discriminator is entirely the reconfig authorization gate.
fn make_reconfig_proposal(
    kps: &[Keypair],
    vset: &ValidatorSet,
    rc: Reconfig,
    payload: &[u8],
) -> Signed<Proposal> {
    let leader1 = vset.leader(Round(1));
    let b = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 0,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: blake3_id(&payload.to_vec()),
        author: leader1,
        reconfig: Some(rc),
    };
    let prop = Proposal {
        block: b,
        last_round_tc: None,
    };
    sign_proposal(kp_of(kps, leader1), &prop)
}

fn voted(out: &[Command]) -> bool {
    out.iter()
        .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_))))
}

/// The current set minus its first member plus a newcomer (seed 5).
fn execution_next_set(kps: &[Keypair]) -> ValidatorSet {
    let newcomer = Keypair::from_seed(5);
    ValidatorSet::new(
        kps.iter()
            .skip(1)
            .chain(std::iter::once(&newcomer))
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect(),
    )
}

fn execution_reconfig(next_set: ValidatorSet) -> Reconfig {
    Reconfig {
        next_set,
        evidence: vec![],
        operator_sig: None,
        jail: None,
    }
}

/// A follower of the round-1 leader, with execution owning the set from `from`.
fn execution_follower(kps: &[Keypair], vset: &ValidatorSet, from: Option<u64>) -> ConsensusCore {
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() != leader1).unwrap();
    let mut core = core_as(vset, me_idx);
    if let Some(from) = from {
        core.set_execution_reconfig_from(from);
    }
    core
}

/// From the handover height an unsigned reconfiguration that admits a new
/// member is voted; before it, or without a handover, the same block is not.
#[test]
fn execution_owns_the_set_from_the_handover_height() {
    let (kps, vset) = validators();
    let proposal = || {
        make_reconfig_proposal(
            &kps,
            &vset,
            execution_reconfig(execution_next_set(&kps)),
            b"execution",
        )
    };

    let mut owned = execution_follower(&kps, &vset, Some(1));
    let out = owned.handle(Event::Proposal(proposal()), 0);
    assert!(voted(&out), "block 1 at the handover height: {out:?}");

    for from in [None, Some(2)] {
        let mut before = execution_follower(&kps, &vset, from);
        let out = before.handle(Event::Proposal(proposal()), 0);
        assert!(!voted(&out), "handover {from:?}: {out:?}");
    }
}

/// Once execution owns the set, an operator signature no longer authorizes
/// anything, and neither do evidence or jail terms.
#[test]
fn execution_reconfig_carries_nothing_but_the_set() {
    let (kps, vset) = validators();
    let next = ValidatorSet::new(
        kps.iter()
            .take(3)
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect(),
    );
    let operator = Keypair::from_seed(999_999);
    let signed = Reconfig {
        operator_sig: Some(operator.sign(
            Domain::Reconfig,
            &azbft_types::reconfig_signing_bytes(&next, 0),
        )),
        ..execution_reconfig(next.clone())
    };
    // The control: before the handover the operator path still works.
    let mut legacy = execution_follower(&kps, &vset, Some(2));
    let out = legacy.handle(
        Event::Proposal(make_reconfig_proposal(&kps, &vset, signed.clone(), b"op")),
        0,
    );
    assert!(
        voted(&out),
        "operator reconfig before the handover: {out:?}"
    );

    let jailed = Reconfig {
        jail: Some(JailRecord {
            offender: kps[3].node_id(),
            until_epoch: 1,
        }),
        ..execution_reconfig(next.clone())
    };
    let empty = execution_reconfig(ValidatorSet::new(Vec::new()));
    for (name, rc) in [("operator", signed), ("jail", jailed), ("empty", empty)] {
        let mut owned = execution_follower(&kps, &vset, Some(1));
        let out = owned.handle(
            Event::Proposal(make_reconfig_proposal(&kps, &vset, rc, name.as_bytes())),
            0,
        );
        assert!(!voted(&out), "{name}: {out:?}");
    }
}

/// Proofs of possession are still required of every BLS key a set brings in.
#[test]
fn execution_reconfig_still_needs_proofs_of_possession() {
    let (kps, vset) = validators();
    let mut members = execution_next_set(&kps).members().to_vec();
    members[0].bls_pubkey = vec![1; 48];
    members[0].bls_pop = vec![2; 96];
    let rc = execution_reconfig(ValidatorSet::new_members(members));
    let mut owned = execution_follower(&kps, &vset, Some(1));
    let out = owned.handle(
        Event::Proposal(make_reconfig_proposal(&kps, &vset, rc, b"pop")),
        0,
    );
    assert!(!voted(&out), "{out:?}");
}

/// The host stages execution's set; the leader's next block carries it
/// unsigned. Without a handover height the request is ignored.
#[test]
fn a_staged_execution_set_rides_on_the_next_proposal() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() == leader1).unwrap();
    let next = execution_next_set(&kps);
    let carried = |from: Option<u64>| {
        let mut core = core_as(&vset, me_idx);
        if let Some(from) = from {
            core.set_execution_reconfig_from(from);
        }
        let _ = core.handle(Event::RequestExecutionReconfig(next.clone()), 0);
        let _ = core.start();
        let out = handle_payload_ready(&mut core, Round(1), b"p".to_vec(), 0);
        out.iter().find_map(|c| match c {
            Command::Broadcast(ConsensusMessage::Proposal(sp)) => {
                Some(sp.inner.block.reconfig.clone())
            }
            _ => None,
        })
    };
    assert_eq!(
        carried(Some(1)),
        Some(Some(execution_reconfig(next.clone())))
    );
    assert_eq!(carried(None), Some(None));
}

/// From the handover an operator request staged earlier is not proposed;
/// before it, it still is.
#[test]
fn a_staged_operator_request_is_dropped_from_the_handover() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() == leader1).unwrap();
    let operator = Keypair::from_seed(999_999);
    let sig = operator.sign(
        Domain::Reconfig,
        &azbft_types::reconfig_signing_bytes(&vset, 0),
    );
    let carried = |from: u64| {
        let mut core = core_as(&vset, me_idx);
        core.set_execution_reconfig_from(from);
        let _ = core.handle(Event::RequestReconfig(vset.clone(), sig.clone()), 0);
        let _ = core.start();
        let out = handle_payload_ready(&mut core, Round(1), b"p".to_vec(), 0);
        let block = out.iter().find_map(|c| match c {
            Command::Broadcast(ConsensusMessage::Proposal(sp)) => {
                Some(sp.inner.block.reconfig.clone())
            }
            _ => None,
        });
        (block, core.pending_reconfig.is_some())
    };
    assert_eq!(carried(1), (Some(None), false));
    let (before, staged) = carried(2);
    assert!(matches!(before, Some(Some(ref rc)) if rc.operator_sig.is_some()));
    assert!(staged);
}

/// An operator transition certified before the handover is retried after
/// it under the rules it was certified under.
#[test]
fn a_transition_locked_before_the_handover_can_still_end() {
    let (kps, vset) = validators();
    let next = ValidatorSet::new(
        kps.iter()
            .take(3)
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect(),
    );
    let operator = Keypair::from_seed(999_999);
    let signed = Reconfig {
        operator_sig: Some(operator.sign(
            Domain::Reconfig,
            &azbft_types::reconfig_signing_bytes(&next, 0),
        )),
        ..execution_reconfig(next)
    };
    let mut locked = execution_follower(&kps, &vset, Some(1));
    locked.pending_reconfig = Some(signed.clone());
    locked.epoch_ending_round = Some(Round(0));
    let out = locked.handle(
        Event::Proposal(make_reconfig_proposal(
            &kps,
            &vset,
            signed.clone(),
            b"retry",
        )),
        0,
    );
    assert!(voted(&out), "{out:?}");

    // Its leader still proposes the retry.
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() == leader1).unwrap();
    let mut leader = core_as(&vset, me_idx);
    leader.set_execution_reconfig_from(1);
    leader.pending_reconfig = Some(signed.clone());
    leader.epoch_ending_round = Some(Round(0));
    let _ = leader.start();
    let out = handle_payload_ready(&mut leader, Round(1), b"p".to_vec(), 0);
    let carried = out.iter().find_map(|c| match c {
        Command::Broadcast(ConsensusMessage::Proposal(sp)) => Some(sp.inner.block.reconfig.clone()),
        _ => None,
    });
    assert_eq!(carried, Some(Some(signed)));
}

/// A certified execution transition, new members and all, is retried
/// under the execution rules.
#[test]
fn a_locked_execution_transition_is_retried() {
    let (kps, vset) = validators();
    let rc = execution_reconfig(execution_next_set(&kps));
    let mut locked = execution_follower(&kps, &vset, Some(1));
    locked.pending_reconfig = Some(rc.clone());
    locked.epoch_ending_round = Some(Round(0));
    let out = locked.handle(
        Event::Proposal(make_reconfig_proposal(&kps, &vset, rc, b"retry")),
        0,
    );
    assert!(voted(&out), "{out:?}");
}

/// A certified transition is locked: a later execution request cannot replace it.
#[test]
fn a_locked_transition_ignores_execution_requests() {
    let (kps, vset) = validators();
    let mut core = core_as(&vset, 0);
    core.set_execution_reconfig_from(1);
    let locked = execution_reconfig(execution_next_set(&kps));
    core.pending_reconfig = Some(locked.clone());
    core.epoch_ending_round = Some(Round(1));
    let _ = core.handle(Event::RequestExecutionReconfig(vset.clone()), 0);
    assert_eq!(core.pending_reconfig, Some(locked));
}

/// Missing authorization: A reconfig with no operator_sig and no evidence MUST be rejected.
/// (Closes the old operator-authorized path unsigned-reconfig gap.)
#[test]
fn unsigned_reconfig_not_voted() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() != leader1).unwrap();
    let mut core = core_as(&vset, me_idx);

    let next_set = ValidatorSet::new(
        kps.iter()
            .take(3)
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect(),
    );
    let rc = Reconfig {
        next_set,
        evidence: vec![],
        operator_sig: None,
        jail: None,
    };
    let signed = make_reconfig_proposal(&kps, &vset, rc, b"unsigned-reconfig");
    let out = core.handle(Event::Proposal(signed), 0);

    assert!(
        !out.iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "unsigned reconfig with no evidence MUST NOT produce a Vote; got {out:?}"
    );
}

/// Invalid authorization: A reconfig with a forged/wrong operator_sig MUST be rejected.
#[test]
fn forged_operator_sig_not_voted() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() != leader1).unwrap();
    let mut core = core_as(&vset, me_idx);

    let next_set = ValidatorSet::new(
        kps.iter()
            .take(3)
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect(),
    );
    // Sign over a DIFFERENT next_set (all 4 validators) — binding mismatch.
    let op = Keypair::from_seed(999_999);
    let different_set = vset.clone(); // signing bytes over the wrong set
    let bad_sig = op.sign(
        Domain::Reconfig,
        &azbft_types::reconfig_signing_bytes(&different_set, 0),
    );
    let rc = Reconfig {
        next_set,
        evidence: vec![],
        operator_sig: Some(bad_sig),
        jail: None,
    };
    let signed = make_reconfig_proposal(&kps, &vset, rc, b"forged-sig-reconfig");
    let out = core.handle(Event::Proposal(signed), 0);

    assert!(
        !out.iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "forged operator sig MUST NOT produce a Vote; got {out:?}"
    );
}

/// Valid authorization: A reconfig with a VALID operator signature MUST be voted on.
/// (Control case — the gate should not over-reject.)
#[test]
fn operator_signed_reconfig_voted() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() != leader1).unwrap();
    let mut core = core_as(&vset, me_idx);

    let next_set = ValidatorSet::new(
        kps.iter()
            .take(3)
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect(),
    );
    let op = Keypair::from_seed(999_999);
    let sig = op.sign(
        Domain::Reconfig,
        &azbft_types::reconfig_signing_bytes(&next_set, 0),
    );
    let rc = Reconfig {
        next_set,
        evidence: vec![],
        operator_sig: Some(sig),
        jail: None,
    };
    let signed = make_reconfig_proposal(&kps, &vset, rc, b"operator-signed-reconfig");
    let out = core.handle(Event::Proposal(signed), 0);

    assert!(
        out.iter()
            .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_)))),
        "operator-signed reconfig MUST produce a Vote; got {out:?}"
    );
}
// ===== epoch-boundary coverage =========================================
// Added after a mutation run found four behaviour changes with no test
// watching them. Each test below fails when the code it covers is reverted.

/// An operator-signed transition to `next_set`, valid for epoch 0 under the
/// operator key `core_as` installs.
fn boundary_reconfig(next_set: ValidatorSet) -> Reconfig {
    let operator = Keypair::from_seed(999_999);
    let sig = operator.sign(
        Domain::Reconfig,
        &azbft_types::reconfig_signing_bytes(&next_set, 0),
    );
    Reconfig {
        next_set,
        evidence: vec![],
        operator_sig: Some(sig),
        jail: None,
    }
}

fn sent_a_vote(out: &[Command]) -> bool {
    out.iter()
        .any(|c| matches!(c, Command::Send(_, ConsensusMessage::Vote(_))))
}

fn emitted_a_commit(out: &[Command]) -> bool {
    out.iter().any(|c| matches!(c, Command::Commit(_)))
}

/// The `process_qc` conflict gate, reached by ordinary proposals.
///
/// A first review of this PR concluded the gate was unreachable — that
/// `on_proposal` always rejects a conflicting block before it can enter the
/// tree. Arrival order says otherwise: the reconfig check runs BEFORE
/// `tree.insert`, which runs BEFORE `process_qc`. So a proposal carrying
/// transition B whose parent QC certifies transition A passes the check
/// while nothing is locked yet, lands in the tree, and only then does the
/// same event lock this node on A. The tree now holds a certified block
/// whose reconfig differs from the lock, which is exactly what the gate is
/// for.
#[test]
fn boundary_conflict_gate_is_reached_by_proposal_arrival_order() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() != leader1).unwrap();
    let mut core = core_as(&vset, me_idx);

    let a = boundary_reconfig(vset.without(&kps[0].node_id()));
    let b = boundary_reconfig(vset.without(&kps[1].node_id()));
    assert_ne!(a, b);

    let p1 = make_reconfig_proposal(&kps, &vset, a.clone(), b"conflict-r1");
    let b1 = p1.inner.block.clone();
    let out1 = core.handle(Event::Proposal(p1), 1);
    assert!(sent_a_vote(&out1), "R1 must be voted");
    assert_eq!(core.epoch_ending_round, None, "nothing is locked after R1");

    let blk2 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 2,
        timestamp_ms: 2,
        epoch: 0,
        round: Round(2),
        parent_qc: qc_over(b1.id(), Round(1), &kps),
        payload_hash: blake3_id(&b"conflict-r2".to_vec()),
        author: vset.leader(Round(2)),
        reconfig: Some(b.clone()),
    };
    let p2 = Proposal {
        block: blk2.clone(),
        last_round_tc: None,
    };
    let _ = core.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, blk2.author), &p2)),
        2,
    );
    assert!(
        core.contains_block(&blk2.id()),
        "the conflicting block reaches the tree — this is the premise"
    );
    assert_eq!(core.epoch_ending_round, Some(Round(1)), "locked on A@R1");
    assert_eq!(core.pending_reconfig.as_ref(), Some(&a));

    // An ordinary block extending QC(conflicting block) now hits the gate.
    let blk3 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 3,
        timestamp_ms: 3,
        epoch: 0,
        round: Round(3),
        parent_qc: qc_over(blk2.id(), Round(2), &kps),
        payload_hash: blake3_id(&b"conflict-r3".to_vec()),
        author: vset.leader(Round(3)),
        reconfig: None,
    };
    let p3 = Proposal {
        block: blk3.clone(),
        last_round_tc: None,
    };
    let out3 = core.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, blk3.author), &p3)),
        3,
    );
    assert!(
        !sent_a_vote(&out3),
        "the conflicting parent QC must not be voted on"
    );
    assert!(
        !emitted_a_commit(&out3),
        "no commit may ride the conflicting QC"
    );
    assert_eq!(
        core.pending_reconfig.as_ref(),
        Some(&a),
        "the locked transition must survive"
    );
    assert_eq!(
        core.epoch_ending_round,
        Some(Round(1)),
        "the boundary must not move to the conflicting attempt"
    );
    assert_eq!(
        core.high_qc().round,
        Round(1),
        "the conflicting QC must not be adopted"
    );
}

/// The same gate, reached by bulk sync — the path that makes deleting it
/// unsafe. `SyncApply` inserts blocks after header validation only; it has
/// no reconfig gate of its own, so `process_qc`'s is the only thing standing
/// between a synced conflicting transition and this node's lock.
#[test]
fn boundary_conflict_gate_is_reached_by_sync_apply() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() != leader1).unwrap();
    let mut core = core_as(&vset, me_idx);

    let a = boundary_reconfig(vset.without(&kps[0].node_id()));
    let b = boundary_reconfig(vset.without(&kps[1].node_id()));

    let p1 = make_reconfig_proposal(&kps, &vset, a.clone(), b"sync-r1");
    let b1 = p1.inner.block.clone();
    let _ = core.handle(Event::Proposal(p1), 1);
    let blk2 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 2,
        timestamp_ms: 2,
        epoch: 0,
        round: Round(2),
        parent_qc: qc_over(b1.id(), Round(1), &kps),
        payload_hash: blake3_id(&b"sync-r2".to_vec()),
        author: vset.leader(Round(2)),
        reconfig: Some(a.clone()),
    };
    let p2 = Proposal {
        block: blk2.clone(),
        last_round_tc: None,
    };
    let _ = core.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, blk2.author), &p2)),
        2,
    );
    assert_eq!(core.epoch_ending_round, Some(Round(1)), "locked on A@R1");
    assert_eq!(core.pending_reconfig.as_ref(), Some(&a));

    let blk3 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 3,
        timestamp_ms: 3,
        epoch: 0,
        round: Round(3),
        parent_qc: qc_over(blk2.id(), Round(2), &kps),
        payload_hash: blake3_id(&b"sync-r3".to_vec()),
        author: vset.leader(Round(3)),
        reconfig: Some(b.clone()),
    };
    let commit_qc = qc_over(blk3.id(), Round(3), &kps);
    let out = core.handle(
        Event::SyncApply {
            blocks: vec![blk3.clone()],
            commit_qc,
        },
        3,
    );
    assert!(
        core.contains_block(&blk3.id()),
        "SyncApply inserts unconditionally — this is the premise"
    );
    assert!(
        !emitted_a_commit(&out),
        "a bulk-synced conflicting transition must not drive a commit"
    );
    assert_eq!(
        core.pending_reconfig.as_ref(),
        Some(&a),
        "the lock must not be replaced by a bulk-synced conflicting transition"
    );
    assert_eq!(
        core.epoch_ending_round,
        Some(Round(1)),
        "the boundary must not move to the synced attempt"
    );
}

/// The retired-epoch output filter, with a batch that carries real output.
///
/// The assertion this PR shipped for the filter checked a batch that had no
/// `Send`/`Broadcast`/`CreatePayload` in it at all, so it passed with or
/// without the filter. Here the boundary two-chain commit lands in the same
/// batch as this node's vote for the committing block, so the filter has
/// something to drop and removing it fails the test.
#[test]
fn boundary_commit_batch_drops_a_live_vote() {
    let (kps, vset) = validators();
    // `me` leads none of R1..R3, which keeps the dropped command a Send(Vote)
    // rather than a Broadcast of our own proposal.
    let me = vset.members()[0].node_id;
    assert_ne!(me, vset.leader(Round(1)));
    assert_ne!(me, vset.leader(Round(2)));
    assert_ne!(me, vset.leader(Round(3)));
    let me_idx = kps.iter().position(|k| k.node_id() == me).unwrap();
    let mut core = core_as(&vset, me_idx);

    let next = ValidatorSet::new(
        kps.iter()
            .take(3)
            .map(|k| (k.node_id(), k.pubkey_bytes(), 1u64))
            .collect(),
    );
    let locked = boundary_reconfig(next);

    let r1 = make_reconfig_proposal(&kps, &vset, locked.clone(), b"drop-r1");
    let r1_block = r1.inner.block.clone();
    let _ = core.handle(Event::Proposal(r1), 1);
    let qc1 = qc_over(r1_block.id(), Round(1), &kps);

    let r2 = Proposal {
        block: Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 2,
            timestamp_ms: 2,
            epoch: 0,
            round: Round(2),
            parent_qc: qc1,
            payload_hash: blake3_id(&b"drop-r2".to_vec()),
            author: vset.leader(Round(2)),
            reconfig: Some(locked.clone()),
        },
        last_round_tc: None,
    };
    let r2_block = r2.block.clone();
    let _ = core.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, r2.block.author), &r2)),
        2,
    );
    let qc2 = qc_over(r2_block.id(), Round(2), &kps);

    let r3 = Proposal {
        block: Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 3,
            timestamp_ms: 3,
            epoch: 0,
            round: Round(3),
            parent_qc: qc2,
            payload_hash: blake3_id(&b"drop-r3".to_vec()),
            author: vset.leader(Round(3)),
            reconfig: Some(locked),
        },
        last_round_tc: None,
    };
    let commands = core.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, r3.block.author), &r3)),
        3,
    );

    assert!(
        commands.iter().any(|c| matches!(
            c,
            Command::Commit(cb) if cb.two_chain && cb.block.reconfig.is_some()
        )),
        "precondition: this batch must carry the boundary two-chain commit; got {commands:?}"
    );
    assert!(
        commands.iter().all(|c| !matches!(c, Command::Send(_, _))),
        "a live vote survived the boundary-commit batch: {commands:?}"
    );
}

/// Once a transition is certified, a later operator request must not replace
/// it. Nodes receive operator requests at different moments; letting a late
/// one overwrite the lock would leave honest nodes retrying different values,
/// and a node would then reject the QC for the transition it certified itself.
///
/// Dropping the request is deliberate, not an oversight: the operator sees
/// exactly what it saw before this PR, and queuing it would mean a stale
/// request activating in an epoch nobody asked it for.
#[test]
fn late_operator_request_cannot_replace_the_certified_lock() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let me_idx = kps.iter().position(|k| k.node_id() != leader1).unwrap();
    let mut core = core_as(&vset, me_idx);

    let a = boundary_reconfig(vset.without(&kps[0].node_id()));

    // Certify A: R1 carries it, R2 re-emits it and its QC(R1) locks us.
    let p1 = make_reconfig_proposal(&kps, &vset, a.clone(), b"late-r1");
    let b1 = p1.inner.block.clone();
    let _ = core.handle(Event::Proposal(p1), 1);
    let blk2 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 2,
        timestamp_ms: 2,
        epoch: 0,
        round: Round(2),
        parent_qc: qc_over(b1.id(), Round(1), &kps),
        payload_hash: blake3_id(&b"late-r2".to_vec()),
        author: vset.leader(Round(2)),
        reconfig: Some(a.clone()),
    };
    let p2 = Proposal {
        block: blk2.clone(),
        last_round_tc: None,
    };
    let _ = core.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, blk2.author), &p2)),
        2,
    );
    assert_eq!(core.epoch_ending_round, Some(Round(1)), "locked on A@R1");
    assert_eq!(core.pending_reconfig.as_ref(), Some(&a));

    // A well-formed, correctly signed request for a DIFFERENT set arrives late.
    let other = vset.without(&kps[1].node_id());
    let operator = Keypair::from_seed(999_999);
    let other_sig = operator.sign(
        Domain::Reconfig,
        &azbft_types::reconfig_signing_bytes(&other, 0),
    );
    let _ = core.handle(Event::RequestReconfig(other.clone(), other_sig), 2);

    assert_eq!(
        core.pending_reconfig.as_ref(),
        Some(&a),
        "a late operator request must not replace the certified transition"
    );

    // And the consequence that makes this load-bearing: we still accept the
    // retry of the transition we ourselves certified.
    let retry = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 3,
        timestamp_ms: 3,
        epoch: 0,
        round: Round(3),
        parent_qc: qc_over(blk2.id(), Round(2), &kps),
        payload_hash: blake3_id(&b"late-retry".to_vec()),
        author: vset.leader(Round(3)),
        reconfig: Some(a.clone()),
    };
    let p3 = Proposal {
        block: retry.clone(),
        last_round_tc: None,
    };
    let retry_id = retry.id();
    let out = core.handle(
        Event::Proposal(sign_proposal(kp_of(&kps, retry.author), &p3)),
        3,
    );
    // The observable is admission, not the vote: this proposal's parent QC
    // completes the boundary two-chain, so the retired-epoch filter removes
    // our vote from this very batch (see
    // `boundary_commit_batch_drops_a_live_vote`). Admission into the tree is
    // what `on_proposal`'s reconfig gate decides, and that gate compares
    // against the lock — if a late request had replaced it, the retry of our
    // own certified transition would be turned away here.
    assert!(
        core.contains_block(&retry_id),
        "the retry of our own certified transition must still be admitted; got {out:?}"
    );
}

/// A synced batch whose reconfig sits on a deep ancestor applies no reconfig
/// effects — only the two-chain commit target does.
///
/// This shape used to be what `committed_reconfig_records_consumed_evidence`
/// exercised (b1..b4). That test was shortened to a two-block chain when the
/// `i + 1 == n` narrowing landed, which removed the only coverage that could
/// tell the old behaviour from the new one. Rather than restore an assertion
/// that is now false, this pins the new one. See the argument at the
/// narrowing for why the skipped effects are never lost on the active path.
#[test]
fn synced_deep_ancestor_reconfig_applies_no_effects() {
    let (kps, vset) = validators();
    let mut core = core_as(&vset, 0);
    let equivocator_kp = &kps[1];
    let proof = make_equivocation_proof(equivocator_kp);
    let key = {
        let v = &proof.vote_a.inner;
        (v.voter, v.epoch, v.round.0)
    };
    let operator = Keypair::from_seed(999_999);
    let next = vset.without(&equivocator_kp.node_id());
    let removal = Reconfig {
        next_set: next.clone(),
        evidence: vec![proof],
        operator_sig: Some(operator.sign(
            Domain::Reconfig,
            &azbft_types::reconfig_signing_bytes(&next, 0),
        )),
        jail: None,
    };

    let b1 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 1,
        timestamp_ms: 1,
        epoch: 0,
        round: Round(1),
        parent_qc: QuorumCert::genesis(),
        payload_hash: blake3_id(&b"deep-one".to_vec()),
        author: vset.leader(Round(1)),
        reconfig: Some(removal),
    };
    let b2 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 2,
        timestamp_ms: 2,
        epoch: 0,
        round: Round(2),
        parent_qc: qc_over(b1.id(), Round(1), &kps),
        payload_hash: blake3_id(&b"deep-two".to_vec()),
        author: vset.leader(Round(2)),
        reconfig: None,
    };
    let b3 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 3,
        timestamp_ms: 3,
        epoch: 0,
        round: Round(3),
        parent_qc: qc_over(b2.id(), Round(2), &kps),
        payload_hash: blake3_id(&b"deep-three".to_vec()),
        author: vset.leader(Round(3)),
        reconfig: None,
    };
    let b4 = Block {
        header_version: BLOCK_HEADER_VERSION_V2,
        height: 4,
        timestamp_ms: 4,
        epoch: 0,
        round: Round(4),
        parent_qc: qc_over(b3.id(), Round(3), &kps),
        payload_hash: blake3_id(&b"deep-four".to_vec()),
        author: vset.leader(Round(4)),
        reconfig: None,
    };
    let b1_id = b1.id();
    let commit_qc = qc_over(b4.id(), Round(4), &kps);
    let out = core.handle(
        Event::SyncApply {
            blocks: vec![b1, b2, b3, b4],
            commit_qc,
        },
        0,
    );

    assert!(
        out.iter()
            .any(|c| matches!(c, Command::Commit(cb) if cb.block.id() == b1_id)),
        "precondition: the reconfig ancestor must actually be committed; got {out:?}"
    );
    assert!(
        out.iter().any(|c| matches!(
            c,
            Command::Commit(cb) if cb.block.id() == b1_id && !cb.two_chain
        )),
        "an ancestor is an inert attempt, not an epoch roll: {out:?}"
    );
    assert!(
        !core.consumed_evidence().contains(&key),
        "only the two-chain commit target may consume evidence"
    );
}

// ---- blockchain#95: votes to author + next leader; skip-absent leaders ----

/// A QC over `(block_id, round)` signed by exactly `signers`.
fn qc_by(block_id: Hash, round: Round, signers: &[&Keypair]) -> QuorumCert {
    let sigs: Vec<(NodeId, Vec<u8>)> = signers
        .iter()
        .map(|k| {
            (
                k.node_id(),
                k.sign(Domain::Vote, &vote_digest(&block_id, round).0),
            )
        })
        .collect();
    QuorumCert {
        block_id,
        round,
        agg: SecpMultiSig::aggregate(&sigs),
    }
}

fn vote_targets(out: &[Command]) -> Vec<NodeId> {
    out.iter()
        .filter_map(|c| match c {
            Command::Send(to, ConsensusMessage::Vote(_)) => Some(*to),
            _ => None,
        })
        .collect()
}

/// A vote goes to the next leader, which forms the QC on the happy path, and
/// also to the block's author. If the next leader is down the author still
/// certifies the block and carries that QC into the timeouts, so the block is
/// not orphaned by the view change.
#[test]
fn vote_goes_to_the_block_author_and_the_next_leader() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let leader2 = vset.leader(Round(2));
    let me_idx = kps
        .iter()
        .position(|k| k.node_id() != leader1 && k.node_id() != leader2)
        .unwrap();
    let mut core = core_as(&vset, me_idx);
    let b = block_round1(leader1, b"payload-1");
    let out = core.handle(
        Event::Proposal(sign_proposal(
            kp_of(&kps, leader1),
            &Proposal {
                block: b,
                last_round_tc: None,
            },
        )),
        0,
    );
    let mut targets = vote_targets(&out);
    targets.sort();
    let mut want = vec![leader1, leader2];
    want.sort();
    assert_eq!(
        targets, want,
        "one vote each to the author and the next leader"
    );
}

/// The author's copy of the vote is enough to certify its own block: with the
/// next leader silent, the author collects a quorum, forms the QC and moves on
/// with it as `high_qc`.
#[test]
fn the_author_certifies_its_block_from_the_extra_votes() {
    let (kps, vset) = validators();
    let leader1 = vset.leader(Round(1));
    let author_idx = kps.iter().position(|k| k.node_id() == leader1).unwrap();
    let mut author = core_as(&vset, author_idx);
    author.start();
    let b = block_round1(leader1, b"payload-1");
    author.tree_insert_for_test(b.clone());
    for kp in kps.iter().filter(|k| k.node_id() != vset.leader(Round(2))) {
        let vote = Vote {
            epoch: 0,
            block_id: b.id(),
            round: Round(1),
            voter: kp.node_id(),
        };
        author.handle(Event::Vote(sign_vote(kp, &vote)), 0);
    }
    assert_eq!(author.high_qc().block_id, b.id());
    assert_eq!(author.round(), Round(2));
}

/// Four validators where `absent` signs nothing. Returns `(b1, b2)` with b2's
/// parent QC (the liveness QC of round 3) signed by the other three.
fn chain_without(kps: &[Keypair], vset: &ValidatorSet, absent: NodeId) -> (Block, Block) {
    let present: Vec<&Keypair> = kps.iter().filter(|k| k.node_id() != absent).collect();
    let b1 = block_round1(vset.leader(Round(1)), b"b1");
    let b2 = Block {
        height: 2,
        timestamp_ms: 2,
        round: Round(2),
        parent_qc: qc_by(b1.id(), Round(1), &present),
        payload_hash: blake3_id(&b"b2".to_vec()),
        author: vset.leader(Round(2)),
        ..b1.clone()
    };
    (b1, b2)
}

fn round3_block(kps: &[Keypair], b2: &Block, author: NodeId, absent: NodeId) -> Block {
    let present: Vec<&Keypair> = kps.iter().filter(|k| k.node_id() != absent).collect();
    Block {
        height: 3,
        timestamp_ms: 3,
        round: Round(3),
        parent_qc: qc_by(b2.id(), Round(2), &present),
        payload_hash: blake3_id(&b"b3".to_vec()),
        author,
        ..b2.clone()
    }
}

/// Under round_robin_skip_absent the round of a validator missing from the
/// liveness QC belongs to the next member in schedule order: its own proposal
/// is refused and the skip leader's is voted. The same proposal from the
/// absent base leader is voted under plain round robin (control).
#[test]
fn skip_absent_round_belongs_to_the_next_present_member() {
    let (kps, vset) = validators();
    let absent = vset.leader(Round(3));
    let skip = vset.leader(Round(4));
    let (b1, b2) = chain_without(&kps, &vset, absent);
    let me_idx = kps
        .iter()
        .position(|k| k.node_id() != absent && k.node_id() != skip)
        .unwrap();
    let propose = |mode: LeaderSchedule, author: NodeId| {
        let mut core = core_as(&vset, me_idx);
        core.set_leader_mode(mode);
        core.tree_insert_for_test(b1.clone());
        core.tree_insert_for_test(b2.clone());
        let b3 = round3_block(&kps, &b2, author, absent);
        core.handle(
            Event::Proposal(sign_proposal(
                kp_of(&kps, author),
                &Proposal {
                    block: b3,
                    last_round_tc: None,
                },
            )),
            0,
        )
    };
    assert!(has_vote(&propose(LeaderSchedule::RoundRobin, absent)));
    assert!(!has_vote(&propose(
        LeaderSchedule::RoundRobinSkipAbsent,
        absent
    )));
    assert!(has_vote(&propose(
        LeaderSchedule::RoundRobinSkipAbsent,
        skip
    )));
    assert!(!has_vote(&propose(LeaderSchedule::RoundRobin, skip)));
}

/// The skip leader is the one that builds round 3: the votes on b2 are routed
/// to it (b2's parent QC already shows the absence), it forms the QC, and on
/// entering round 3 it asks for a payload. The absent base leader would not.
#[test]
fn skip_leader_collects_the_votes_and_builds_the_round() {
    let (kps, vset) = validators();
    let absent = vset.leader(Round(3));
    let skip = vset.leader(Round(4));
    let (b1, b2) = chain_without(&kps, &vset, absent);

    // a replica voting on b2 routes to the skip leader and to b2's author
    let voter_idx = kps
        .iter()
        .position(|k| k.node_id() != absent && k.node_id() != skip && k.node_id() != b2.author)
        .unwrap();
    let mut voter = core_as(&vset, voter_idx);
    voter.set_leader_mode(LeaderSchedule::RoundRobinSkipAbsent);
    voter.tree_insert_for_test(b1.clone());
    let out = voter.handle(
        Event::Proposal(sign_proposal(
            kp_of(&kps, b2.author),
            &Proposal {
                block: b2.clone(),
                last_round_tc: None,
            },
        )),
        0,
    );
    let targets = vote_targets(&out);
    assert!(
        targets.contains(&skip) && !targets.contains(&absent),
        "{targets:?}"
    );

    let skip_idx = kps.iter().position(|k| k.node_id() == skip).unwrap();
    let mut leader = core_as(&vset, skip_idx);
    leader.set_leader_mode(LeaderSchedule::RoundRobinSkipAbsent);
    leader.start();
    leader.tree_insert_for_test(b1.clone());
    leader.tree_insert_for_test(b2.clone());
    let mut out = Vec::new();
    for kp in kps.iter().filter(|k| k.node_id() != absent) {
        let vote = Vote {
            epoch: 0,
            block_id: b2.id(),
            round: Round(2),
            voter: kp.node_id(),
        };
        out.extend(leader.handle(Event::Vote(sign_vote(kp, &vote)), 0));
    }
    assert_eq!(leader.round(), Round(3));
    assert!(
        out.iter()
            .any(|c| matches!(c, Command::CreatePayload { round, .. } if *round == Round(3))),
        "the skip leader builds round 3; got {out:?}"
    );
    let parent = leader.high_qc().clone();
    assert!(leader
        .proposal_build_context(Round(3), &parent, 0)
        .is_some());
    assert_eq!(leader.current_leader(), Some(skip));
}

/// Ancestry import checks each author against the parent it extends: the
/// third block's liveness QC is the second block's parent QC.
#[test]
fn ancestry_import_checks_skip_absent_authors() {
    let (kps, vset) = validators();
    let absent = vset.leader(Round(3));
    let skip = vset.leader(Round(4));
    let (b1, b2) = chain_without(&kps, &vset, absent);
    let present: Vec<&Keypair> = kps.iter().filter(|k| k.node_id() != absent).collect();
    let import = |author: NodeId| {
        let mut core = core_as(&vset, 0);
        core.set_leader_mode(LeaderSchedule::RoundRobinSkipAbsent);
        let b3 = round3_block(&kps, &b2, author, absent);
        let target = qc_by(b3.id(), Round(3), &present);
        core.import_live_ancestors(&[b1.clone(), b2.clone(), b3], &target)
    };
    assert_eq!(import(absent), Err("invalid ancestry author"));
    assert_eq!(import(skip), Ok(()));
}
