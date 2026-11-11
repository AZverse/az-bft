//! The `handle(Event) -> Vec<Command>` core: the Jolteon 2-chain BFT flow.
//!
//! Every state transition lives here. The dispatcher [`ConsensusCore::handle`]
//! fans an [`Event`] out to one path method; each path returns the
//! [`Command`]s the host must execute (broadcast, send, arm/cancel timer,
//! request a payload, commit a block).
//!
//! ## Safety precondition (load-bearing)
//!
//! The round-watermark lock in `azbft-safety` is only sound if **no unverified
//! certificate is ever allowed to move `high_qc`, `preferred_round`, or drive a
//! commit**, and **no unauthored proposal is ever acted on**. So:
//!
//! * proposal author signatures are checked before `on_proposal` does
//!   anything (`Domain::Proposal` over `borsh(proposal.inner)`);
//! * every QC is signature+quorum verified in `process_qc` before it touches
//!   `high_qc` / the lock / commits — *except* the genesis QC (`round == 0`,
//!   empty agg), trusted by convention;
//! * each incoming vote / timeout signature is checked before it is collected,
//!   so any QC/TC built from collected material is verified-by-construction.
//!
//! [`Event`]: crate::event::Event
//! [`Command`]: crate::command::Command

use crate::command::{Command, CommittedBlock, ProposalBuildContext};
use crate::event::{Event, LogicalTime};
use crate::evidence::{
    verify_equivocation_proof, verify_operator_multisig, verify_reconfig_authorized,
};
use crate::state::{AggScheme, ConsensusCore};
use azbft_crypto::aggregator::{verify_agg, BlsMultiSig, SecpMultiSig, VoteAggregator};
use azbft_crypto::domain::Domain;
use azbft_types::{evidence::EquivocationProof, *};

/// Host-command execution classes, from earliest to latest.
///
/// Keep this match exhaustive on purpose: adding a new [`Command`] must fail to
/// compile here until its crash and latency dependencies have been considered.
/// Commands within one class retain their original relative order because
/// `sort_by_key` is stable.
fn command_execution_class(command: &Command) -> u8 {
    match command {
        // The wrapper inserts Persist only after sorting, but classify it first
        // as a defensive statement of the invariant: safety watermarks must be
        // durable before every network output that can depend on them.
        Command::Persist(_) => 0,
        // Evidence retention is cheap and stays ahead of network output so the
        // new vote-before-commit crash window does not also widen the window in
        // which locally-detected equivocation evidence can be lost.
        Command::Equivocation(_) => 1,
        // Arm/cancel the local pacemaker before sending. Neither operation
        // depends on a committed-block append, and an fsync must not defer it.
        Command::SetTimer(_, _) | Command::CancelTimer => 2,
        // Messages are already constructed, checked and signed by the core.
        // Their only durable prerequisite is Persist above, not the append of
        // an already-certified ancestor emitted in the same command batch.
        Command::Send(_, _) | Command::Broadcast(_) => 3,
        // The driver keeps this arm internally ordered as durable chain append
        // first, application delivery second. This classification changes
        // only where the intact arm runs relative to outbound messages.
        Command::Commit(_) => 4,
        // Payload construction can await an external payload provider in the
        // host, so it must not become a new obstacle in front of a ready vote.
        Command::CreatePayload { .. } => 5,
    }
}

/// Why a round was left, which decides whether the pacemaker backoff survives.
///
/// A round that produced a QC is consensus progress and resets the backoff. A
/// round that only produced a timeout certificate produced no block: leaving it
/// is the failure the backoff exists to answer, so the backoff must carry over
/// and keep growing. Resetting on both made the spec's "doubles on consecutive
/// timeouts" unreachable, because a stuck chain leaves every round by TC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RoundExit {
    /// The round was certified: a QC for it (or a later round) was processed.
    Certified,
    /// The round expired and a timeout certificate carried us out of it.
    TimedOut,
}

/// How many rounds behind its own a stuck node still answers a stale timeout
/// (blockchain#181: the peers that lost their timeouts are one round behind).
pub const STALE_ANSWER_WINDOW: u64 = 2;

impl ConsensusCore {
    /// Bootstrap into the current round: if leader, request a payload; always arm the
    /// round timer.
    pub fn start(&mut self) -> Vec<Command> {
        let mut out = Vec::new();
        self.enter_round(self.round, &mut out);
        out
    }

    /// Dispatch an event, then enforce the persist-before-dependent-message
    /// invariant: if this `handle` call changed the safety snapshot
    /// `{epoch, last_voted_round, preferred_round}`, **prepend**
    /// [`Command::Persist`] to the returned batch so every outbound message it
    /// produced is sequenced *after* the snapshot is made durable by the driver.
    ///
    /// This wrapper compares the snapshot before/after `handle_inner`
    /// structurally — it does not special-case individual events — so it covers
    /// *every* path that can move a watermark (voting via `make_vote`, lock
    /// raise via `update_on_qc`, and `SyncApply`'s `process_qc`). If the snapshot
    /// is unchanged, the batch is returned verbatim (no `Persist`), preserving
    /// the pre-persistence command stream exactly.
    pub fn handle(&mut self, ev: Event, now: LogicalTime) -> Vec<Command> {
        let before = self.safety_snapshot();
        let mut cmds = self.handle_inner(ev, now);
        // Once this batch commits a reconfiguration, the host is about to
        // replace this epoch's core. Do not let command reordering publish a
        // vote, timeout, proposal, or payload request from the retired epoch
        // before the durable commit arm has triggered that replacement.
        // Local timer commands are harmless and will be replaced by the new
        // core's start batch; network output from the old epoch is not.
        if cmds.iter().any(|command| {
            matches!(
                command,
                Command::Commit(committed)
                    if committed.two_chain && committed.block.reconfig.is_some()
            )
        }) {
            cmds.retain(|command| {
                !matches!(
                    command,
                    Command::Send(_, _) | Command::Broadcast(_) | Command::CreatePayload { .. }
                )
            });
        }
        // Command scheduling: execute latency-sensitive local control + network output
        // before any co-emitted durable block append. This does not weaken the durability invariant:
        // a changed safety snapshot is synchronously persisted at index 0 below,
        // before every Send/Broadcast. Stable sorting preserves causal order
        // within each class (notably ancestors-first Commit order).
        cmds.sort_by_key(command_execution_class);
        if self.safety_snapshot() != before {
            cmds.insert(0, Command::Persist(self.safety_snapshot()));
        }
        cmds
    }

    /// Dispatch an event to its path. `_now` is the host's logical clock; the
    /// Current paths are time-free (the pacemaker drives timing via emitted
    /// `SetTimer` commands), so it is currently unused but kept in the
    /// signature for forward compatibility.
    fn handle_inner(&mut self, ev: Event, now: LogicalTime) -> Vec<Command> {
        match ev {
            Event::Proposal(sp) => self.on_proposal(sp, now),
            Event::Vote(sv) => self.on_vote(sv),
            Event::RemoteTimeout(st) => self.on_remote_timeout(st),
            Event::LocalTimeout(r) => self.on_local_timeout(r),
            Event::PayloadReady { context, payload } => {
                self.on_payload_ready(context, payload, now)
            }
            Event::RequestReconfig(set, sig) => {
                // A certified reconfiguration locks the transition contents.
                // Later operator requests must wait for the next epoch rather
                // than replace the value honest validators are retrying.
                if self.epoch_ending_round.is_none() {
                    self.pending_reconfig = Some(Reconfig {
                        next_set: set,
                        evidence: vec![],
                        operator_sig: Some(sig),
                        jail: None,
                    });
                }
                Vec::new()
            }
            Event::RequestRemoval(x, proof) => {
                // Operator-submitted, evidence-justified removal. Validate before
                // staging: the target must be a current validator, the proof must
                // name that target, and the proof must verify against the current set.
                if self.epoch_ending_round.is_none()
                    && self.vset.contains(&x)
                    && proof.vote_a.inner.voter == x
                    && verify_equivocation_proof(&proof, &self.vset)
                {
                    self.pending_reconfig = Some(Reconfig {
                        next_set: self.vset.without(&x),
                        evidence: vec![proof],
                        operator_sig: None,
                        jail: None,
                    });
                }
                Vec::new()
            }
            Event::RequestJail(jail_vset, sig, jr) => {
                let jail_bytes = azbft_types::reconfig_signing_bytes_jail(
                    &jail_vset,
                    self.epoch,
                    &Some(jr.clone()),
                );
                if self.epoch_ending_round.is_none()
                    && self.vset.contains(&jr.offender)
                    && jail_vset == self.vset.without(&jr.offender)
                    && jr.until_epoch > self.epoch
                    && verify_operator_multisig(&self.operator_set, &jail_bytes, &sig)
                {
                    self.pending_reconfig = Some(Reconfig {
                        next_set: jail_vset,
                        evidence: vec![],
                        operator_sig: Some(sig),
                        jail: Some(jr),
                    });
                }
                Vec::new()
            }
            Event::RequestExecutionReconfig(set) => {
                if self.epoch_ending_round.is_none() && self.execution_reconfig_from.is_some() {
                    self.pending_reconfig = Some(Reconfig {
                        next_set: set,
                        evidence: vec![],
                        operator_sig: None,
                        jail: None,
                    });
                }
                Vec::new()
            }
            Event::SyncApply { blocks, commit_qc } => {
                if blocks.iter().any(|b| b.epoch != self.epoch) {
                    return Vec::new();
                }
                let mut replay_anchors = std::collections::BTreeMap::new();
                for block in &blocks {
                    let parent_anchor = if block.parent_qc.round.0 == 0 {
                        Some(self.chain_anchor)
                    } else {
                        replay_anchors
                            .get(&block.parent_qc.block_id)
                            .copied()
                            .or_else(|| {
                                self.tree
                                    .get(&block.parent_qc.block_id)
                                    .map(ChainAnchorV2::from_block)
                            })
                    };
                    let Some(parent_anchor) = parent_anchor else {
                        return Vec::new();
                    };
                    if validate_block_header_v2(block, parent_anchor, None).is_err() {
                        return Vec::new();
                    }
                    replay_anchors.insert(block.id(), ChainAnchorV2::from_block(block));
                }
                for b in blocks {
                    self.tree.insert(b);
                }
                let mut out = Vec::new();
                let _ = self.process_qc(&commit_qc, &mut out);
                out
            }
        }
    }

    /// Verify + absorb a QC: adopt it as `high_qc` if it is at least as high,
    /// run the 2-chain commit rule (rule 2) if the certified block is known,
    /// then advance to `qc.round + 1`. Commit commands are pushed onto `out`.
    ///
    /// Genesis (`qc.round == 0`) is trusted: it skips crypto verification and,
    /// because the genesis block is not in the tree, commits nothing — it only
    /// (potentially) triggers a round advance.
    pub(crate) fn process_qc(&mut self, qc: &QuorumCert, out: &mut Vec<Command>) -> bool {
        // (1) verify — genesis exempt. An unverified QC must not influence
        //     high_qc / the lock / commits, so we bail entirely on failure.
        //     Dispatch on the QC's OWN agg variant (verify_agg), not this node's
        //     forming scheme — so a secp QC from a peer verifies on a BLS node
        //     and vice-versa.
        // Verify over the vote_digest (block_id + round), NOT the bare block_id:
        // this is what binds the QC's round into the signature, so a valid QC can
        // no longer be relabelled to a different round. Returns false on failure
        // so callers (on_proposal) can refuse to vote on an unverifiable parent.
        if qc.round.0 != 0
            && verify_agg(
                &qc.agg,
                &vote_digest(&qc.block_id, qc.round),
                Domain::Vote,
                &self.vset,
            )
            .is_err()
        {
            return false;
        }

        // Inspect a known certified block before allowing the certificate to
        // move any local safety state. Once an epoch transition is locked, a
        // different reconfiguration must not replace it even if presented with
        // an otherwise valid QC.
        if let Some(reconfig) = self
            .tree
            .get(&qc.block_id)
            .and_then(|block| block.reconfig.as_ref())
        {
            if self.epoch_ending_round.is_some() && self.pending_reconfig.as_ref() != Some(reconfig)
            {
                return false;
            }
        }

        // (2) adopt as high_qc if it is at least as high. `>=` (not `>`) so a
        //     QC at the same round as the current high_qc — e.g. re-derived
        //     from a fresh proposal — is idempotently kept.
        if qc.round >= self.high_qc.round {
            self.high_qc = qc.clone();
        }

        // (3) rule 2 commit — needs the certified block in the tree. Clone the
        //     block out first so we are not holding an immutable borrow of
        //     `self.tree` while mutating `self.safety` and re-borrowing the
        //     tree mutably in `commit`.
        if let Some(b) = self.tree.get(&qc.block_id).cloned() {
            // A proposal alone is not an epoch boundary: it can lose its round
            // before gathering a quorum. Close the epoch only after a verified
            // QC certifies the known reconfiguration block. Until then, retain
            // pending_reconfig so a later leader can retry the same authorized
            // request.
            if let Some(reconfig) = &b.reconfig {
                self.epoch_ending_round = Some(b.round);
                // Keep the certified value staged. If the immediately-adjacent
                // child times out, an honest later leader re-emits this exact
                // transition until an adjacent two-chain commits one attempt.
                self.pending_reconfig = Some(reconfig.clone());
            }
            // Call `update_on_qc` once because it both raises the lock and
            // returns the commit target.
            if let Some(commit_id) = self.safety.update_on_qc(&b) {
                // `commit` returns ancestors first, with the commit target at
                // the tail. Each emitted block carries its linked certificate;
                // indexed iteration provides the following blocks used by that
                // linkage.
                let chain = self.tree.commit(commit_id);
                let n = chain.len();
                for i in 0..n {
                    let block = chain[i].clone();
                    // A reconfiguration proposal becomes an epoch boundary only
                    // when this exact block is the consecutive two-chain commit
                    // target. A timed-out attempt may later enter the durable
                    // prefix as an ancestor of a different consecutive pair;
                    // that linkage-level record is an inert attempt, not a second
                    // validator-set activation.
                    //
                    // Why skipping the ancestor never loses an effect. On the
                    // active path a deep ancestor carrying a DIFFERENT transition
                    // cannot arise at all: the voting gate below refuses any block
                    // past r0+1 unless it re-emits the exact locked transition, so
                    // no ordinary tail grows past the boundary; and `on_proposal`
                    // runs `process_qc` per parent QC, committing ancestors one at
                    // a time, so a multi-block batch with an uncommitted reconfig
                    // ancestor never accumulates. The only reachable deep-ancestor
                    // shape is a timed-out retry, whose tail carries the SAME
                    // transition — and all three skipped effects (jail insert,
                    // jail removal, consumed-evidence insert) are idempotent set
                    // writes the tail applies anyway.
                    //
                    // `SyncApply` does NOT replay those gates: it validates block
                    // headers and the final commit QC, nothing else. The invariant
                    // therefore rests on the host delivering an already-validated
                    // segment. Anyone loosening the voting gate is also loosening
                    // this. `synced_deep_ancestor_reconfig_applies_no_effects`
                    // pins the behaviour that follows.
                    if i + 1 == n {
                        if let Some(rc) = &block.reconfig {
                            if let Some(jr) = &rc.jail {
                                self.jailed.insert(jr.offender, jr.until_epoch);
                            } else {
                                for m in rc.next_set.members() {
                                    let id = &m.node_id;
                                    if !self.vset.contains(id) && self.jailed.contains_key(id) {
                                        self.jailed.remove(id);
                                    }
                                }
                            }
                            // Consumed-evidence replay protection: record each carried equivocation proof as
                            // consumed so the same act cannot be replayed in a later
                            // reconfig to punish the offender twice (consumed-evidence replay protection).
                            // Key = the act (voter, epoch, round); insert-only.
                            // Deterministic — every node applies the same committed block.
                            for p in &rc.evidence {
                                let v = &p.vote_a.inner;
                                self.consumed_evidence.insert((v.voter, v.epoch, v.round.0));
                            }
                        }
                    }
                    // Commit-certificate linkage:`commit_qc` certifies
                    // `child`; `child.parent_qc` certifies `block`.
                    //   • batch tail (i==n-1): a real 2-chain — child = b (the
                    //     block certified by the triggering `qc`), commit_qc = qc.
                    //   • i==n-2: child = commit_id block (chain[n-1]); its cert is
                    //     `b.parent_qc`, which certifies commit_id.
                    //   • earlier: child = chain[i+1], certified by chain[i+2].parent_qc.
                    let (child, commit_qc) = if i + 2 < n {
                        (chain[i + 1].clone(), chain[i + 2].parent_qc.clone())
                    } else if i + 1 < n {
                        (chain[i + 1].clone(), b.parent_qc.clone())
                    } else {
                        (b.clone(), qc.clone())
                    };
                    let cert = CommitCert {
                        block: block.clone(),
                        child,
                        commit_qc,
                    };
                    out.push(Command::Commit(Box::new(CommittedBlock {
                        block,
                        cert,
                        two_chain: i + 1 == n,
                    })));
                }
            }
        }

        // (4) advance.
        self.advance_round(Round(qc.round.0 + 1), RoundExit::Certified, out);
        true
    }

    /// Move to `target` if it is strictly ahead of the current round, entering
    /// the new round. Only a [`RoundExit::Certified`] advance clears the
    /// pacemaker backoff.
    pub(crate) fn advance_round(&mut self, target: Round, exit: RoundExit, out: &mut Vec<Command>) {
        if target > self.round {
            self.round = target;
            self.stale_answered.clear();
            self.stuck_in_round = false;
            if exit == RoundExit::Certified {
                self.pacemaker.on_progress(target);
            }
            self.enter_round(target, out);
        }
    }

    /// On entering a round: if this node is its leader, request a payload to
    /// propose; always (re)arm the round timer.
    pub(crate) fn enter_round(&mut self, r: Round, out: &mut Vec<Command>) {
        if self.leader_after_parent(r, &self.high_qc) == Some(self.me) {
            out.push(Command::CreatePayload {
                round: r,
                parent: self.high_qc.clone(),
            });
        }
        let leader = self.leader_after_parent(r, &self.high_qc);
        out.push(Command::SetTimer(
            r,
            self.pacemaker.timer_duration_led_by(r, leader),
        ));
    }

    /// Proposal path: verify author, store the block, absorb its parent QC
    /// (which may commit + advance), then run rule 1 — if we may vote, send the
    /// vote to the *next* round's leader and to the block's author, and arm our timer.
    pub(crate) fn on_proposal(&mut self, sp: Signed<Proposal>, now: LogicalTime) -> Vec<Command> {
        let mut out = Vec::new();
        let prop = sp.inner;
        let b = prop.block.clone();
        // Cross-epoch guard: ignore a proposal authored in a different epoch.
        if b.epoch != self.epoch {
            return out;
        }

        // The proposal must come from this round's leader, and its embedded
        // block must name that leader as author. Under a skip-absent schedule the
        // leader depends on the parent block; an unknown parent leaves it unknown
        // and the proposal is dropped (the host's unknown-parent recovery applies).
        let Some(leader) = self.proposal_leader(&b) else {
            return out;
        };
        let Some(pk) = self.vset.pubkey_of(&leader).map(|p| p.to_vec()) else {
            return out;
        };
        // Author-signature check (concern #3): Domain::Proposal over the borsh
        // bytes of the *whole* proposal (block + last_round_tc), so the TC the
        // leader attaches is covered too.
        let prop_bytes = borsh::to_vec(&prop).expect("borsh");
        if !azbft_crypto::keypair::verify(Domain::Proposal, &prop_bytes, &sp.sig, &pk) {
            return out;
        }
        if b.author != leader {
            return out;
        }
        // An authentic proposal from the round's leader: it is not absent.
        self.pacemaker.on_leader_proposed(&leader);
        if self.proposal_seen < b.round {
            self.proposal_seen = b.round;
        }

        // Operator authorization: every reconfig block must be authorized — either by a valid
        // operator signature (path 1) or by a pure evidence-removal (path 2,
        // Evidence-based removal). Unsigned / forged-sig reconfigs are rejected here so they can
        // never gather a quorum. `verify_reconfig_authorized` subsumes
        // `verify_removal_justified`: path 2 is the old evidence-only gate;
        // path 1 is the new operator-sig gate.
        if let Some(rc) = &b.reconfig {
            // From the execution handover height the set is execution's: no
            // operator path, and the host has already checked it names the set
            // its own execution derived. New members are what it is for.
            // A retry of an operator transition certified before the handover
            // keeps the rules it was certified under; refusing it would leave
            // the locked epoch with no way to end.
            let locked_operator_retry = self.epoch_ending_round.is_some()
                && self.pending_reconfig.as_ref() == Some(rc)
                && !crate::reconfig::is_execution_reconfig(rc);
            let execution_owned = !locked_operator_retry
                && self
                    .execution_reconfig_from
                    .is_some_and(|from| b.height >= from);
            if execution_owned {
                if !crate::reconfig::is_execution_reconfig(rc) {
                    return out;
                }
            } else if !verify_reconfig_authorized(&self.vset, rc, self.epoch, &self.operator_set) {
                return out;
            }
            // Consumed-evidence replay protection: reject a reconfig that reuses an already-consumed
            // equivocation act — the same proof replayed to slash/remove the same
            // offender twice (consumed-evidence replay protection). The act key (voter, epoch, round) is
            // read from vote_a; only a genuinely-consumed act matches, so a fresh or
            // unrelated proof is unaffected. Conservative: any consumed proof in the
            // bundle rejects the whole reconfig (the proposer resubmits with only
            // fresh evidence) — safe, since rejecting a proposal is at worst liveness.
            // Deterministic across nodes (consumed_evidence derives from committed
            // blocks); empty evidence (trusted / plain operator reconfig) is a no-op.
            if rc.evidence.iter().any(|p| {
                let v = &p.vote_a.inner;
                self.consumed_evidence
                    .contains(&(v.voter, v.epoch, v.round.0))
            }) {
                return out;
            }
            // BLS validator adoption: PoP-on-adoption, gated on CONTENT (the next_set carrying
            // BLS columns), NOT on this node's forming scheme. `verify_vset_pops`
            // requires a valid proof-of-possession for every member that presents
            // a BLS key and skips secp-only members (empty BLS column), so this
            // is a no-op for a secp-only next_set and leaves the secp path
            // byte-identical — while making the rogue-key defense LOCAL and
            // independent of the transitive-QC argument: a crafted BLS key can
            // never enter the fast-aggregate set via reconfig, even if THIS node
            // happens to form secp. Reject the reconfig if any BLS key lacks a
            // valid PoP.
            if !azbft_crypto::aggregator::verify_vset_pops(&rc.next_set) {
                return out;
            }
            if self.epoch_ending_round.is_some() && self.pending_reconfig.as_ref() != Some(rc) {
                return out;
            }
            for m in rc.next_set.members() {
                let id = &m.node_id;
                if !execution_owned && !self.vset.contains(id) {
                    match self.jailed.get(id) {
                        Some(&until_epoch) if self.epoch >= until_epoch => {}
                        Some(_) => {
                            return out;
                        }
                        None => {
                            return out;
                        }
                    }
                }
            }
        }

        let parent_anchor = if b.parent_qc.round.0 == 0 {
            Some(self.chain_anchor)
        } else {
            self.tree
                .get(&b.parent_qc.block_id)
                .map(ChainAnchorV2::from_block)
        };
        let Some(parent_anchor) = parent_anchor else {
            return out;
        };
        if validate_block_header_v2(&b, parent_anchor, Some(now)).is_err() {
            return out;
        }

        // Store, then verify-and-absorb the block's parent QC. process_qc does
        // the crypto verification of parent_qc, so the lock the vote below
        // relies on can only have been raised by a verified QC.
        self.tree.insert(b.clone());
        let parent_qc = b.parent_qc.clone();
        // CRITICAL (qc-round-auth): the vote below relies on `b.parent_qc.round`
        // (make_vote's lock check `parent_qc.round >= preferred_round`). That
        // round is only trustworthy if parent_qc actually verifies — with
        // `vote_digest` binding the round into the vote signature, a forged or
        // round-relabelled parent_qc now fails verification in process_qc. Its
        // failure must therefore GATE the vote: otherwise a Byzantine leader
        // could present an unverifiable parent_qc carrying an inflated round to
        // bypass the lock and admit conflicting commits. Genesis (round 0) is
        // exempt (process_qc returns true for it).
        if !self.process_qc(&parent_qc, &mut out) {
            return out;
        }

        // HIGH (round-proof, HotStuff round-proof rule): b.round must be
        // JUSTIFIED — either by a QC at round-1 (parent_qc, verified just above) or
        // by a valid TC for round-1. Without this a Byzantine leader could propose
        // at an arbitrary future round, forcing honest nodes to jump
        // last_voted_round and stalling the view (censorship griefing).
        if b.parent_qc.round.0 + 1 == b.round.0 {
            // Consecutive: parent_qc directly justifies the round; a consecutive
            // proposal carries no TC (matches the local proposal builder).
            if prop.last_round_tc.is_some() {
                return out;
            }
        } else {
            // Non-consecutive: the round can only have advanced via timeout, so a
            // TC proving a quorum timed out `b.round - 1` is required.
            let Some(tc) = prop.last_round_tc.as_ref() else {
                return out;
            };
            if tc.round.0 + 1 != b.round.0 {
                return out;
            }
            // The timeout certificate's highest QC is the only safe parent for
            // the first proposal after a view change. Merely checking the TC's
            // round/aggregate is insufficient: a leader whose local `high_qc`
            // is stale could otherwise attach a valid TC while extending a
            // different, older QC. With two-chain finality that can make
            // different replicas commit sibling blocks depending on message
            // arrival order. QC aggregates are not canonical (different quorum
            // subsets may certify the same block), so bind identity by
            // `(round, block_id)`, not by aggregate bytes.
            if tc.high_qc.round != b.parent_qc.round || tc.high_qc.block_id != b.parent_qc.block_id
            {
                return out;
            }
            // A valid TC carries a quorum of timeout signatures over both the
            // epoch and round. Binding the epoch prevents replay after an epoch
            // transition resets the round counter.
            if verify_agg(
                &tc.agg,
                &timeout_digest(self.epoch, tc.round),
                Domain::Timeout,
                &self.vset,
            )
            .is_err()
            {
                return out;
            }
        }

        // Epoch-boundary gate: the adjacent child at R0+1 remains the preferred
        // commit vehicle. If it times out, later rounds may progress only by
        // re-emitting the exact certified transition. This preserves the old
        // anti-fork property (no ordinary epoch-e tail can grow beyond the
        // boundary) without making R0+1 a single liveness point. A QC for a
        // retry moves `epoch_ending_round`, opening exactly one adjacent-child
        // round for the existing two-chain ECC.
        if let Some(r0) = self.epoch_ending_round {
            if b.round.0 > r0.0 + 1
                && (self.pending_reconfig.is_none()
                    || b.reconfig.as_ref() != self.pending_reconfig.as_ref())
            {
                return out;
            }
        }

        // Rule 1: may we vote? (round-monotone AND extends the lock.)
        if let Some(vote) = self.safety.make_vote(&b, self.me) {
            // Re-arm our own timer for this block's round.
            out.push(Command::SetTimer(
                b.round,
                self.pacemaker
                    .timer_duration_led_by(b.round, Some(b.author)),
            ));
            // Vote is signed over vote_digest(block_id, round) under Domain::Vote
            // — binding the round so a valid QC cannot be relabelled — matching
            // how the QC verifier checks an aggregated cert. The single-vote
            // scheme follows the forming scheme: secp single-sig on a secp
            // network, a BLS single-sig (folded later into one aggregate) on a
            // BLS network.
            let vd = vote_digest(&vote.block_id, vote.round);
            let sig = match self.agg_scheme {
                AggScheme::Secp => self.signer.sign(Domain::Vote, &vd.0),
                AggScheme::Bls => self.signer.sign_bls_vote(&vd.0),
            };
            // The next leader extends `b`, so its liveness QC is `b.parent_qc`, which
            // is known now — before any QC on `b` exists.
            let next =
                self.vset
                    .leader_after(Round(b.round.0 + 1), self.leader_mode, Some(&b.parent_qc));
            let vote = ConsensusMessage::Vote(Signed { inner: vote, sig });
            // Also give the vote to the block's own leader (monad-bft routes votes
            // to the current and the next leader). Any collector that reaches quorum
            // forms the QC, so if the next leader is down the current one still
            // certifies `b`, enters the next round and carries the QC in its
            // timeout's `high_qc`: the TC then extends `b` instead of dropping it.
            if b.author != next {
                out.push(Command::Send(b.author, vote.clone()));
            }
            out.push(Command::Send(next, vote));
        }
        out
    }

    /// Vote path (run by the round's vote collector = leader of `round+1`):
    /// verify the vote, detect equivocation, collect it, and once collected
    /// stake crosses quorum build the QC and feed it through [`process_qc`].
    ///
    /// Signature verification is HOISTED above the `qc_formed` early-return
    /// (equivocation detection): every arriving vote is verified before checking whether the
    /// QC already formed, so a late equivocating vote is never silently dropped
    /// by the early-return before its double-sign is observed.
    pub(crate) fn on_vote(&mut self, sv: Signed<Vote>) -> Vec<Command> {
        let mut out = Vec::new();
        let vote = sv.inner.clone(); // NOTE: .clone() — sv is reused below (must stay whole)
        if vote.epoch != self.epoch {
            return out;
        }
        // —— signature verification HOISTED above the qc_formed early-return ——
        // The single-vote signature scheme follows the forming scheme: a
        // secp single-sig verify on a secp network, a BLS single-sig verify on a
        // BLS network. (The QC built from these is verified again per-variant in
        // process_qc; this hoisted check keeps an unverified/equivocating vote
        // from ever being collected.)
        let vd = vote_digest(&vote.block_id, vote.round);
        let verified = match self.agg_scheme {
            AggScheme::Secp => {
                let Some(pk) = self.vset.pubkey_of(&vote.voter).map(|p| p.to_vec()) else {
                    return out;
                };
                azbft_crypto::keypair::verify(Domain::Vote, &vd.0, &sv.sig, &pk)
            }
            AggScheme::Bls => {
                let Some(pk_bytes) = self.vset.bls_pubkey_of(&vote.voter).map(|p| p.to_vec())
                else {
                    return out;
                };
                match (
                    azbft_crypto::bls::BlsPublicKey::from_bytes(&pk_bytes),
                    azbft_crypto::bls::BlsSignature::from_bytes(&sv.sig),
                ) {
                    (Some(pk), Some(sig)) => {
                        azbft_crypto::bls::bls_verify(Domain::Vote, &vd.0, &sig, &pk)
                    }
                    _ => false,
                }
            }
        };
        if !verified {
            return out;
        }
        // —— equivocation detection side-branch ——
        // Emitted BEFORE the QC/quorum section below, so when the same vote both
        // detects an equivocation AND completes a quorum, `Command::Equivocation`
        // precedes the `process_qc` commands in `out` (and `handle()` still
        // prepends any `Persist` at index 0). Consumers must not assume evidence
        // is ordered after a co-emitted Commit.
        match self.voted.get(&(vote.round, vote.voter)) {
            Some(prev) if prev.inner.block_id != vote.block_id => {
                out.push(Command::Equivocation(EquivocationProof::new(
                    prev.clone(),
                    sv.clone(),
                )));
            }
            None => {
                self.voted.insert((vote.round, vote.voter), sv.clone());
            }
            Some(_) => {} // same block_id again: nothing
        }
        // —— UNCHANGED below: QC/quorum (old in-place verify block deleted, now hoisted) ——
        let key = (vote.round, vote.block_id);
        if self.qc_formed.contains_key(&key) {
            return out;
        }
        let entry = self.votes.entry(key).or_default();
        if !entry.iter().any(|(n, _)| *n == vote.voter) {
            entry.push((vote.voter, sv.sig));
        }
        let power: u64 = entry
            .iter()
            .map(|(n, _)| self.vset.stake_of(n).unwrap_or(0))
            .sum();
        if power >= self.vset.quorum() {
            // Form the QC with this node's chain-constant scheme. (Verification
            // downstream dispatches per-variant, so peers on either scheme can
            // verify what we form.)
            let agg = match self.agg_scheme {
                AggScheme::Secp => SecpMultiSig::aggregate(entry),
                AggScheme::Bls => BlsMultiSig::aggregate(entry),
            };
            let qc = QuorumCert {
                block_id: vote.block_id,
                round: vote.round,
                agg,
            };
            self.qc_formed.insert(key, ());
            let _ = self.process_qc(&qc, &mut out);
        }
        out
    }

    /// Freeze the signed header fields and exact parent token before an
    /// execution adapter is asked to prepare transaction bytes.
    pub fn proposal_build_context(
        &self,
        round: Round,
        parent: &QuorumCert,
        now: LogicalTime,
    ) -> Option<ProposalBuildContext> {
        if round != self.round
            || self.leader_after_parent(round, parent) != Some(self.me)
            || parent != &self.high_qc
        {
            return None;
        }
        let parent_anchor = if parent.round.0 == 0 {
            self.chain_anchor
        } else {
            ChainAnchorV2::from_block(self.tree.get(&parent.block_id)?)
        };
        let next_anchor = parent_anchor.next_for_proposal(now).ok()?;
        Some(ProposalBuildContext {
            epoch: self.epoch,
            round,
            parent: parent.clone(),
            height: next_anchor.height,
            timestamp_ms: next_anchor.timestamp_ms,
            proposer: self.me,
        })
    }

    /// Payload-ready path (run by the round leader after it asked for a
    /// payload): re-check the frozen parent token, build the exact prepared
    /// header, attach the justifying TC, sign, and broadcast the proposal.
    pub(crate) fn on_payload_ready(
        &mut self,
        context: ProposalBuildContext,
        payload: Vec<u8>,
        now: LogicalTime,
    ) -> Vec<Command> {
        let mut out = Vec::new();
        // An async Prepare result is stale as soon as epoch, round, leader or
        // high-QC changes. It must never attach to the newer consensus state.
        if context.epoch != self.epoch
            || context.round != self.round
            || self.leader_after_parent(context.round, &context.parent) != Some(self.me)
            || context.proposer != self.me
            || context.parent != self.high_qc
        {
            return out;
        }
        let parent_anchor = if context.parent.round.0 == 0 {
            self.chain_anchor
        } else {
            let Some(parent) = self.tree.get(&context.parent.block_id) else {
                return out;
            };
            ChainAnchorV2::from_block(parent)
        };
        // From the execution handover an operator request staged earlier can
        // no longer be voted. Drop it unless it is already certified.
        if self.epoch_ending_round.is_none()
            && self
                .execution_reconfig_from
                .is_some_and(|from| context.height >= from)
            && self
                .pending_reconfig
                .as_ref()
                .is_some_and(|rc| !crate::reconfig::is_execution_reconfig(rc))
        {
            self.pending_reconfig = None;
        }
        let block = Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: context.height,
            timestamp_ms: context.timestamp_ms,
            epoch: self.epoch,
            round: context.round,
            parent_qc: context.parent.clone(),
            payload_hash: blake3_id(&payload),
            author: self.me,
            // Before certification this carries a staged request. Afterwards
            // it carries the immutable, certified request again so a timeout
            // cannot permanently close the only adjacent-child window.
            reconfig: self.pending_reconfig.clone(),
        };
        if validate_block_header_v2(&block, parent_anchor, Some(now)).is_err() {
            return out;
        }
        // Attach the TC only when the round was reached via TIMEOUT — i.e. this is
        // NOT a consecutive extension of high_qc — AND the TC justifies exactly
        // this round jump (tc.round + 1 == round). A consecutive proposal must
        // carry no TC: on_proposal's round-proof (and the proposal admission rule)
        // rejects consecutive+TC.
        let last_round_tc = if context.parent.round.0 + 1 == context.round.0 {
            None
        } else {
            self.high_tc
                .clone()
                .filter(|tc| tc.round.0 + 1 == context.round.0)
        };
        let prop = Proposal {
            block,
            last_round_tc,
        };
        let sig = self
            .signer
            .sign(Domain::Proposal, &borsh::to_vec(&prop).expect("borsh"));
        out.push(Command::Broadcast(ConsensusMessage::Proposal(Signed {
            inner: prop,
            sig,
        })));
        out
    }

    /// Local-timeout path: if the fired timer is for the current round, bump
    /// the pacemaker backoff and broadcast a `Timeout` carrying our `high_qc`.
    pub(crate) fn on_local_timeout(&mut self, r: Round) -> Vec<Command> {
        let mut out = Vec::new();
        // Ignore a stale timer for a round we've already left.
        if r != self.round {
            return out;
        }
        self.safety.mark_timeout(r);
        self.pacemaker.on_local_timeout(r);
        // Its leader's proposal never came: count the leader silent, once a round.
        let leader = self.leader_after_parent(r, &self.high_qc);
        if self.proposal_seen < r && self.silent_counted < r {
            self.silent_counted = r;
            if let Some(leader) = leader {
                self.pacemaker.on_leader_silent(leader);
            }
        }
        // Stuck: answer the stale timeouts of this pass (again).
        self.stale_answered.clear();
        self.stuck_in_round = true;
        let t = Timeout {
            epoch: self.epoch,
            round: r,
            high_qc: self.high_qc.clone(),
            sender: self.me,
        };
        // Timeout is signed over timeout_digest(epoch, round) under Domain::Timeout
        // — binding the epoch so the resulting TC cannot be replayed in a later
        // epoch (round resets to 1 on an epoch roll).
        let sig = self
            .signer
            .sign(Domain::Timeout, &timeout_digest(self.epoch, r).0);
        out.push(Command::Broadcast(ConsensusMessage::Timeout(Signed {
            inner: t,
            sig,
        })));
        // Self re-arm with backed-off duration (pacemaker already counted this
        // timeout). Hosts only deliver timers; they never re-arm.
        out.push(Command::SetTimer(
            r,
            self.pacemaker.timer_duration_led_by(r, leader),
        ));
        out
    }

    /// Remote-timeout path (run by anyone collecting timeouts): verify the
    /// timeout, absorb the QC it carries (verified via [`process_qc`]), collect
    /// it, and once collected stake crosses quorum build the TC, adopt it as
    /// `high_tc`, and advance to `round + 1`.
    pub(crate) fn on_remote_timeout(&mut self, st: Signed<Timeout>) -> Vec<Command> {
        let mut out = Vec::new();
        let t = st.inner;
        // Cross-epoch guard: ignore a timeout from a different epoch.
        if t.epoch != self.epoch {
            return out;
        }

        // Verify the timeout signature (Domain::Timeout over timeout_digest(epoch,
        // round)). t.epoch == self.epoch is enforced by the cross-epoch guard above.
        let Some(pk) = self.vset.pubkey_of(&t.sender).map(|p| p.to_vec()) else {
            return out;
        };
        if !azbft_crypto::keypair::verify(
            Domain::Timeout,
            &timeout_digest(t.epoch, t.round).0,
            &st.sig,
            &pk,
        ) {
            return out;
        }

        // A validator still timing out a round this node has left: after a cold
        // restart it lost the timeouts it had collected, and this node, already
        // past that round, will not time it out again, so neither side can finish
        // a certificate. Answer with this node's timeout for that round and its
        // high_qc: with the others' timeouts the peer forms the TC, and the QC
        // moves it on if the round ended with one. This node cannot vote in a
        // round it has left, so the timeout promises nothing new; the signature
        // binds only (epoch, round). Each (sender, round) is answered once per
        // round or local timeout of this node, so an answer reaching a validator
        // that has also moved on is not answered back in a loop. Only a node that
        // has itself timed out its current round answers: while the chain makes
        // progress a lagging validator catches up as before, and the answer
        // changes nothing about how rounds advance.
        // Only rounds just behind this one are answered: the restart split above is one
        // round behind, and an unbounded window would let a faulty validator make a stuck
        // node sign (and remember) one answer for every past round.
        if t.round < self.round
            && self.round.0 - t.round.0 <= STALE_ANSWER_WINDOW
            && t.sender != self.me
            && self.stuck_in_round
        {
            if !self.stale_answered.insert((t.sender, t.round)) {
                return out;
            }
            let reply = Timeout {
                epoch: self.epoch,
                round: t.round,
                high_qc: self.high_qc.clone(),
                sender: self.me,
            };
            let sig = self
                .signer
                .sign(Domain::Timeout, &timeout_digest(self.epoch, t.round).0);
            out.push(Command::Send(
                t.sender,
                ConsensusMessage::Timeout(Signed { inner: reply, sig }),
            ));
            return out;
        }

        if self.tc_formed.contains_key(&t.round) {
            return out;
        }

        // Absorb the timeout's carried high_qc — process_qc verifies it (so an
        // unverified QC riding in on a timeout can't move our lock) and may
        // commit / advance.
        let hq = t.high_qc.clone();
        let _ = self.process_qc(&hq, &mut out);

        let entry = self.timeouts.entry(t.round).or_default();
        if !entry.iter().any(|(n, _, _)| *n == t.sender) {
            entry.push((t.sender, st.sig, t.high_qc));
        }

        let power: u64 = entry
            .iter()
            .map(|(n, _, _)| self.vset.stake_of(n).unwrap_or(0))
            .sum();
        // A future-view timeout cannot move the core by itself: one Byzantine
        // validator could otherwise force arbitrary view jumps. Once verified,
        // de-duplicated timeout stake exceeds the maximum Byzantine stake (f+1),
        // echo that round locally. Persist-before-broadcast is supplied by
        // `handle` because `mark_timeout` advances the vote watermark.
        let relay_threshold = self
            .vset
            .total_stake()
            .saturating_sub(self.vset.quorum())
            .saturating_add(1);
        if power >= relay_threshold
            && t.round > self.round
            && t.round > self.safety.last_voted_round
        {
            self.safety.mark_timeout(t.round);
            let relay = Timeout {
                epoch: self.epoch,
                round: t.round,
                high_qc: self.high_qc.clone(),
                sender: self.me,
            };
            let sig = self
                .signer
                .sign(Domain::Timeout, &timeout_digest(self.epoch, t.round).0);
            out.push(Command::Broadcast(ConsensusMessage::Timeout(Signed {
                inner: relay,
                sig,
            })));
        }

        if power >= self.vset.quorum() {
            let sigs: Vec<(NodeId, Vec<u8>)> =
                entry.iter().map(|(n, s, _)| (*n, s.clone())).collect();
            // TC aggregate is ALWAYS secp — NOT matched on agg_scheme (unlike the QC
            // site). Timeout single-sigs are signed under Domain::Timeout with the
            // secp key (see on_local_timeout's `self.signer.sign(Domain::Timeout,..)`)
            // and verified as secp, regardless of network scheme — so there are no
            // BLS sigs to aggregate here, and BLS-aggregating secp bytes would be
            // garbage. The TC's agg is also never verify_agg'd nor hashed into
            // Block.id(), so the scheme is immaterial; secp is the correct sig type.
            // If timeout vote signatures adopt BLS in the future, revisit this site.
            let agg = SecpMultiSig::aggregate(&sigs);
            // The TC carries the highest high_qc among the timeouts it
            // aggregates, so the next leader proposes on the freshest cert.
            let best_high_qc = entry
                .iter()
                .map(|(_, _, q)| q.clone())
                .max_by_key(|q| q.round.0)
                .unwrap_or_else(QuorumCert::genesis);
            let tc = TimeoutCert {
                round: t.round,
                agg,
                high_qc: best_high_qc.clone(),
            };
            // Keep the proposal parent and the TC's certified high-QC in lockstep.
            // `process_qc` above normally already installed this value, but an
            // equal-round certificate can arrive in a different order; assigning
            // the selected TC value here makes the next leader's parent explicit.
            if best_high_qc.round >= self.high_qc.round {
                self.high_qc = best_high_qc;
            }
            self.tc_formed.insert(t.round, ());
            // Adopt as high_tc only if it is the freshest TC seen (monotonic, like
            // high_qc): a late TC for an older round must not clobber a newer one,
            // which would make make_proposal emit a non-consecutive proposal carrying
            // a stale TC that peers reject under the round-proof — burning a view.
            if self.high_tc.as_ref().is_none_or(|h| tc.round > h.round) {
                self.high_tc = Some(tc);
            }
            self.advance_round(Round(t.round.0 + 1), RoundExit::TimedOut, &mut out);
        }
        out
    }
}

#[cfg(test)]
mod tests;
