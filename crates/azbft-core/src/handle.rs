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
        self.advance_round(Round(qc.round.0 + 1), out);
        true
    }

    /// Move to `target` if it is strictly ahead of the current round, resetting
    /// the pacemaker backoff and entering the new round.
    pub(crate) fn advance_round(&mut self, target: Round, out: &mut Vec<Command>) {
        if target > self.round {
            self.round = target;
            self.pacemaker.on_progress(target);
            self.enter_round(target, out);
        }
    }

    /// On entering a round: if this node is its leader, request a payload to
    /// propose; always (re)arm the round timer.
    pub(crate) fn enter_round(&mut self, r: Round, out: &mut Vec<Command>) {
        if self.leader(r) == self.me {
            out.push(Command::CreatePayload {
                round: r,
                parent: self.high_qc.clone(),
            });
        }
        out.push(Command::SetTimer(r, self.pacemaker.timer_duration(r)));
    }

    /// Proposal path: verify author, store the block, absorb its parent QC
    /// (which may commit + advance), then run rule 1 — if we may vote, send the
    /// vote to the *next* round's leader and arm our timer.
    pub(crate) fn on_proposal(&mut self, sp: Signed<Proposal>, now: LogicalTime) -> Vec<Command> {
        let mut out = Vec::new();
        let prop = sp.inner;
        let b = prop.block.clone();
        // Cross-epoch guard: ignore a proposal authored in a different epoch.
        if b.epoch != self.epoch {
            return out;
        }

        // The proposal must come from this round's leader, and its embedded
        // block must name that leader as author.
        let leader = self.leader(b.round);
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

        // Operator authorization: every reconfig block must be authorized — either by a valid
        // operator signature (path 1) or by a pure evidence-removal (path 2,
        // Evidence-based removal). Unsigned / forged-sig reconfigs are rejected here so they can
        // never gather a quorum. `verify_reconfig_authorized` subsumes
        // `verify_removal_justified`: path 2 is the old evidence-only gate;
        // path 1 is the new operator-sig gate.
        if let Some(rc) = &b.reconfig {
            if !verify_reconfig_authorized(&self.vset, rc, self.epoch, &self.operator_set) {
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
                if !self.vset.contains(id) {
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
                self.pacemaker.timer_duration(b.round),
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
            let next = self.leader(Round(b.round.0 + 1));
            out.push(Command::Send(
                next,
                ConsensusMessage::Vote(Signed { inner: vote, sig }),
            ));
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
        if round != self.round || self.leader(round) != self.me || parent != &self.high_qc {
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
            || self.leader(context.round) != self.me
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
        out.push(Command::SetTimer(r, self.pacemaker.timer_duration(r)));
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

        if self.tc_formed.contains_key(&t.round) {
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
            self.advance_round(Round(t.round.0 + 1), &mut out);
        }
        out
    }
}

#[cfg(test)]
mod tests {
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
            core.advance_round(round, &mut Vec::new());
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
                let Command::Broadcast(ConsensusMessage::Timeout(echo)) = &commands[echo_index]
                else {
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
        assert!(commands.iter().any(
            |command| matches!(command, Command::SetTimer(round, _) if *round == start_round)
        ));
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
            .filter_map(|(index, command)| {
                matches!(command, Command::SetTimer(_, _)).then_some(index)
            })
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
        let proof = find_equivocation(&out2)
            .expect("second conflicting vote must emit Command::Equivocation");
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
}
