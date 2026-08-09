//! Consensus state machine state + the `Signer` injection point.
//!
//! `ConsensusCore` is the sans-IO core of the Jolteon 2-chain BFT protocol.
//! It owns no clocks, no sockets, no threads: every effect leaves as a
//! [`Command`](crate::command::Command), every input arrives as an
//! [`Event`](crate::event::Event). The only injected capability is signing,
//! behind the [`Signer`] trait — and even that is deterministic (a signature
//! is a pure function of key + message), so the whole `handle` path stays a
//! pure `Event -> Vec<Command>` transition.

use crate::command::SafetySnapshot;
use crate::{blocktree::BlockTree, pacemaker::Pacemaker};
use azbft_crypto::domain::Domain;
use azbft_safety::SafetyRules;
use azbft_types::{Reconfig, *};
use std::collections::{BTreeMap, BTreeSet};

/// Private-key signing is injected so the core stays free of key material and
/// stays deterministic. Implementations must return a signature that is a pure
/// function of `(key, domain, msg)` — no randomized nonces that vary per call
/// in a way the harness can observe. (`azbft-crypto`'s ECDSA-over-prehash signing
/// is deterministic, so the `Keypair` implementation satisfies this.)
///
/// `Send` is required so a host can own the core on a multi-threaded runtime
/// and move it across worker threads. It is a marker-only bound: it changes no
/// behaviour and every signer here wraps a `Keypair`, which is already `Send`.
pub trait Signer: Send {
    fn sign(&self, d: Domain, msg: &[u8]) -> Vec<u8>;
    fn node_id(&self) -> NodeId;
    /// Produce this node's BLS single signature over `digest(Domain::Vote, msg)`
    /// — the per-validator vote signature that `BlsMultiSig::aggregate` folds
    /// into a QC. Only called when the core's [`AggScheme`] is `Bls`. The
    /// default returns empty bytes (suitable for secp-only signers, which are
    /// never invoked on a BLS network); a dual-key signer overrides it.
    fn sign_bls_vote(&self, _msg: &[u8]) -> Vec<u8> {
        Vec::new()
    }
}

/// QC forming scheme selected once when a core is constructed.
///
/// Verification does not read this setting. It dispatches on each certificate's
/// own `AggSig` variant, so historical certificates remain verifiable.
/// Timeout votes and TCs always use secp256k1 and are independent of this
/// setting.
///
/// `AggScheme::default()` is `Bls` for callers that explicitly default a
/// configuration. Compatibility constructors form secp256k1 QCs; callers that
/// want BLS pass `AggScheme::Bls` to an explicit-scheme constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AggScheme {
    /// A sorted set of per-validator secp256k1 signatures.
    Secp,
    /// A single BLS aggregate signature plus its sorted signer set.
    #[default]
    Bls,
}

/// Collected per-`(round, block_id)` vote signatures, keyed for QC formation.
type VoteSet = Vec<(NodeId, Vec<u8>)>;
/// Collected per-`round` timeout records: `(sender, sig, that sender's high_qc)`.
type TimeoutSet = Vec<(NodeId, Vec<u8>, QuorumCert)>;

/// The replicated-state-machine core. One per validator.
pub struct ConsensusCore {
    /// This node's identity.
    pub(crate) me: NodeId,
    /// The epoch this node currently operates in. Stamped onto every
    /// `Block`/`Vote`/`Timeout` this core authors. (Genesis starts at epoch 0.)
    pub(crate) epoch: u64,
    /// Validator set for the current epoch.
    pub(crate) vset: ValidatorSet,
    /// Leader-selection mode (chain constant; `RoundRobin` default). Set via
    /// `set_leader_mode` at construction and re-applied on every epoch roll from the
    /// same config, so every node stays uniform — a divergence would fork. Never
    /// serialized (not part of the wire `ValidatorSet`).
    pub(crate) leader_mode: LeaderSchedule,
    /// The round this node currently considers itself in.
    pub(crate) round: Round,
    /// Highest QC this node has verified — drives proposal `parent_qc` and
    /// the safety lock.
    pub(crate) high_qc: QuorumCert,
    /// Highest TC formed/seen — lets the next leader justify a round jump.
    pub(crate) high_tc: Option<TimeoutCert>,
    /// The two safety rules (vote monotonicity + lock / commit).
    pub(crate) safety: SafetyRules,
    /// All blocks we've seen, plus commit bookkeeping.
    pub(crate) tree: BlockTree,
    /// Height/time predecessor for a block whose parent QC is this epoch's
    /// genesis QC. Carried across epoch rolls and recovery.
    pub(crate) chain_anchor: ChainAnchorV2,
    /// Round timer / exponential backoff.
    pub(crate) pacemaker: Pacemaker,
    /// Injected signer.
    pub(crate) signer: Box<dyn Signer>,
    /// Vote collection: `(round, block_id) -> [(voter, sig)]`. A QC forms once
    /// the collected stake crosses quorum.
    pub(crate) votes: BTreeMap<(Round, Hash), VoteSet>,
    /// Guard: a `(round, block_id)` whose QC has already formed, so we never
    /// re-fire `process_qc` for the same certificate.
    pub(crate) qc_formed: BTreeMap<(Round, Hash), ()>,
    /// Timeout collection: `round -> [(sender, sig, high_qc)]`.
    pub(crate) timeouts: BTreeMap<Round, TimeoutSet>,
    /// Guard: a round whose TC has already formed.
    pub(crate) tc_formed: BTreeMap<Round, ()>,
    /// A reconfiguration staged to ride out on the next block this node authors.
    /// Once a QC certifies it, the exact value stays here as the immutable
    /// transition lock and is re-emitted after view changes until an adjacent
    /// two-chain commits one attempt. `None` when no reconfiguration or removal
    /// is pending. Set by
    /// `RequestReconfig` for an operator-authorized change and `RequestRemoval`
    /// for an evidence-justified removal. Exactly one pending reconfig can be
    /// staged at a time; a new `Request*` may replace an uncertified request but
    /// cannot replace a transition after its first QC.
    pub(crate) pending_reconfig: Option<Reconfig>,
    /// The latest round carrying the locked transition that obtained a QC: set in
    /// `process_qc` when a verified QC certifies a known reconfiguration block
    /// (to that block's round). Read by the epoch-ending vote gate, which permits
    /// its adjacent child and otherwise only an exact retry of `pending_reconfig`.
    /// `None` until a reconfiguration is certified; until then the gate never fires.
    pub(crate) epoch_ending_round: Option<Round>,
    /// First verified vote seen from each (round, voter) pair. Used by the
    /// equivocation detector in `on_vote` (equivocation detection): when a second verified
    /// vote from the same (round, voter) arrives with a DIFFERENT block_id, that
    /// pair is a confirmed double-sign and a `Command::Equivocation` is emitted.
    /// Only the FIRST vote is stored; on conflict we do NOT overwrite (the first
    /// vote stays as the stable antecedent for the proof).
    ///
    /// Key omits epoch deliberately: the core is single-epoch and rebuilt fresh
    /// on every epoch roll (so this map resets), and `on_vote`'s `vote.epoch !=
    /// self.epoch` guard drops foreign-epoch votes before this map is touched —
    /// so a `(round, voter)` key can never conflate two epochs. Grows like the
    /// sibling `votes`/`qc_formed` maps (unpruned within an epoch).
    pub(crate) voted: BTreeMap<(Round, NodeId), Signed<Vote>>,
    /// Operator authority carried unchanged across epoch transitions.
    /// A single-key set uses the raw signature encoding; a host can provide an
    /// M-of-N set with [`ConsensusCore::with_operator_set`].
    pub(crate) operator_set: OperatorSet,
    /// Chain-constant QC forming scheme. Certificate verification dispatches
    /// on the certificate's own variant.
    pub(crate) agg_scheme: AggScheme,
    /// Temporarily removed validators and their earliest return epochs.
    ///
    /// Entries are inserted when jail reconfigurations commit, carried across
    /// epoch transitions, and removed when authorized returns commit.
    ///
    /// **Known alpha limitation:** block-sync responses and checkpoints do not
    /// yet carry this map. See `STATUS.md` for the public support boundary.
    pub(crate) jailed: BTreeMap<NodeId, u64>,
    /// Consumed-evidence replay protection: consumed-evidence ledger. The set of equivocation acts
    /// `(voter, epoch, round)` already punished by a committed reconfig, so the same
    /// proof cannot be replayed to slash or remove the offender twice.
    /// **Insert-only** (monotonic): once an act is punished its proof is spent forever.
    /// Node-local derived state, never serialized on the wire. Every node inserts the
    /// same keys from the same committed reconfig blocks, so it is deterministically
    /// consistent across nodes. Durability parallels `jailed` (carried on epoch roll,
    /// reconstructed on checkpoint-adopt, applied on sync/gossip catch-up, persisted
    /// across restart), but simpler: insert-only needs no `vset` at the catch-up sites.
    pub(crate) consumed_evidence: BTreeSet<(NodeId, u64, u64)>,
}

impl ConsensusCore {
    /// Build a core with an injected signer. Starts in round 1 with the
    /// genesis QC as `high_qc`. Call [`ConsensusCore::start`] to actually
    /// enter round 1 (request a payload if leader, arm the timer).
    ///
    /// Equivalent to [`ConsensusCore::with_signer_restored`] with no restored
    /// safety state (fresh `SafetyRules::default()`).
    pub fn with_signer(
        epoch: u64,
        vset: ValidatorSet,
        base_timer: u64,
        signer: Box<dyn Signer>,
        operator_pk: Vec<u8>,
    ) -> Self {
        Self::with_signer_restored(epoch, vset, base_timer, signer, None, operator_pk)
    }

    /// Like [`with_signer`](Self::with_signer) but selects the QC forming
    /// scheme. Verification still dispatches per certificate.
    pub fn with_signer_scheme(
        epoch: u64,
        vset: ValidatorSet,
        base_timer: u64,
        signer: Box<dyn Signer>,
        operator_pk: Vec<u8>,
        agg_scheme: AggScheme,
    ) -> Self {
        Self::with_signer_restored_scheme(
            epoch,
            vset,
            base_timer,
            signer,
            None,
            operator_pk,
            agg_scheme,
        )
    }

    /// Build a core with an injected signer, optionally restoring the
    /// safety-critical watermarks from a crash-recovered snapshot.
    ///
    /// `restored = Some((last_voted_round, preferred_round))` initializes
    /// [`SafetyRules`] to those persisted values (so a node rebuilt after a
    /// crash refuses to double-vote or break a lock it established before
    /// crashing); `None` starts fresh (`SafetyRules::default()`), reproducing
    /// the pre-persistence behaviour exactly. The driver injects the restored
    /// pair only when the loaded snapshot's epoch matches this core's `epoch`;
    /// other epochs start fresh.
    ///
    /// Restoration reads/writes only `SafetyRules`' public fields — `azbft-safety`
    /// logic is untouched.
    ///
    /// Compatibility constructors form secp256k1 QCs. Callers selecting BLS use
    /// [`with_signer_scheme`](Self::with_signer_scheme) or
    /// [`with_signer_restored_scheme`](Self::with_signer_restored_scheme) with
    /// `AggScheme::Bls`.
    pub fn with_signer_restored(
        epoch: u64,
        vset: ValidatorSet,
        base_timer: u64,
        signer: Box<dyn Signer>,
        restored: Option<(Round, Round)>,
        operator_pk: Vec<u8>,
    ) -> Self {
        Self::with_signer_restored_scheme(
            epoch,
            vset,
            base_timer,
            signer,
            restored,
            operator_pk,
            AggScheme::Secp,
        )
    }

    /// Full constructor: restored watermarks plus an explicit QC forming scheme.
    #[allow(clippy::too_many_arguments)]
    pub fn with_signer_restored_scheme(
        epoch: u64,
        vset: ValidatorSet,
        base_timer: u64,
        signer: Box<dyn Signer>,
        restored: Option<(Round, Round)>,
        operator_pk: Vec<u8>,
        agg_scheme: AggScheme,
    ) -> Self {
        let me = signer.node_id();
        let safety = restored
            .map(|(last_voted_round, preferred_round)| SafetyRules {
                last_voted_round,
                preferred_round,
            })
            .unwrap_or_default();
        Self {
            me,
            epoch,
            vset,
            round: Round(1),
            high_qc: QuorumCert::genesis(),
            high_tc: None,
            safety,
            tree: BlockTree::new(),
            chain_anchor: ChainAnchorV2::default(),
            pacemaker: Pacemaker::new(base_timer),
            signer,
            votes: BTreeMap::new(),
            qc_formed: BTreeMap::new(),
            timeouts: BTreeMap::new(),
            tc_formed: BTreeMap::new(),
            pending_reconfig: None,
            epoch_ending_round: None,
            voted: BTreeMap::new(),
            operator_set: OperatorSet::single(operator_pk),
            agg_scheme,
            jailed: BTreeMap::new(),
            consumed_evidence: BTreeSet::new(),
            leader_mode: LeaderSchedule::default(),
        }
    }

    /// Sets the chain-constant operator authority.
    ///
    /// The host uses this when genesis configures multiple keys or a threshold
    /// above one. The setting does not modify safety, wire, QC, or TC state.
    pub fn with_operator_set(mut self, operator_set: OperatorSet) -> Self {
        self.operator_set = operator_set;
        self
    }

    /// Install the predecessor used by the first block of this core's epoch.
    pub fn with_chain_anchor(mut self, chain_anchor: ChainAnchorV2) -> Self {
        self.chain_anchor = chain_anchor;
        self
    }
    /// Restore the smallest certified frontier needed to resume safely after a
    /// process restart. The durable commit certificate proves both the committed
    /// tip and its certified child; the latter is the only safe high-QC parent
    /// after restored locking watermarks have moved beyond genesis.
    pub fn restore_committed_tip(&mut self, cert: &CommitCert) -> Result<(), &'static str> {
        if cert.block.epoch != self.epoch || cert.child.epoch != self.epoch {
            return Err("durable tip epoch does not match the active core");
        }
        if cert.block.header_version != BLOCK_HEADER_VERSION_V2 {
            return Err("durable tip uses an unsupported block header");
        }
        if self.chain_anchor != ChainAnchorV2::from_block(&cert.block) {
            return Err("durable tip does not match the recovered chain anchor");
        }
        if !crate::verify_commit_cert(cert, &self.vset) {
            return Err("durable tip commit certificate is invalid");
        }
        if validate_block_header_v2(&cert.child, ChainAnchorV2::from_block(&cert.block), None)
            .is_err()
        {
            return Err("durable tip child header is invalid");
        }
        let next_round = self
            .safety
            .last_voted_round
            .0
            .max(cert.commit_qc.round.0)
            .checked_add(1)
            .ok_or("durable tip recovery round overflow")?;

        self.tree.insert(cert.block.clone());
        let marked = self.tree.commit(cert.block.id());
        if marked.len() != 1 || marked[0].id() != cert.block.id() {
            return Err("durable tip recovery requires a fresh block tree");
        }
        self.tree.insert(cert.child.clone());
        self.high_qc = cert.commit_qc.clone();
        self.round = Round(next_round);
        Ok(())
    }

    /// Current epoch boundary/recovery anchor.
    pub fn chain_anchor(&self) -> ChainAnchorV2 {
        self.chain_anchor
    }

    /// The QC/TC forming scheme this core uses (test/inspection accessor).
    pub fn agg_scheme(&self) -> AggScheme {
        self.agg_scheme
    }

    /// Take a snapshot of the safety-critical state for durable persistence.
    /// Reads only the public watermark fields of [`SafetyRules`]; `azbft-safety`
    /// logic is untouched. Used by the `handle()` wrapper to detect a change
    /// (and prepend [`Command::Persist`](crate::command::Command::Persist)) and
    /// by the driver to serialize what to fsync.
    pub(crate) fn safety_snapshot(&self) -> SafetySnapshot {
        SafetySnapshot {
            epoch: self.epoch,
            last_voted_round: self.safety.last_voted_round,
            preferred_round: self.safety.preferred_round,
        }
    }

    // ---- test / inspection accessors ----

    /// Current round.
    pub fn round(&self) -> Round {
        self.round
    }

    /// Current epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Highest verified QC.
    pub fn high_qc(&self) -> &QuorumCert {
        &self.high_qc
    }

    /// This node's id.
    pub fn me(&self) -> NodeId {
        self.me
    }

    /// Insert a block straight into the tree (test hook so a collector node
    /// can know the block its incoming votes certify without first replaying
    /// the proposal).
    pub fn tree_insert_for_test(&mut self, b: Block) {
        self.tree.insert(b);
    }

    /// Returns the block certified by the current high QC when it is present.
    pub fn high_qc_block(&self) -> Option<Block> {
        self.tree.get(&self.high_qc.block_id).cloned()
    }

    /// Whether the current epoch's in-memory block tree contains `id`.
    ///
    /// This is deliberately a read-only driver boundary. A live proposal whose
    /// non-genesis parent is absent must not enter the core: `process_qc` can
    /// otherwise advance on the certified fragment and later derive a commit
    /// from a second, disconnected fragment. Sync application remains the one
    /// path allowed to populate a missing contiguous history in bulk.
    pub fn contains_block(&self, id: &Hash) -> bool {
        self.tree.get(id).is_some()
    }

    /// Returns the validator set active in this epoch.
    pub fn vset(&self) -> &ValidatorSet {
        &self.vset
    }

    /// the leader for `round` under this core's configured mode. The consensus
    /// leader checks (`on_proposal` author validation, "am I the leader") MUST route
    /// through here rather than the raw round-robin `vset.leader`, or a StakeWeighted
    /// chain would compute different leaders on different nodes and fork.
    pub fn leader(&self, round: Round) -> NodeId {
        self.vset.leader_with_mode(round, self.leader_mode)
    }

    /// set the leader-selection mode (a chain constant). Called at construction and
    /// re-applied on every epoch roll from the same config, so the mode never drifts.
    pub fn set_leader_mode(&mut self, mode: LeaderSchedule) {
        self.leader_mode = mode;
    }

    /// the current leader-selection mode (driver roll-carry / forwarding).
    pub fn leader_mode(&self) -> LeaderSchedule {
        self.leader_mode
    }

    /// Returns the current temporary-removal map.
    pub fn jailed(&self) -> &BTreeMap<NodeId, u64> {
        &self.jailed
    }

    /// Returns whether `id` is temporarily removed.
    pub fn is_jailed(&self, id: &NodeId) -> bool {
        self.jailed.contains_key(id)
    }

    /// Returns the first epoch in which `id` may return.
    pub fn jailed_until(&self, id: &NodeId) -> Option<u64> {
        self.jailed.get(id).copied()
    }

    /// Restores the temporary-removal map during an epoch transition.
    ///
    /// The complete map is carried forward; entries are removed only when an
    /// authorized return reconfiguration commits.
    pub fn restore_jailed(&mut self, jailed: std::collections::BTreeMap<NodeId, u64>) {
        self.jailed = jailed;
    }

    /// Consumed-evidence replay protection: read-only view of the consumed-evidence ledger (tests / driver
    /// durability). See the `consumed_evidence` field.
    pub fn consumed_evidence(&self) -> &BTreeSet<(NodeId, u64, u64)> {
        &self.consumed_evidence
    }

    /// Consumed-evidence replay protection: merge a consumed-evidence set into this core's ledger
    /// (epoch-roll carry / restart load / checkpoint-adopt reconstruct / catch-up).
    /// **Union** (insert-only): unlike `restore_jailed` (which replaces), this never
    /// drops an already-consumed act — re-applying the same or overlapping set is
    /// idempotent, matching the monotonic ledger.
    pub fn restore_consumed(&mut self, consumed: BTreeSet<(NodeId, u64, u64)>) {
        self.consumed_evidence.extend(consumed);
    }
}
