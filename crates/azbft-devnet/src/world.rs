use crate::adversary::DevnetFault;
use crate::clock::EventQueue;
use crate::driver::{message_to_event, DeterministicSigner, NodeDriver};
use crate::invariant::agreement;
use crate::net::Network;
use crate::transcript::{DevnetTranscript, TRANSCRIPT_VERSION};
use crate::{DevnetConfig, DevnetError};
use azbft_core::{AggScheme, Command, ConsensusCore, Event};
use azbft_crypto::bls::BlsSecretKey;
use azbft_crypto::keypair::Keypair;
use azbft_types::{ConsensusMessage, Member, NodeId, Round, ValidatorSet};
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use std::collections::{BTreeMap, BTreeSet};

const BASE_TIMER: u64 = 100;

pub(crate) struct World {
    config: DevnetConfig,
    queue: EventQueue<Event>,
    nodes: Vec<NodeDriver>,
    network: Network,
    rng: ChaCha8Rng,
    validator_set: ValidatorSet,
    index_by_id: BTreeMap<NodeId, usize>,
    view_changes: u64,
    processed_events: u64,
    step_cap: u64,
}

impl World {
    pub(crate) fn new(config: DevnetConfig, fault: DevnetFault) -> Result<Self, DevnetError> {
        if config.validators < 4 {
            return Err(DevnetError::InvalidConfig(
                "a public devnet requires at least four validators",
            ));
        }
        if config.blocks == 0 {
            return Err(DevnetError::InvalidConfig(
                "the requested block count must be positive",
            ));
        }

        let seeds: Vec<u64> = (0..config.validators)
            .map(|index| derive_validator_seed(config.seed, index))
            .collect();
        let keys: Vec<Keypair> = seeds.iter().copied().map(Keypair::from_seed).collect();
        let members = keys
            .iter()
            .zip(seeds.iter().copied())
            .map(|(key, seed)| {
                let bls = BlsSecretKey::from_seed(seed);
                Member::new(
                    key.node_id(),
                    key.pubkey_bytes(),
                    bls.public().to_bytes().to_vec(),
                    bls.prove_possession().to_bytes().to_vec(),
                    1,
                )
            })
            .collect();
        let validator_set = ValidatorSet::new_members(members);
        let index_by_id = keys
            .iter()
            .enumerate()
            .map(|(index, key)| (key.node_id(), index))
            .collect::<BTreeMap<_, _>>();

        let unavailable = unavailable_indices(&fault, &validator_set, &index_by_id)?;
        let available_stake = validator_set
            .members()
            .iter()
            .enumerate()
            .filter(|(index, _)| !unavailable.contains(index))
            .map(|(_, member)| member.stake)
            .sum::<u64>();
        if available_stake < validator_set.quorum() {
            return Err(DevnetError::NoFinality {
                requested: config.blocks,
                finalized: 0,
                processed_events: 0,
            });
        }

        let operator_key = Keypair::from_seed(config.seed.rotate_left(17) ^ 0xA2BF_7001);
        let operator_public_key = operator_key.pubkey_bytes();
        let mut nodes = seeds
            .iter()
            .copied()
            .enumerate()
            .map(|(index, seed)| {
                let core = ConsensusCore::with_signer_scheme(
                    0,
                    validator_set.clone(),
                    BASE_TIMER,
                    Box::new(DeterministicSigner::from_seed(seed)),
                    operator_public_key.clone(),
                    AggScheme::Bls,
                );
                NodeDriver::new(core, unavailable.contains(&index))
            })
            .collect::<Vec<_>>();

        let step_cap = config.blocks.saturating_mul(400).max(2_000);
        let mut world = Self {
            queue: EventQueue::new(),
            nodes: Vec::new(),
            network: Network::local(),
            rng: ChaCha8Rng::seed_from_u64(config.seed),
            validator_set,
            index_by_id,
            view_changes: 0,
            processed_events: 0,
            step_cap,
            config,
        };

        let startup = nodes
            .iter_mut()
            .enumerate()
            .filter(|(_, node)| !node.unavailable)
            .map(|(index, node)| (index, node.core.start()))
            .collect::<Vec<_>>();
        world.nodes = nodes;
        for (index, commands) in startup {
            world.apply_commands(index, commands, 0);
        }

        Ok(world)
    }

    pub(crate) fn run(mut self) -> Result<DevnetTranscript, DevnetError> {
        while self.processed_events < self.step_cap {
            let Some((index, event)) = self.queue.pop() else {
                break;
            };
            if self.nodes[index].unavailable {
                self.processed_events += 1;
                continue;
            }
            if matches!(event, Event::LocalTimeout(_)) {
                self.view_changes += 1;
            }
            let now = self.queue.now();
            let commands = self.nodes[index].core.handle(event, now);
            self.apply_commands(index, commands, now);
            self.processed_events += 1;

            if self
                .nodes
                .iter()
                .filter(|node| !node.unavailable)
                .all(|node| node.finalized.len() as u64 >= self.config.blocks)
            {
                return self.into_transcript();
            }
        }

        let finalized = self
            .nodes
            .iter()
            .filter(|node| !node.unavailable)
            .map(|node| node.finalized.len() as u64)
            .max()
            .unwrap_or(0);
        Err(DevnetError::NoFinality {
            requested: self.config.blocks,
            finalized,
            processed_events: self.processed_events,
        })
    }

    fn into_transcript(self) -> Result<DevnetTranscript, DevnetError> {
        if !agreement(&self.nodes) {
            return Err(DevnetError::AgreementViolation);
        }
        let records = self
            .nodes
            .iter()
            .filter(|node| !node.unavailable)
            .max_by_key(|node| node.finalized.len())
            .expect("validated devnet has an available quorum")
            .finalized
            .iter()
            .take(self.config.blocks as usize)
            .cloned()
            .collect();

        Ok(DevnetTranscript {
            version: TRANSCRIPT_VERSION,
            seed: self.config.seed,
            validator_set: self.validator_set,
            finalized: records,
            view_changes: self.view_changes,
            processed_events: self.processed_events,
        })
    }

    fn apply_commands(&mut self, source: usize, commands: Vec<Command>, now: u64) {
        for command in commands {
            match command {
                Command::Broadcast(message) => self.broadcast(source, message, now),
                Command::Send(target, message) => self.send(source, target, message, now),
                Command::SetTimer(round, duration) => {
                    self.queue.schedule(
                        now.saturating_add(duration),
                        source,
                        Event::LocalTimeout(round),
                    );
                }
                Command::CancelTimer => {}
                Command::CreatePayload { round, parent } => {
                    let Some(context) = self.nodes[source]
                        .core
                        .proposal_build_context(round, &parent, now)
                    else {
                        continue;
                    };
                    let payload = self.nodes[source].build_payload(round);
                    self.queue
                        .schedule(now, source, Event::PayloadReady { context, payload });
                }
                Command::Commit(committed) => self.nodes[source].on_commit(*committed),
                Command::Persist(_) | Command::Equivocation(_) => {}
            }
        }
    }

    fn broadcast(&mut self, source: usize, message: ConsensusMessage, now: u64) {
        for target in 0..self.nodes.len() {
            if self.nodes[target].unavailable {
                continue;
            }
            let delay = self.network.delay(source, target, &mut self.rng);
            self.queue.schedule(
                now.saturating_add(delay),
                target,
                message_to_event(message.clone()),
            );
        }
    }

    fn send(&mut self, source: usize, target: NodeId, message: ConsensusMessage, now: u64) {
        let Some(&target_index) = self.index_by_id.get(&target) else {
            return;
        };
        if self.nodes[target_index].unavailable {
            return;
        }
        let delay = self.network.delay(source, target_index, &mut self.rng);
        self.queue.schedule(
            now.saturating_add(delay),
            target_index,
            message_to_event(message),
        );
    }
}

fn derive_validator_seed(seed: u64, index: usize) -> u64 {
    seed.wrapping_mul(1_000)
        .wrapping_add(index as u64)
        .wrapping_add(1)
}

fn unavailable_indices(
    fault: &DevnetFault,
    validator_set: &ValidatorSet,
    index_by_id: &BTreeMap<NodeId, usize>,
) -> Result<BTreeSet<usize>, DevnetError> {
    let indices = match fault {
        DevnetFault::None => Vec::new(),
        DevnetFault::UnavailableInitialLeader => {
            let leader = validator_set.leader(Round(1));
            vec![index_by_id[&leader]]
        }
        DevnetFault::UnavailableValidators(indices) => indices.clone(),
    };

    let mut result = BTreeSet::new();
    for index in indices {
        if index >= validator_set.len() {
            return Err(DevnetError::InvalidValidatorIndex(index));
        }
        result.insert(index);
    }
    Ok(result)
}
