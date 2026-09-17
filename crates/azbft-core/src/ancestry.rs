//! Bounded, certificate-authenticated import of a missing live ancestor chain.
//! Import populates the tree only: it never votes, commits, advances a round,
//! or changes a safety watermark. The host resumes normal event processing.

use crate::ConsensusCore;
use azbft_crypto::{aggregator::verify_agg, domain::Domain};
use azbft_types::{validate_block_header_v2, vote_digest, Block, ChainAnchorV2, Hash, QuorumCert};

pub const MAX_LIVE_ANCESTORS: usize = 64;

impl ConsensusCore {
    /// Return available ancestors in parent-first order, including `target`.
    /// A short result is not a proof that older ancestors do not exist.
    pub fn live_ancestors(&self, target: Hash, limit: usize) -> Vec<Block> {
        let mut blocks = Vec::new();
        let mut id = target;
        for _ in 0..limit.min(MAX_LIVE_ANCESTORS) {
            let Some(block) = self.tree.get(&id) else {
                break;
            };
            blocks.push(block.clone());
            if block.parent_qc.round.0 == 0 {
                break;
            }
            id = block.parent_qc.block_id;
        }
        blocks.reverse();
        blocks
    }

    /// Authenticate the whole connected segment before mutating the tree.
    /// `target_qc` certifies the final block; each child certifies its parent.
    /// Epoch transitions use the existing committed-history/ECC path instead.
    pub fn import_live_ancestors(
        &mut self,
        blocks: &[Block],
        target_qc: &QuorumCert,
    ) -> Result<(), &'static str> {
        if blocks.is_empty() || blocks.len() > MAX_LIVE_ANCESTORS {
            return Err("invalid ancestry length");
        }
        if let Some(committed) = self.tree.last_committed_id() {
            if !self
                .tree
                .is_ancestor(&committed, &blocks[0].parent_qc.block_id)
            {
                return Err("ancestry does not extend committed frontier");
            }
        }
        let mut parent = if blocks[0].parent_qc.round.0 == 0 {
            if blocks[0].parent_qc != QuorumCert::genesis() {
                return Err("invalid genesis certificate");
            }
            self.chain_anchor
        } else {
            let anchor = self
                .tree
                .get(&blocks[0].parent_qc.block_id)
                .ok_or("unknown ancestry anchor")?;
            if anchor.epoch != self.epoch
                || anchor.round != blocks[0].parent_qc.round
                || anchor.reconfig.is_some()
            {
                return Err("invalid ancestry anchor");
            }
            verify_agg(
                &blocks[0].parent_qc.agg,
                &vote_digest(&anchor.id(), anchor.round),
                Domain::Vote,
                &self.vset,
            )
            .map_err(|_| "invalid anchor certificate")?;
            ChainAnchorV2::from_block(anchor)
        };
        for (index, block) in blocks.iter().enumerate() {
            if block.epoch != self.epoch || block.reconfig.is_some() {
                return Err("epoch transition requires committed recovery");
            }
            if block.author != self.leader(block.round) {
                return Err("invalid ancestry author");
            }
            if block.round <= block.parent_qc.round {
                return Err("non-increasing ancestry round");
            }
            validate_block_header_v2(block, parent, None).map_err(|_| "invalid ancestry header")?;
            let certificate = blocks
                .get(index + 1)
                .map_or(target_qc, |child| &child.parent_qc);
            if certificate.round.0 == 0
                || certificate.block_id != block.id()
                || certificate.round != block.round
            {
                return Err("ancestry certificate mismatch");
            }
            verify_agg(
                &certificate.agg,
                &vote_digest(&certificate.block_id, certificate.round),
                Domain::Vote,
                &self.vset,
            )
            .map_err(|_| "invalid ancestry certificate")?;
            parent = ChainAnchorV2::from_block(block);
        }
        for block in blocks {
            self.tree.insert(block.clone());
        }
        Ok(())
    }
}
