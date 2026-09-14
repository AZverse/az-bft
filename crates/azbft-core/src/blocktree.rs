use azbft_types::{ids::Hash, Block};
use std::collections::BTreeMap;

pub struct BlockTree {
    blocks: BTreeMap<Hash, Block>,
    committed: BTreeMap<Hash, ()>,
    last_committed_round: u64,
    last_committed_id: Option<Hash>,
}

impl Default for BlockTree {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockTree {
    pub fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
            committed: BTreeMap::new(),
            last_committed_round: 0,
            last_committed_id: None,
        }
    }

    pub fn insert(&mut self, b: Block) {
        self.blocks.insert(b.id(), b);
    }

    pub fn get(&self, id: &Hash) -> Option<&Block> {
        self.blocks.get(id)
    }

    pub fn is_ancestor(&self, anc: &Hash, desc: &Hash) -> bool {
        let mut cur = *desc;
        loop {
            if &cur == anc {
                return true;
            }
            match self.blocks.get(&cur) {
                Some(b) => cur = b.parent_qc.block_id,
                None => return false,
            }
        }
    }

    /// Commit `target` and all uncommitted ancestors, ancestors-first, each once.
    pub fn commit(&mut self, target: Hash) -> Vec<Block> {
        let mut chain = Vec::new();
        let mut cur = target;
        while let Some(b) = self.blocks.get(&cur) {
            if self.committed.contains_key(&cur) {
                break;
            }
            chain.push(b.clone());
            cur = b.parent_qc.block_id;
        }
        chain.reverse();
        for b in &chain {
            self.committed.insert(b.id(), ());
            self.last_committed_round = b.round.0;
            self.last_committed_id = Some(b.id());
        }
        chain
    }

    pub fn prune_below(&mut self, round: u64) {
        let committed = &self.committed;
        self.blocks
            .retain(|id, b| b.round.0 >= round || committed.contains_key(id));
    }

    pub fn last_committed_round(&self) -> u64 {
        self.last_committed_round
    }

    pub fn last_committed_id(&self) -> Option<Hash> {
        self.last_committed_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azbft_types::*;

    fn blk(r: u64, pr: u64, payload: u8) -> Block {
        Block {
            header_version: BLOCK_HEADER_VERSION_V2,
            height: 1,
            timestamp_ms: 1,
            epoch: 0,
            round: Round(r),
            parent_qc: QuorumCert {
                block_id: Hash([pr as u8; 32]),
                round: Round(pr),
                agg: AggSig::default(),
            },
            payload_hash: Hash([payload; 32]),
            author: NodeId::default(),
            reconfig: None,
        }
    }

    #[test]
    fn insert_get_and_commit_walk_in_order() {
        let mut t = BlockTree::new();
        let b1 = blk(1, 0, 1);
        let id1 = b1.id();
        let mut b2 = blk(2, 1, 2);
        b2.parent_qc.block_id = id1; // link b2 -> b1
        t.insert(b1.clone());
        t.insert(b2.clone());
        let committed = t.commit(b2.id());
        assert_eq!(
            committed.iter().map(|b| b.id()).collect::<Vec<_>>(),
            vec![id1, b2.id()]
        );
        assert!(t.commit(b2.id()).is_empty()); // idempotent
    }
}
