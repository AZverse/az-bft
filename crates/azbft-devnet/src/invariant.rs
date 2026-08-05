use crate::driver::NodeDriver;
use azbft_types::Hash;
use std::collections::BTreeMap;

pub(crate) fn agreement(nodes: &[NodeDriver]) -> bool {
    let mut committed: BTreeMap<(u64, u64), Hash> = BTreeMap::new();

    for node in nodes.iter().filter(|node| !node.unavailable) {
        for record in &node.finalized {
            let key = (record.block.epoch, record.block.round.0);
            let block_id = record.block.id();
            match committed.get(&key) {
                Some(previous) if *previous != block_id => return false,
                Some(_) => {}
                None => {
                    committed.insert(key, block_id);
                }
            }
        }
    }

    true
}
