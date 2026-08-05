use borsh::{BorshDeserialize, BorshSerialize};

#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, BorshSerialize, BorshDeserialize,
)]
pub struct Round(pub u64);

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Default,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct NodeId(pub [u8; 20]);

#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Default,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct Hash(pub [u8; 32]);

/// Deterministic id of any borsh-serializable value.
pub fn blake3_id<T: BorshSerialize>(v: &T) -> Hash {
    let bytes = borsh::to_vec(v).expect("borsh serialize");
    Hash(*blake3::hash(&bytes).as_bytes())
}

/// NodeId from a public key's bytes = blake3(pubkey)[..20].
pub fn node_id_from_pubkey(pubkey: &[u8]) -> NodeId {
    let h = blake3::hash(pubkey);
    let mut id = [0u8; 20];
    id.copy_from_slice(&h.as_bytes()[..20]);
    NodeId(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hash_is_deterministic_over_borsh() {
        let a = blake3_id(&123u64);
        let b = blake3_id(&123u64);
        assert_eq!(a, b);
        assert_ne!(a, blake3_id(&124u64));
    }
    #[test]
    fn round_orders() {
        assert!(Round(1) < Round(2));
    }
}
