use crate::domain::{digest, Domain};
use azbft_types::ids::{node_id_from_pubkey, NodeId};
use k256::ecdsa::{
    signature::hazmat::{PrehashSigner, PrehashVerifier},
    Signature, SigningKey, VerifyingKey,
};

#[derive(Clone)]
pub struct Keypair {
    sk: SigningKey,
}

impl Keypair {
    /// Deterministically constructs a low-entropy key for tests and devnets.
    ///
    /// This function is intentionally feature-gated and must never be used for
    /// production keys.
    #[cfg(any(test, feature = "insecure-test-keys"))]
    pub fn from_seed(seed: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        bytes[31] = 1; // ensure nonzero scalar
        Self {
            sk: SigningKey::from_bytes(&bytes.into()).expect("valid scalar"),
        }
    }

    /// Construct from a raw 32-byte secp256k1 scalar. Returns `None` if the
    /// bytes do not represent a valid non-zero scalar in the field.
    pub fn from_sk_bytes(bytes: &[u8; 32]) -> Option<Self> {
        SigningKey::from_bytes(&(*bytes).into())
            .ok()
            .map(|sk| Self { sk })
    }

    /// Export the 32-byte secp256k1 scalar (the secret key).
    /// The caller is responsible for zeroing the returned buffer when done.
    pub fn sk_bytes(&self) -> [u8; 32] {
        let fb = self.sk.to_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&fb);
        out
    }

    pub fn pubkey_bytes(&self) -> Vec<u8> {
        VerifyingKey::from(&self.sk).to_sec1_bytes().to_vec()
    }

    pub fn node_id(&self) -> NodeId {
        node_id_from_pubkey(&self.pubkey_bytes())
    }

    /// Return the raw 32-byte scalar of the secp256k1 signing key.
    /// Returns the canonical 32-byte scalar representation for deterministic key backup.
    /// static key pair (static-key backup). Not exposed on the wire.
    pub fn secp_scalar_bytes(&self) -> [u8; 32] {
        let fb = self.sk.to_bytes();
        // `FieldBytes` is a `GenericArray<u8, U32>`; indexing gives us `&[u8]`.
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&fb[..]);
        arr
    }

    pub fn sign(&self, d: Domain, msg: &[u8]) -> Vec<u8> {
        let sig: Signature = self.sk.sign_prehash(&digest(d, msg)).expect("sign");
        sig.to_vec()
    }
}

pub fn verify(d: Domain, msg: &[u8], sig: &[u8], pubkey: &[u8]) -> bool {
    let started = matches!(d, Domain::Vote).then(crate::perf::start).flatten();
    let (vk, sig) = match (
        VerifyingKey::from_sec1_bytes(pubkey),
        Signature::from_slice(sig),
    ) {
        (Ok(v), Ok(s)) => (v, s),
        _ => {
            crate::perf::record_single_vote_verify(started);
            return false;
        }
    };
    let valid = vk.verify_prehash(&digest(d, msg), &sig).is_ok();
    crate::perf::record_single_vote_verify(started);
    valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::Domain;

    #[test]
    fn sign_verify_roundtrip() {
        let kp = Keypair::from_seed(7);
        let msg = b"hello";
        let sig = kp.sign(Domain::Vote, msg);
        assert!(verify(Domain::Vote, msg, &sig, &kp.pubkey_bytes()));
    }

    #[test]
    fn domain_separation_rejects_cross_use() {
        let kp = Keypair::from_seed(7);
        let sig = kp.sign(Domain::Vote, b"x");
        assert!(!verify(Domain::Timeout, b"x", &sig, &kp.pubkey_bytes()));
    }

    #[test]
    fn node_id_is_stable() {
        assert_eq!(
            Keypair::from_seed(7).node_id(),
            Keypair::from_seed(7).node_id()
        );
    }

    #[cfg(feature = "host-extensions")]
    #[test]
    fn handshake_domain_separated() {
        let kp = Keypair::from_seed(7);
        let sig = kp.sign(Domain::Handshake, b"challenge");
        assert!(verify(
            Domain::Handshake,
            b"challenge",
            &sig,
            &kp.pubkey_bytes()
        ));
        // a Vote sig must not verify as Handshake
        let v = kp.sign(Domain::Vote, b"challenge");
        assert!(!verify(
            Domain::Handshake,
            b"challenge",
            &v,
            &kp.pubkey_bytes()
        ));
    }
}
