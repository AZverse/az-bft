//! BLS12-381 aggregate signatures for AZBFT quorum certificates.
//!
//! BLS aggregate signatures are wired into QC formation through
//! `BlsMultiSig`. The secp256k1 path remains available, and certificate
//! verification dispatches on the encoded signature variant.
//!
//! The module uses the min-pk scheme: public keys are 48-byte compressed G1
//! points and signatures are 96-byte compressed G2 points. A QC carries one
//! aggregate signature plus a sorted signer set.
//!
//! Message domains are separated at the hash layer by
//! [`crate::domain::digest`]. The fixed BLS ciphersuite identifiers below are
//! separate from those per-message domain tags.
//!
//! Fast aggregate verification requires proof of possession for every admitted
//! public key. [`BlsSecretKey::prove_possession`] and [`pop_verify`] implement
//! that check; validator-set adoption rejects BLS keys without a valid proof.
//!
//! The cryptographic construction follows the BLS signature specification,
//! EIP-2333 key generation, and the `blst` API.

use crate::domain::{digest, Domain};
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;

/// Compressed length of a min-pk public key (G1 point), in bytes.
pub const BLS_PUBLIC_KEY_LEN: usize = 48;
/// Compressed length of a min-pk signature (G2 point), in bytes.
pub const BLS_SIGNATURE_LEN: usize = 96;

/// Ciphersuite domain-separation tag (DST). This is the standard min-pk
/// proof-of-possession ciphersuite string from the BLS signature draft; it is
/// fixed for the whole scheme and held constant across sign and verify. It is
/// orthogonal to the per-message [`Domain`] tag, which is folded into the
/// signed digest by [`digest`].
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// DST used only for proof-of-possession signatures (signing one's own public
/// key). Kept distinct from [`DST`] so a PoP can never be replayed as a regular
/// message signature, per the BLS PoP scheme.
const DST_POP: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// A BLS secret key constructed from validated scalar bytes or input keying material.
#[derive(Clone)]
pub struct BlsSecretKey(SecretKey);

/// A BLS public key (G1, 48-byte compressed).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlsPublicKey(PublicKey);

/// A BLS signature (G2, 96-byte compressed).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlsSignature(Signature);

impl BlsSecretKey {
    /// Deterministically derives a low-entropy key for tests and devnets.
    ///
    /// The seed is expanded into fixed input keying material before `blst`
    /// key generation. This function is intentionally feature-gated and must
    /// never be used for production keys.
    #[cfg(any(test, feature = "insecure-test-keys"))]
    pub fn from_seed(seed: u64) -> Self {
        let mut ikm = [0u8; 32];
        ikm[..8].copy_from_slice(&seed.to_le_bytes());
        ikm[31] = 1; // ensure nonzero, ≥ 32-byte IKM
        let sk = SecretKey::key_gen(&ikm, &[]).expect("key_gen with 32-byte ikm");
        Self(sk)
    }

    /// Construct from raw 32-byte BLS secret key scalar bytes (as produced by
    /// [`BlsSecretKey::sk_bytes`]). Returns `None` if the bytes are not a valid
    /// blst secret key scalar (i.e. not a non-zero element of the BLS12-381 Fr
    /// field in big-endian encoding).
    pub fn from_sk_bytes(bytes: &[u8; 32]) -> Option<Self> {
        SecretKey::from_bytes(bytes.as_slice()).ok().map(Self)
    }

    /// Export the 32-byte BLS secret key scalar (big-endian Fr element). The
    /// caller is responsible for zeroing the returned buffer when done.
    pub fn sk_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Derive a key from arbitrary input keying material (IKM) using
    /// `blst`'s `key_gen` (HKDF-based, per EIP-2333 / BLS draft). The IKM
    /// must be at least 32 bytes; any length ≥ 32 is accepted.
    ///
    /// This accepts a full-entropy buffer and is suitable when key material is
    /// supplied by a cryptographically secure random source.
    pub fn from_ikm(ikm: &[u8]) -> Option<Self> {
        if ikm.len() < 32 {
            return None;
        }
        SecretKey::key_gen(ikm, &[]).ok().map(Self)
    }

    /// The corresponding public key.
    pub fn public(&self) -> BlsPublicKey {
        BlsPublicKey(self.0.sk_to_pk())
    }

    /// Sign the domain-separated digest of `msg` under domain `d`.
    ///
    /// The signed message is [`digest(d, msg)`](digest) — the same 32-byte
    /// domain-separated digest the secp path signs — so domain separation is
    /// reused unchanged.
    pub fn sign(&self, d: Domain, msg: &[u8]) -> BlsSignature {
        let sig = self.0.sign(&digest(d, msg), DST, &[]);
        BlsSignature(sig)
    }

    /// Produce a proof-of-possession: a signature over this key's own public
    /// key under the dedicated PoP DST. Used to defend the fast-aggregate path
    /// against rogue-key attacks (verified by [`pop_verify`]).
    pub fn prove_possession(&self) -> BlsSignature {
        let pk_bytes = self.public().to_bytes();
        BlsSignature(self.0.sign(&pk_bytes, DST_POP, &[]))
    }
}

impl BlsPublicKey {
    /// 48-byte compressed encoding.
    pub fn to_bytes(&self) -> [u8; BLS_PUBLIC_KEY_LEN] {
        self.0.compress()
    }

    /// Parse a 48-byte compressed encoding. Returns `None` on a wrong length,
    /// bad encoding, off-curve point, or point outside the prime-order subgroup
    /// — never panics. This is what keeps the BLS and secp schemes from being
    /// confused: a secp public key is not a valid 48-byte G1 point.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != BLS_PUBLIC_KEY_LEN {
            return None;
        }
        // `from_bytes` (a.k.a. uncompress) performs the encoding/curve checks;
        // `validate` additionally rejects the identity and enforces subgroup
        // membership.
        let pk = PublicKey::from_bytes(bytes).ok()?;
        pk.validate().ok()?;
        Some(BlsPublicKey(pk))
    }
}

impl BlsSignature {
    /// 96-byte compressed encoding.
    pub fn to_bytes(&self) -> [u8; BLS_SIGNATURE_LEN] {
        self.0.compress()
    }

    /// Parse a 96-byte compressed encoding. Returns `None` on a wrong length,
    /// bad encoding, or off-curve point — never panics.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != BLS_SIGNATURE_LEN {
            return None;
        }
        Signature::from_bytes(bytes).ok().map(BlsSignature)
    }
}

/// Verify a single BLS signature over `digest(d, msg)`.
///
/// Returns `true` iff `sig` is a valid signature of the domain-separated digest
/// under `pk`. Performs signature-group and public-key validation.
pub fn bls_verify(d: Domain, msg: &[u8], sig: &BlsSignature, pk: &BlsPublicKey) -> bool {
    let started = matches!(d, Domain::Vote).then(crate::perf::start).flatten();
    let valid = sig.0.verify(
        true, // sig_groupcheck
        &digest(d, msg),
        DST,
        &[], // aug
        &pk.0,
        true, // pk_validate
    ) == BLST_ERROR::BLST_SUCCESS;
    crate::perf::record_single_vote_verify(started);
    valid
}

/// Aggregate public keys: `Σ pk`. Returns `None` if the input is empty or any
/// key fails subgroup validation.
pub fn aggregate_pubkeys(pks: &[BlsPublicKey]) -> Option<BlsPublicKey> {
    if pks.is_empty() {
        return None;
    }
    let refs: Vec<&PublicKey> = pks.iter().map(|p| &p.0).collect();
    let agg = AggregatePublicKey::aggregate(&refs, true).ok()?;
    Some(BlsPublicKey(agg.to_public_key()))
}

/// Aggregate signatures: `Σ sig`. Returns `None` if the input is empty or any
/// signature fails the group check.
pub fn aggregate_signatures(sigs: &[BlsSignature]) -> Option<BlsSignature> {
    if sigs.is_empty() {
        return None;
    }
    let refs: Vec<&Signature> = sigs.iter().map(|s| &s.0).collect();
    let agg = AggregateSignature::aggregate(&refs, true).ok()?;
    Some(BlsSignature(agg.to_signature()))
}

/// Fast-aggregate-verify against an already-aggregated public key (same-msg
/// path).
///
/// Verifies that `agg_sig` is the aggregate of signatures over the single
/// digest `digest(d, msg)` by the set of signers whose aggregate public key is
/// `agg_pk`: one message, N signers, one aggregate signature, and one
/// aggregate public key are verified with a single pairing check.
///
/// Soundness note: this is sound only when every public key folded into
/// `agg_pk` has a valid proof-of-possession (see [`pop_verify`]); without PoP
/// enforcement at registration, the fast-aggregate path is open to rogue-key
/// forgery.
pub fn aggregate_verify(
    d: Domain,
    msg: &[u8],
    agg_sig: &BlsSignature,
    agg_pk: &BlsPublicKey,
) -> bool {
    agg_sig.0.fast_aggregate_verify_pre_aggregated(
        true, // sig_groupcheck
        &digest(d, msg),
        DST,
        &agg_pk.0,
    ) == BLST_ERROR::BLST_SUCCESS
}

/// Fast-aggregate-verify directly against the list of signer public keys
/// (same-msg path). Equivalent to aggregating `pks` and calling
/// [`aggregate_verify`], but lets `blst` do the public-key aggregation
/// internally. Returns `false` on an empty key list.
///
/// Same PoP soundness caveat as [`aggregate_verify`].
pub fn fast_aggregate_verify(
    d: Domain,
    msg: &[u8],
    agg_sig: &BlsSignature,
    pks: &[BlsPublicKey],
) -> bool {
    if pks.is_empty() {
        return false;
    }
    let refs: Vec<&PublicKey> = pks.iter().map(|p| &p.0).collect();
    agg_sig
        .0
        .fast_aggregate_verify(true, &digest(d, msg), DST, &refs)
        == BLST_ERROR::BLST_SUCCESS
}

/// Verify a proof-of-possession produced by [`BlsSecretKey::prove_possession`].
///
/// Returns `true` iff `pop` is a valid signature of `pk`'s own compressed bytes
/// under the PoP DST. A public key should only be admitted into a fast-aggregate
/// set once this returns `true`, which is what closes the rogue-key hole.
pub fn pop_verify(pk: &BlsPublicKey, pop: &BlsSignature) -> bool {
    let pk_bytes = pk.to_bytes();
    pop.0.verify(true, &pk_bytes, DST_POP, &[], &pk.0, true) == BLST_ERROR::BLST_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    // Sign and verify round trip.
    #[test]
    fn sign_verify_roundtrip() {
        let sk = BlsSecretKey::from_seed(7);
        let msg = b"hello";
        let sig = sk.sign(Domain::Vote, msg);
        assert!(bls_verify(Domain::Vote, msg, &sig, &sk.public()));
    }

    // Domain separation.
    #[test]
    fn domain_separation_rejects_cross_use() {
        let sk = BlsSecretKey::from_seed(7);
        let sig = sk.sign(Domain::Vote, b"x");
        // Same key, same payload bytes, different Domain -> different digest -> reject.
        assert!(!bls_verify(Domain::Timeout, b"x", &sig, &sk.public()));
        assert!(!bls_verify(Domain::Proposal, b"x", &sig, &sk.public()));
    }

    #[test]
    fn verify_rejects_wrong_message_and_wrong_key() {
        let sk = BlsSecretKey::from_seed(11);
        let other = BlsSecretKey::from_seed(12);
        let sig = sk.sign(Domain::Vote, b"payload");
        assert!(!bls_verify(Domain::Vote, b"payload2", &sig, &sk.public()));
        assert!(!bls_verify(Domain::Vote, b"payload", &sig, &other.public()));
    }

    // Aggregate verification over a common message.
    #[test]
    fn aggregate_verify_of_n_sigs() {
        let n = 4u64;
        let sks: Vec<_> = (0..n).map(|i| BlsSecretKey::from_seed(200 + i)).collect();
        let msg = b"block-digest";
        let sigs: Vec<_> = sks.iter().map(|s| s.sign(Domain::Vote, msg)).collect();
        let pks: Vec<_> = sks.iter().map(|s| s.public()).collect();

        let agg_sig = aggregate_signatures(&sigs).expect("agg sig");
        let agg_pk = aggregate_pubkeys(&pks).expect("agg pk");

        // Pre-aggregated path.
        assert!(aggregate_verify(Domain::Vote, msg, &agg_sig, &agg_pk));
        // blst-internal aggregation path (should agree).
        assert!(fast_aggregate_verify(Domain::Vote, msg, &agg_sig, &pks));
    }

    #[test]
    fn aggregate_verify_single_signer() {
        // N=1 is a valid aggregate degenerate case.
        let sk = BlsSecretKey::from_seed(5);
        let msg = b"solo";
        let sig = sk.sign(Domain::Vote, msg);
        let agg_sig = aggregate_signatures(&[sig]).expect("agg sig");
        let agg_pk = aggregate_pubkeys(&[sk.public()]).expect("agg pk");
        assert!(aggregate_verify(Domain::Vote, msg, &agg_sig, &agg_pk));
    }

    // Tampered aggregate signatures are rejected.
    #[test]
    fn aggregate_verify_rejects_tampered_sig() {
        let sks: Vec<_> = (0..4u64)
            .map(|i| BlsSecretKey::from_seed(300 + i))
            .collect();
        let msg = b"m";
        let sigs: Vec<_> = sks.iter().map(|s| s.sign(Domain::Vote, msg)).collect();
        let pks: Vec<_> = sks.iter().map(|s| s.public()).collect();
        let agg_sig = aggregate_signatures(&sigs).expect("agg sig");
        let agg_pk = aggregate_pubkeys(&pks).expect("agg pk");

        // Flip one byte in the middle of the aggregate signature; re-parse.
        let mut raw = agg_sig.to_bytes();
        raw[40] ^= 0x01;
        // Tampered bytes either fail to decode (acceptable rejection) or, if they
        // still parse as a curve point, must fail verification.
        if let Some(bad) = BlsSignature::from_bytes(&raw) {
            assert!(!aggregate_verify(Domain::Vote, msg, &bad, &agg_pk));
        }
    }

    // Insufficient and mismatched signer sets are rejected.
    #[test]
    fn aggregate_verify_rejects_mismatched_signer_set() {
        let sks: Vec<_> = (0..4u64)
            .map(|i| BlsSecretKey::from_seed(400 + i))
            .collect();
        let msg = b"m";
        // Aggregate signature over ALL 4 signers...
        let sigs: Vec<_> = sks.iter().map(|s| s.sign(Domain::Vote, msg)).collect();
        let agg_sig = aggregate_signatures(&sigs).expect("agg sig");

        // ...but aggregate the public keys of only 3 of them (drop signer 3).
        let pks_short: Vec<_> = sks[..3].iter().map(|s| s.public()).collect();
        let agg_pk_short = aggregate_pubkeys(&pks_short).expect("agg pk");

        // Signer set of the signature and of the public key disagree -> reject.
        assert!(!aggregate_verify(
            Domain::Vote,
            msg,
            &agg_sig,
            &agg_pk_short
        ));
        assert!(!fast_aggregate_verify(
            Domain::Vote,
            msg,
            &agg_sig,
            &pks_short
        ));

        // Symmetric: extra public key not represented in the signature.
        let pks_long: Vec<_> = (0..5u64)
            .map(|i| BlsSecretKey::from_seed(400 + i).public())
            .collect();
        assert!(!fast_aggregate_verify(
            Domain::Vote,
            msg,
            &agg_sig,
            &pks_long
        ));
    }

    // Signature schemes remain isolated.
    #[test]
    fn cross_scheme_isolation() {
        use crate::keypair::Keypair;

        // A secp256k1 signature (~64-71 bytes) is not a valid 96-byte BLS sig.
        let secp = Keypair::from_seed(7);
        let secp_sig = secp.sign(Domain::Vote, b"x"); // Vec<u8>, wrong length for BLS
        assert!(BlsSignature::from_bytes(&secp_sig).is_none());

        // A secp public key (33-byte SEC1) is not a valid 48-byte BLS pubkey.
        let secp_pk = secp.pubkey_bytes();
        assert!(BlsPublicKey::from_bytes(&secp_pk).is_none());

        // Reverse direction: a 96-byte BLS signature is not a valid secp sig,
        // and a 48-byte BLS pubkey is not a valid secp SEC1 key, so the secp
        // verifier rejects them outright (returns false, never panics).
        let bls = BlsSecretKey::from_seed(7);
        let bls_sig = bls.sign(Domain::Vote, b"x").to_bytes();
        let bls_pk = bls.public().to_bytes();
        assert!(!crate::keypair::verify(
            Domain::Vote,
            b"x",
            &bls_sig,
            &bls_pk
        ));
    }

    #[test]
    fn from_bytes_rejects_wrong_length_and_garbage() {
        assert!(BlsPublicKey::from_bytes(&[0u8; 47]).is_none());
        assert!(BlsPublicKey::from_bytes(&[0u8; 49]).is_none());
        assert!(BlsPublicKey::from_bytes(&[]).is_none());
        // Right length but all-zero is not a valid (uncompressed/validated) point.
        assert!(BlsPublicKey::from_bytes(&[0u8; BLS_PUBLIC_KEY_LEN]).is_none());

        assert!(BlsSignature::from_bytes(&[0u8; 95]).is_none());
        assert!(BlsSignature::from_bytes(&[0u8; 97]).is_none());
        assert!(BlsSignature::from_bytes(&[0xffu8; BLS_SIGNATURE_LEN]).is_none());
    }

    // Deterministic and reproducible signatures.
    #[test]
    fn keygen_is_deterministic() {
        // Same seed -> identical public key bytes and identical signature bytes.
        let a = BlsSecretKey::from_seed(42);
        let b = BlsSecretKey::from_seed(42);
        assert_eq!(a.public().to_bytes(), b.public().to_bytes());

        let sig_a = a.sign(Domain::Vote, b"determinism");
        let sig_b = b.sign(Domain::Vote, b"determinism");
        assert_eq!(sig_a.to_bytes(), sig_b.to_bytes());

        // Different seeds -> different keys.
        let c = BlsSecretKey::from_seed(43);
        assert_ne!(a.public().to_bytes(), c.public().to_bytes());
    }

    #[test]
    fn encoding_round_trips() {
        let sk = BlsSecretKey::from_seed(99);
        let pk = sk.public();
        let sig = sk.sign(Domain::Vote, b"rt");

        let pk2 = BlsPublicKey::from_bytes(&pk.to_bytes()).expect("pk roundtrip");
        let sig2 = BlsSignature::from_bytes(&sig.to_bytes()).expect("sig roundtrip");
        assert_eq!(pk, pk2);
        assert_eq!(sig, sig2);
        assert!(bls_verify(Domain::Vote, b"rt", &sig2, &pk2));
    }

    /// Cross-platform byte-stability anchor: pin the public key and
    /// signature bytes for a fixed seed so any library/version/platform change
    /// that perturbs the encoding is caught as a regression here. `blst`'s
    /// deterministic key derivation + BLS signing (no per-signature nonce)
    /// makes both values fixed for a given seed and message.
    #[test]
    fn known_seed_byte_vectors_are_stable() {
        let sk = BlsSecretKey::from_seed(1);
        let pk = sk.public().to_bytes();
        let sig = sk
            .sign(Domain::Vote, b"azbft-bls-test-vector-v1")
            .to_bytes();

        // Self-consistency: the pinned bytes verify against each other.
        let pk_parsed = BlsPublicKey::from_bytes(&pk).expect("pk");
        let sig_parsed = BlsSignature::from_bytes(&sig).expect("sig");
        assert!(bls_verify(
            Domain::Vote,
            b"azbft-bls-test-vector-v1",
            &sig_parsed,
            &pk_parsed
        ));

        // Lengths are the min-pk compressed sizes.
        assert_eq!(pk.len(), BLS_PUBLIC_KEY_LEN);
        assert_eq!(sig.len(), BLS_SIGNATURE_LEN);

        // Cross-platform byte-stability anchors. If a future
        // toolchain/blst bump perturbs the encoding, these assertions fire and
        // force a conscious review. The values are not security-sensitive — a
        // public key and a signature for a throwaway seed. Pinned by the reference-vector helper below.
        assert_eq!(pk, EXPECTED_PK_SEED1);
        assert_eq!(sig, EXPECTED_SIG_SEED1);
    }

    // Proof-of-possession protects aggregate verification.
    #[test]
    fn proof_of_possession_roundtrip() {
        let sk = BlsSecretKey::from_seed(77);
        let pop = sk.prove_possession();
        // Valid PoP verifies against its own key.
        assert!(pop_verify(&sk.public(), &pop));
        // PoP of one key must not verify against a different key.
        let other = BlsSecretKey::from_seed(78);
        assert!(!pop_verify(&other.public(), &pop));
        // A regular message signature is not a valid PoP (different DST).
        let msg_sig = sk.sign(Domain::Vote, &sk.public().to_bytes());
        assert!(!pop_verify(&sk.public(), &msg_sig));
    }

    #[test]
    fn registration_rejects_key_without_valid_pop() {
        // Exercise the validator-key registration check: a key is only admitted to the
        // aggregate set if it ships a valid PoP. A key whose PoP is missing or
        // forged (here: a PoP made by a *different* key) must be rejected, which
        // is what closes the rogue-key hole in the fast-aggregate path.
        let honest = BlsSecretKey::from_seed(81);
        let attacker = BlsSecretKey::from_seed(82);

        let good_pop = honest.prove_possession();
        assert!(pop_verify(&honest.public(), &good_pop));

        // Attacker presents the honest key but signs the PoP with its own key.
        let forged_pop = attacker.prove_possession();
        assert!(!pop_verify(&honest.public(), &forged_pop));
    }

    // Pinned byte vectors for seed=1 / Domain::Vote / b"azbft-bls-test-vector-v1".
    // min-pk: pk = 48B G1 compressed, sig = 96B G2 compressed. Generated by the pinned Rust toolchain and `blst` dependency. See
    // `known_seed_byte_vectors_are_stable`.
    const EXPECTED_PK_SEED1: [u8; BLS_PUBLIC_KEY_LEN] = PK_SEED1;
    const EXPECTED_SIG_SEED1: [u8; BLS_SIGNATURE_LEN] = SIG_SEED1;

    include!("bls_test_vectors.rs");
}
