use azbft_crypto::aggregator::{AggError, SecpMultiSig, VoteAggregator};
use azbft_crypto::apphash::{verify_app_hash_cert_v1, AppHashCertError};
use azbft_crypto::domain::Domain;
use azbft_crypto::keypair::Keypair;
use azbft_types::{
    validator_set_hash, AggSig, AppHashCertV1, AppHashStatementV1, Hash, Member, ValidatorSet,
};

fn test_keypair(seed: u64) -> Keypair {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[31] = 1;
    Keypair::from_sk_bytes(&bytes).expect("valid test scalar")
}

fn setup() -> (Vec<Keypair>, ValidatorSet, AppHashStatementV1) {
    let keypairs = (0..4)
        .map(|seed| test_keypair(100 + seed))
        .collect::<Vec<_>>();
    let vset = ValidatorSet::new_members(
        keypairs
            .iter()
            .map(|keypair| Member::secp_only(keypair.node_id(), keypair.pubkey_bytes(), 1))
            .collect(),
    );
    let statement = AppHashStatementV1 {
        chain_id: 1337,
        epoch: 7,
        validator_set_hash: validator_set_hash(&vset),
        height: 10_000,
        app_hash: Hash([0x27; 32]),
    };
    (keypairs, vset, statement)
}

fn votes(
    keypairs: &[Keypair],
    statement: &AppHashStatementV1,
    domain: Domain,
    count: usize,
) -> Vec<(azbft_types::NodeId, Vec<u8>)> {
    keypairs
        .iter()
        .take(count)
        .map(|keypair| (keypair.node_id(), keypair.sign(domain, &statement.id().0)))
        .collect()
}

fn cert(statement: AppHashStatementV1, votes: &[(azbft_types::NodeId, Vec<u8>)]) -> AppHashCertV1 {
    AppHashCertV1 {
        statement,
        agg: SecpMultiSig::aggregate(votes),
    }
}

#[test]
fn apphash_certificate_v1_accepts_three_of_four_stake() {
    let (keypairs, vset, statement) = setup();
    let cert = cert(
        statement.clone(),
        &votes(&keypairs, &statement, Domain::AppHash, 3),
    );
    assert!(verify_app_hash_cert_v1(&cert, &vset).is_ok());
}

#[test]
fn apphash_certificate_v1_rejects_mismatched_validator_set_hash() {
    let (keypairs, vset, statement) = setup();
    let mut cert = cert(
        statement.clone(),
        &votes(&keypairs, &statement, Domain::AppHash, 3),
    );
    cert.statement.validator_set_hash = Hash([0xff; 32]);
    assert!(matches!(
        verify_app_hash_cert_v1(&cert, &vset),
        Err(AppHashCertError::ValidatorSetHashMismatch)
    ));
}

#[test]
fn apphash_certificate_v1_rejects_below_quorum() {
    let (keypairs, vset, statement) = setup();
    let cert = cert(
        statement.clone(),
        &votes(&keypairs, &statement, Domain::AppHash, 2),
    );
    assert!(matches!(
        verify_app_hash_cert_v1(&cert, &vset),
        Err(AppHashCertError::Aggregate(AggError::BelowQuorum {
            got: 2,
            need: 3
        }))
    ));
}

#[test]
fn apphash_certificate_v1_rejects_duplicate_signer() {
    let (keypairs, vset, statement) = setup();
    let signed = votes(&keypairs, &statement, Domain::AppHash, 3);
    let mut duplicate = SecpMultiSig::aggregate(&signed);
    let AggSig::Secp(sigs) = &mut duplicate else {
        panic!("secp aggregate expected");
    };
    sigs.insert(1, sigs[0].clone());
    let cert = AppHashCertV1 {
        statement,
        agg: duplicate,
    };
    assert!(matches!(
        verify_app_hash_cert_v1(&cert, &vset),
        Err(AppHashCertError::Aggregate(AggError::Duplicate(_)))
    ));
}

#[test]
fn apphash_certificate_v1_rejects_unknown_signer() {
    let (keypairs, vset, statement) = setup();
    let mut signed = votes(&keypairs, &statement, Domain::AppHash, 3);
    let unknown = test_keypair(999);
    signed.push((
        unknown.node_id(),
        unknown.sign(Domain::AppHash, &statement.id().0),
    ));
    signed.sort_by_key(|vote| vote.0);
    let cert = AppHashCertV1 {
        statement,
        agg: AggSig::Secp(signed),
    };
    assert!(matches!(
        verify_app_hash_cert_v1(&cert, &vset),
        Err(AppHashCertError::Aggregate(AggError::UnknownSigner(_)))
    ));
}

#[test]
fn apphash_certificate_v1_rejects_malformed_signature() {
    let (keypairs, vset, statement) = setup();
    let mut signed = votes(&keypairs, &statement, Domain::AppHash, 3);
    signed.sort_by_key(|vote| vote.0);
    signed[0].1 = vec![0x01];
    let cert = AppHashCertV1 {
        statement,
        agg: AggSig::Secp(signed),
    };
    assert!(matches!(
        verify_app_hash_cert_v1(&cert, &vset),
        Err(AppHashCertError::Aggregate(AggError::BadSig(_)))
    ));
}

#[test]
fn apphash_certificate_v1_rejects_vote_domain_signature() {
    let (keypairs, vset, statement) = setup();
    let cert = cert(
        statement.clone(),
        &votes(&keypairs, &statement, Domain::Vote, 3),
    );
    assert!(matches!(
        verify_app_hash_cert_v1(&cert, &vset),
        Err(AppHashCertError::Aggregate(AggError::BadSig(_)))
    ));
}
