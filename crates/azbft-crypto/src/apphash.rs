use crate::aggregator::{verify_agg, AggError};
use crate::domain::Domain;
use azbft_types::{validator_set_hash, AppHashCertV1, ValidatorSet};

#[derive(Debug, thiserror::Error)]
pub enum AppHashCertError {
    #[error("validator set hash mismatch")]
    ValidatorSetHashMismatch,
    #[error("aggregate verification failed: {0}")]
    Aggregate(#[from] AggError),
}

pub fn verify_app_hash_cert_v1(
    cert: &AppHashCertV1,
    historical_vset: &ValidatorSet,
) -> Result<(), AppHashCertError> {
    if validator_set_hash(historical_vset) != cert.statement.validator_set_hash {
        return Err(AppHashCertError::ValidatorSetHashMismatch);
    }
    verify_agg(
        &cert.agg,
        &cert.statement.id(),
        Domain::AppHash,
        historical_vset,
    )
    .map_err(AppHashCertError::Aggregate)
}
