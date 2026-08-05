//! Opt-in consensus crypto timings drained by the node driver.
//!
//! This intentionally avoids a metrics dependency in `azbft-crypto`. A host may
//! enable sampling with `AZBFT_CRYPTO_PERF=1`, drain this process-local queue,
//! and export the samples through its own observability stack. The legacy
//! `AZ_CONSENSUS_PERF` name remains a compatibility alias when the preferred
//! variable is absent.

use std::cell::Cell;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

const MAX_PENDING_SAMPLES: usize = 16_384;

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    SingleVoteVerify,
    AggregateVerify,
    QcAggregate,
}

#[derive(Clone, Copy, Debug)]
pub struct Sample {
    pub kind: Kind,
    pub elapsed_us: u64,
}

static ENABLED: OnceLock<bool> = OnceLock::new();
static SAMPLES: OnceLock<Mutex<Vec<Sample>>> = OnceLock::new();

thread_local! {
    // Aggregate verification invokes the secp single-signature verifier for
    // every constituent signature.  Suppress those nested samples so the
    // single-vote and aggregate histograms are disjoint.
    static AGG_VERIFY_DEPTH: Cell<u32> = const { Cell::new(0) };
}

fn enabled_from_values(preferred: Option<&str>, legacy: Option<&str>) -> bool {
    preferred
        .or(legacy)
        .map(|value| value != "0" && !value.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

fn enabled_from_env() -> bool {
    if let Some(preferred) = std::env::var_os("AZBFT_CRYPTO_PERF") {
        return enabled_from_values(preferred.to_str(), None);
    }
    let legacy = std::env::var_os("AZ_CONSENSUS_PERF");
    enabled_from_values(None, legacy.as_deref().and_then(|value| value.to_str()))
}

pub fn enabled() -> bool {
    *ENABLED.get_or_init(enabled_from_env)
}

pub fn start() -> Option<Instant> {
    // determinism-ok-begin -- opt-in elapsed-time observation only; the sample is
    // drained into metrics and never influences verification or consensus output.
    enabled().then(Instant::now)
    // determinism-ok-end
}

fn record(kind: Kind, started: Option<Instant>) {
    let Some(started) = started else {
        return;
    };
    let sample = Sample {
        kind,
        elapsed_us: started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64,
    };
    let mut samples = SAMPLES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if samples.len() < MAX_PENDING_SAMPLES {
        samples.push(sample);
    }
}

pub fn record_single_vote_verify(started: Option<Instant>) {
    let nested = AGG_VERIFY_DEPTH.with(|depth| depth.get() != 0);
    if !nested {
        record(Kind::SingleVoteVerify, started);
    }
}

pub fn record_qc_aggregate(started: Option<Instant>) {
    record(Kind::QcAggregate, started);
}

pub struct AggregateVerifyGuard;

impl AggregateVerifyGuard {
    pub fn enter() -> Self {
        AGG_VERIFY_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self
    }
}

impl Drop for AggregateVerifyGuard {
    fn drop(&mut self) {
        AGG_VERIFY_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

pub fn record_aggregate_verify(started: Option<Instant>) {
    record(Kind::AggregateVerify, started);
}

pub fn take_samples() -> Vec<Sample> {
    let mut samples = SAMPLES
        .get_or_init(|| Mutex::new(Vec::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::mem::take(&mut *samples)
}

#[cfg(test)]
mod tests {
    use super::enabled_from_values;

    #[test]
    fn preferred_value_enables_sampling() {
        assert!(enabled_from_values(Some("1"), Some("0")));
    }

    #[test]
    fn legacy_value_enables_sampling_when_preferred_is_absent() {
        assert!(enabled_from_values(None, Some("true")));
    }

    #[test]
    fn preferred_false_overrides_legacy_true() {
        assert!(!enabled_from_values(Some("0"), Some("1")));
        assert!(!enabled_from_values(Some("false"), Some("true")));
    }

    #[test]
    fn missing_values_disable_sampling() {
        assert!(!enabled_from_values(None, None));
    }
}
