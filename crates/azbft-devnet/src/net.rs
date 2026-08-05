use rand_chacha::ChaCha8Rng;
use rand_core::RngCore;

/// Small deterministic logical delay used by the in-memory devnet.
pub(crate) struct Network {
    minimum_delay: u64,
    delay_span: u64,
}

impl Network {
    pub(crate) fn local() -> Self {
        Self {
            minimum_delay: 1,
            delay_span: 4,
        }
    }

    pub(crate) fn delay(&self, source: usize, target: usize, rng: &mut ChaCha8Rng) -> u64 {
        if source == target {
            0
        } else {
            self.minimum_delay + rng.next_u64() % self.delay_span
        }
    }
}
