use azbft_types::Round;

pub struct Pacemaker {
    base: u64,
    consecutive_timeouts: u32,
}

impl Pacemaker {
    pub fn new(base: u64) -> Self {
        Self {
            base,
            consecutive_timeouts: 0,
        }
    }

    pub fn timer_duration(&self, _round: Round) -> u64 {
        self.base
            .saturating_mul(1u64 << self.consecutive_timeouts.min(16))
    }

    pub fn on_local_timeout(&mut self, _round: Round) {
        self.consecutive_timeouts += 1;
    }

    pub fn on_progress(&mut self, _new_round: Round) {
        self.consecutive_timeouts = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azbft_types::Round;

    #[test]
    fn backoff_doubles_on_consecutive_timeouts() {
        let mut p = Pacemaker::new(100);
        assert_eq!(p.timer_duration(Round(1)), 100);
        p.on_local_timeout(Round(1));
        assert_eq!(p.timer_duration(Round(2)), 200);
        p.on_local_timeout(Round(2));
        assert_eq!(p.timer_duration(Round(3)), 400);
    }

    #[test]
    fn progress_resets_backoff() {
        let mut p = Pacemaker::new(100);
        p.on_local_timeout(Round(1));
        p.on_progress(Round(2));
        assert_eq!(p.timer_duration(Round(3)), 100);
    }
}
