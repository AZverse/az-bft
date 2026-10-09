use azbft_types::Round;

/// The most times the round timer doubles before it stops growing, so the
/// longest timer is `base << MAX_BACKOFF_DOUBLINGS` (64 x base).
///
/// The cap is what bounds recovery once the cause of a run of expired rounds is
/// gone: every validator still waits out the timer it has grown to before it
/// can time out the round it is stuck in. Backoff carries over rounds left by
/// timeout certificate, so a long run of failed rounds reaches the cap, and a
/// cap of 16 doublings would leave a 70 ms base timer at about 76 minutes.
pub const MAX_BACKOFF_DOUBLINGS: u32 = 6;

/// How many consecutive timeouts after a certified round leave the timer at
/// base before it starts doubling.
///
/// One crashed validator expires two rounds in a row on every pass of the
/// round-robin schedule: its own, and its predecessor's, whose votes are
/// addressed to it as the next leader and are lost. If the second of those
/// rounds is armed with a doubled timer, a 4-validator devnet with one validator
/// down spends 50 + 50 + 200 + 400 ms per pass at a 200 ms base and commits
/// 2.76 blocks/s against 23 with everyone up. Leaving the first timeout
/// unbacked arms that round at base. Doubling still starts at the second
/// consecutive timeout, so a round length too short for the load is still
/// outgrown, one round later than before.
pub const UNBACKED_TIMEOUTS: u32 = 1;

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
        let doublings = self
            .consecutive_timeouts
            .saturating_sub(UNBACKED_TIMEOUTS)
            .min(MAX_BACKOFF_DOUBLINGS);
        self.base.saturating_mul(1u64 << doublings)
    }

    pub fn on_local_timeout(&mut self, _round: Round) {
        self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
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
        assert_eq!(
            p.timer_duration(Round(2)),
            100,
            "the first timeout after progress keeps the base timer"
        );
        p.on_local_timeout(Round(2));
        assert_eq!(p.timer_duration(Round(3)), 200);
        p.on_local_timeout(Round(3));
        assert_eq!(p.timer_duration(Round(4)), 400);
    }

    #[test]
    fn progress_resets_backoff() {
        let mut p = Pacemaker::new(100);
        p.on_local_timeout(Round(1));
        p.on_local_timeout(Round(2));
        p.on_progress(Round(3));
        assert_eq!(p.timer_duration(Round(3)), 100);
    }

    /// The timer stops growing at the cap, however many rounds keep expiring.
    #[test]
    fn backoff_stops_growing_at_the_cap() {
        let mut p = Pacemaker::new(70);
        for round in 1..=u64::from(UNBACKED_TIMEOUTS + MAX_BACKOFF_DOUBLINGS) {
            p.on_local_timeout(Round(round));
        }
        let cap = 70 << MAX_BACKOFF_DOUBLINGS;
        assert_eq!(
            p.timer_duration(Round(0)),
            cap,
            "the last doubling reaches the cap"
        );
        for round in 0..100 {
            p.on_local_timeout(Round(round));
        }
        assert_eq!(
            p.timer_duration(Round(0)),
            cap,
            "further timeouts do not grow it"
        );
        p.on_progress(Round(1));
        assert_eq!(
            p.timer_duration(Round(1)),
            70,
            "progress still returns to base"
        );
    }
}
