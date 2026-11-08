use azbft_types::{NodeId, Round};
use std::collections::BTreeMap;

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
///
/// Votes now also go to the block's author, which certifies the predecessor's
/// block itself, so only the crashed validator's own round expires per pass;
/// that round is the one this keeps at base.
pub const UNBACKED_TIMEOUTS: u32 = 1;

/// How many of its rounds a leader must let expire without a proposal before
/// this node shortens the timer of its rounds.
///
/// A validator that is down still leads its share of rounds; each of them
/// waits out the whole timer. With six validators and one down the chain
/// committed about 4 blocks/s against 27 (blockchain#191). The leader schedule
/// and the voting rules stay as they are: only this node's wait for an absent
/// leader shrinks, so safety is untouched, and the backoff still grows over it
/// when rounds keep expiring for some other reason.
pub const ABSENT_LEADER_ROUNDS: u32 = 3;

/// The timer of an absent leader's round is the base divided by this (at least 1 ms).
pub const ABSENT_LEADER_TIMER_DIVISOR: u64 = 4;

pub struct Pacemaker {
    base: u64,
    consecutive_timeouts: u32,
    /// Rounds each leader let expire without a proposal since its last one.
    silent: BTreeMap<NodeId, u32>,
}

impl Pacemaker {
    pub fn new(base: u64) -> Self {
        Self {
            base,
            consecutive_timeouts: 0,
            silent: BTreeMap::new(),
        }
    }

    pub fn timer_duration(&self, round: Round) -> u64 {
        self.timer_duration_led_by(round, None)
    }

    /// The timer of `round`, led by `leader` if known: the base, divided for
    /// a leader absent for [`ABSENT_LEADER_ROUNDS`] of its rounds, then backed
    /// off for consecutive timeouts.
    pub fn timer_duration_led_by(&self, _round: Round, leader: Option<NodeId>) -> u64 {
        let doublings = self
            .consecutive_timeouts
            .saturating_sub(UNBACKED_TIMEOUTS)
            .min(MAX_BACKOFF_DOUBLINGS);
        let base = if leader.is_some_and(|leader| self.is_absent(&leader)) {
            (self.base / ABSENT_LEADER_TIMER_DIVISOR).max(1)
        } else {
            self.base
        };
        base.saturating_mul(1u64 << doublings)
    }

    /// Whether `leader` let [`ABSENT_LEADER_ROUNDS`] of its rounds expire
    /// without a proposal since its last one.
    pub fn is_absent(&self, leader: &NodeId) -> bool {
        self.silent.get(leader).copied().unwrap_or(0) >= ABSENT_LEADER_ROUNDS
    }

    /// A round led by `leader` expired without its proposal.
    pub fn on_leader_silent(&mut self, leader: NodeId) {
        let silent = self.silent.entry(leader).or_insert(0);
        *silent = silent.saturating_add(1);
    }

    /// `leader` proposed: it is no longer absent.
    pub fn on_leader_proposed(&mut self, leader: &NodeId) {
        self.silent.remove(leader);
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

    /// A leader that lets three of its rounds expire is absent: its rounds
    /// get a quarter of the timer, still backed off; a proposal from it ends
    /// that. Other leaders keep the full timer.
    #[test]
    fn an_absent_leader_gets_a_shorter_timer_until_it_proposes() {
        let absent = NodeId([7; 20]);
        let other = NodeId([8; 20]);
        let mut p = Pacemaker::new(100);
        for _ in 0..ABSENT_LEADER_ROUNDS - 1 {
            p.on_leader_silent(absent);
        }
        assert_eq!(
            p.timer_duration_led_by(Round(1), Some(absent)),
            100,
            "not yet absent"
        );
        p.on_leader_silent(absent);
        assert!(p.is_absent(&absent));
        assert_eq!(p.timer_duration_led_by(Round(1), Some(absent)), 25);
        assert_eq!(p.timer_duration_led_by(Round(1), Some(other)), 100);
        assert_eq!(p.timer_duration_led_by(Round(1), None), 100);
        p.on_local_timeout(Round(1));
        p.on_local_timeout(Round(2));
        assert_eq!(
            p.timer_duration_led_by(Round(3), Some(absent)),
            50,
            "backoff still applies"
        );
        p.on_leader_proposed(&absent);
        assert!(!p.is_absent(&absent));
        assert_eq!(p.timer_duration_led_by(Round(3), Some(absent)), 200);
        assert_eq!(Pacemaker::new(2).timer_duration_led_by(Round(1), None), 2);
        let mut tiny = Pacemaker::new(2);
        for _ in 0..ABSENT_LEADER_ROUNDS {
            tiny.on_leader_silent(absent);
        }
        assert_eq!(
            tiny.timer_duration_led_by(Round(1), Some(absent)),
            1,
            "never zero"
        );
    }

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
