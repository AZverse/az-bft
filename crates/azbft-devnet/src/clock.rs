use std::collections::BTreeMap;

/// Deterministic virtual-time event queue.
pub(crate) struct EventQueue<E> {
    time: u64,
    sequence: u64,
    events: BTreeMap<(u64, u64), (usize, E)>,
}

impl<E> EventQueue<E> {
    pub(crate) fn new() -> Self {
        Self {
            time: 0,
            sequence: 0,
            events: BTreeMap::new(),
        }
    }

    pub(crate) fn now(&self) -> u64 {
        self.time
    }

    pub(crate) fn schedule(&mut self, at: u64, validator: usize, event: E) {
        let key = (at.max(self.time), self.sequence);
        self.sequence += 1;
        self.events.insert(key, (validator, event));
    }

    pub(crate) fn pop(&mut self) -> Option<(usize, E)> {
        let key = *self.events.keys().next()?;
        self.time = key.0;
        self.events.remove(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::EventQueue;

    #[test]
    fn equal_time_events_remain_fifo() {
        let mut queue = EventQueue::new();
        queue.schedule(5, 0, "first");
        queue.schedule(1, 1, "early");
        queue.schedule(5, 2, "second");

        assert_eq!(queue.pop(), Some((1, "early")));
        assert_eq!(queue.pop(), Some((0, "first")));
        assert_eq!(queue.pop(), Some((2, "second")));
    }
}
