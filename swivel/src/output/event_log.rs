//! Bounded event buffer with one read cursor per sink and exact loss accounting.
//!
//! Generated with AI assistance (Claude Code).

use std::collections::{vec_deque, VecDeque};

pub(crate) type SinkId = u32;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LogError {
    IdOverflow,
    SinkNotFound(SinkId),
    CannotRemoveForcedSink(SinkId),
}

struct SinkEntry {
    id: SinkId,
    is_forced: bool,
    cursor: u64,
    skipped: u64,
}

/// Events pending for one sink, borrowed from the log while its lock is held.
pub(super) struct Pending<'a, T> {
    pub(super) skipped: u64,
    pub(super) events: vec_deque::Iter<'a, T>,
}

/// State behind the dispatcher's mutex. Knows nothing about locks, so it is tested directly.
pub(super) struct EventLog<T> {
    events: VecDeque<T>,
    base: u64,
    capacity: usize,
    entries: Vec<SinkEntry>,
    last_id: SinkId,
}

impl<T> EventLog<T> {
    pub(super) fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "event log capacity must be at least 1");
        Self {
            events: VecDeque::with_capacity(capacity),
            base: 0,
            capacity,
            entries: Vec::new(),
            last_id: 0,
        }
    }

    /// Sequence number one past the newest event: what the dispatcher publishes to sinks.
    pub(super) fn head(&self) -> u64 {
        self.base + self.events.len() as u64
    }

    /// Adds a sink that starts at the next event to arrive, not at the buffered backlog.
    pub(super) fn register(&mut self, is_forced: bool) -> Result<SinkId, LogError> {
        self.last_id = self.last_id.checked_add(1).ok_or(LogError::IdOverflow)?;
        let cursor = self.head();
        self.entries.push(SinkEntry {
            id: self.last_id,
            is_forced,
            cursor,
            skipped: 0,
        });
        Ok(self.last_id)
    }

    /// Removes a sink; forced sinks are rejected so the audit output cannot be detached.
    pub(super) fn remove(&mut self, id: SinkId) -> Result<(), LogError> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.id == id)
            .ok_or(LogError::SinkNotFound(id))?;
        if self.entries[idx].is_forced {
            return Err(LogError::CannotRemoveForcedSink(id));
        }
        self.entries.swap_remove(idx);
        Ok(())
    }

    /// Appends `event` without ever exceeding capacity and returns the new head.
    pub(super) fn push(&mut self, event: T) -> u64 {
        if self.events.len() >= self.capacity {
            self.purge();
        }
        self.events.push_back(event);
        self.head()
    }

    /// Hands sink `id` up to `max` pending events and takes its skipped count.
    ///
    /// The cursor advances here, before the sink writes: delivery is at-most-once.
    pub(super) fn read(&mut self, id: SinkId, max: usize) -> Result<Pending<'_, T>, LogError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(LogError::SinkNotFound(id))?;
        let start = entry.cursor.saturating_sub(self.base) as usize;
        let end = start.saturating_add(max).min(self.events.len());
        entry.cursor = self.base + end as u64;
        let skipped = std::mem::take(&mut entry.skipped);
        Ok(Pending {
            skipped,
            events: self.events.range(start..end),
        })
    }

    /// Frees everything all sinks have read and, if that is not enough to fit one more event,
    /// drops the oldest ones and charges each lagging sink exactly what it lost.
    fn purge(&mut self) {
        let read_by_all = self
            .entries
            .iter()
            .map(|e| e.cursor.saturating_sub(self.base) as usize)
            .min()
            .unwrap_or(self.events.len());
        let excess = (self.events.len() + 1).saturating_sub(self.capacity);
        let to_remove = read_by_all.max(excess).min(self.events.len());

        self.events.drain(..to_remove);
        self.base += to_remove as u64;

        for entry in &mut self.entries {
            if entry.cursor < self.base {
                entry.skipped += self.base - entry.cursor;
                entry.cursor = self.base;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(log: &mut EventLog<u32>, id: SinkId) -> (u64, Vec<u32>) {
        let pending = log.read(id, usize::MAX).unwrap();
        (pending.skipped, pending.events.copied().collect())
    }

    #[test]
    fn lagging_sink_is_charged_exactly_what_it_lost() {
        let mut log = EventLog::new(4);
        let fast = log.register(false).unwrap();
        let slow = log.register(false).unwrap();

        for e in 1..=4 {
            log.push(e);
        }
        assert_eq!(read_all(&mut log, fast), (0, vec![1, 2, 3, 4]));

        log.push(5);
        log.push(6);
        assert!(log.events.len() <= 4);

        assert_eq!(read_all(&mut log, fast), (0, vec![5, 6]));
        assert_eq!(read_all(&mut log, slow), (2, vec![3, 4, 5, 6]));
        assert_eq!(read_all(&mut log, slow), (0, vec![]));
    }

    #[test]
    fn every_event_is_either_delivered_or_reported_under_load() {
        let mut log = EventLog::new(3);
        let fast = log.register(false).unwrap();
        let slow = log.register(true).unwrap();
        let (mut fast_seen, mut slow_seen, mut slow_lost) = (Vec::new(), 0, 0);

        for e in 0..100 {
            log.push(e);
            assert!(log.events.len() <= 3);
            fast_seen.extend(read_all(&mut log, fast).1);
            if e % 7 == 0 {
                let (lost, got) = read_all(&mut log, slow);
                slow_lost += lost;
                slow_seen += got.len() as u64;
            }
        }
        let (lost, got) = read_all(&mut log, slow);

        assert_eq!(fast_seen, (0..100).collect::<Vec<_>>());
        assert_eq!(slow_lost + lost + slow_seen + got.len() as u64, 100);
        assert!(slow_lost + lost > 0);
    }

    #[test]
    fn new_sink_starts_at_head_not_at_backlog() {
        let mut log = EventLog::new(8);
        log.register(false).unwrap();
        log.push(1);
        log.push(2);
        let late = log.register(false).unwrap();
        log.push(3);
        assert_eq!(read_all(&mut log, late), (0, vec![3]));
    }

    #[test]
    fn without_sinks_the_log_stays_bounded_and_sequence_is_continuous() {
        let mut log = EventLog::new(2);
        for e in 0..10u32 {
            assert_eq!(log.push(e), u64::from(e) + 1);
            assert!(log.events.len() <= 2);
        }
    }

    #[test]
    fn forced_sink_cannot_be_removed() {
        let mut log = EventLog::<u32>::new(2);
        let audit = log.register(true).unwrap();
        let term = log.register(false).unwrap();

        assert_eq!(
            log.remove(audit),
            Err(LogError::CannotRemoveForcedSink(audit))
        );
        assert_eq!(log.remove(term), Ok(()));
        assert_eq!(log.remove(term), Err(LogError::SinkNotFound(term)));
        assert!(matches!(log.read(term, 1), Err(LogError::SinkNotFound(_))));
        assert!(log.read(audit, 1).is_ok());
    }
}
