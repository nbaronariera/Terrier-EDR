//! Shares the event log between the producer and one delivery task per sink.
//!
//! Generated with AI assistance (Claude Code).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use log::warn;
use tokio::sync::watch;

use super::{
    EventResult, Sink,
    event_log::{EventLog, LogError, SinkId},
};

/// Events a sink copies out per lock acquisition; bounds how long the producer can be blocked.
const BATCH: usize = 64;

type SharedLog = Arc<Mutex<EventLog<EventResult>>>;

pub(crate) struct Dispatcher {
    log: SharedLog,
    head: watch::Sender<u64>,
}

impl Dispatcher {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            log: Arc::new(Mutex::new(EventLog::new(capacity))),
            head: watch::Sender::new(0),
        }
    }

    /// Starts delivering to `sink` from the next published event. Must run inside a Tokio runtime.
    pub(crate) fn register(
        &self,
        sink: Box<dyn Sink>,
        name: &str,
        is_forced: bool,
    ) -> Result<SinkId, LogError> {
        let id = lock(&self.log).register(is_forced)?;
        tokio::spawn(deliver(
            Arc::clone(&self.log),
            self.head.subscribe(),
            sink,
            id,
            name.to_owned(),
        ));
        Ok(id)
    }

    /// Detaches a sink; its task exits on its next read.
    pub(crate) fn remove(&self, id: SinkId) -> Result<(), LogError> {
        lock(&self.log).remove(id)
    }

    pub(crate) fn publish(&self, event: EventResult) {
        let head = lock(&self.log).push(event);
        self.head.send_replace(head);
    }
}

async fn deliver(
    log: SharedLog,
    mut head: watch::Receiver<u64>,
    mut sink: Box<dyn Sink>,
    id: SinkId,
    name: String,
) {
    loop {
        // Copied out so the lock is never held across `write`.
        let Ok((skipped, batch)) = lock(&log)
            .read(id, BATCH)
            .map(|p| (p.skipped, p.events.copied().collect::<Vec<_>>()))
        else {
            return;
        };
        if skipped > 0 {
            warn!("sink {name} fell behind and lost {skipped} events");
        }
        // Reading before waiting covers events published between `register` and `subscribe`.
        if batch.is_empty() {
            if head.changed().await.is_err() {
                return;
            }
            continue;
        }
        for event in &batch {
            if let Err(e) = sink.write(event).await {
                warn!("sink {name} failed to write: {e:?}");
            }
        }
    }
}

/// The log is consistent between calls, so a panic elsewhere must not stop delivery.
fn lock(log: &SharedLog) -> MutexGuard<'_, EventLog<EventResult>> {
    log.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use async_trait::async_trait;
    use tokio::sync::mpsc;

    use super::*;
    use crate::output::SinkError;

    struct Channel(mpsc::UnboundedSender<EventResult>);

    #[async_trait]
    impl Sink for Channel {
        async fn write(&mut self, result: &EventResult) -> Result<(), SinkError> {
            let _ = self.0.send(*result);
            Ok(())
        }
    }

    async fn recv(rx: &mut mpsc::UnboundedReceiver<EventResult>) -> Option<EventResult> {
        tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .ok()
            .flatten()
    }

    #[tokio::test]
    async fn every_sink_gets_events_in_order() {
        let dispatcher = Dispatcher::new(16);
        let (tx_a, mut rx_a) = mpsc::unbounded_channel();
        let (tx_b, mut rx_b) = mpsc::unbounded_channel();
        dispatcher
            .register(Box::new(Channel(tx_a)), "a", true)
            .unwrap();
        dispatcher
            .register(Box::new(Channel(tx_b)), "b", false)
            .unwrap();

        for e in 0..10 {
            dispatcher.publish(e);
        }
        for e in 0..10 {
            assert_eq!(recv(&mut rx_a).await, Some(e));
            assert_eq!(recv(&mut rx_b).await, Some(e));
        }
    }

    #[tokio::test]
    async fn removed_sink_stops_receiving() {
        let dispatcher = Dispatcher::new(16);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let id = dispatcher
            .register(Box::new(Channel(tx)), "t", false)
            .unwrap();
        dispatcher.publish(1);
        assert_eq!(recv(&mut rx).await, Some(1));

        dispatcher.remove(id).unwrap();
        dispatcher.publish(2);
        // The task exits and drops the sender, closing the channel without delivering 2.
        assert_eq!(recv(&mut rx).await, None);
    }
}
