//! Fan-out of evaluated events to the output sinks (terminal, audit log...).
//!
//! Generated with AI assistance (Claude Code).

pub(crate) mod dispatcher;
mod event_log;
mod term;

use async_trait::async_trait;

/// Placeholder for the neutralized event type the sinks receive.
pub(crate) type EventResult = u32;

/// One output destination. Each sink runs in its own task, so a slow sink only delays itself.
#[async_trait]
pub(crate) trait Sink: Send {
    async fn write(&mut self, result: &EventResult) -> Result<(), SinkError>;
}

#[derive(Debug)]
pub(crate) enum SinkError {}
