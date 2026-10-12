// SPDX-License-Identifier: Apache-2.0
//! Log events from the core, delivered to the app through a callback. The
//! app installs a `LogSink` once; every `tracing` event from this crate and
//! the ones under it (`khensu_net`, `khensu_outfox`, `khensu_mls`) arrives as
//! one call with its level, target, event name and `key=value` fields.

use std::fmt::Write as _;
use std::sync::{Arc, OnceLock};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

#[derive(uniffi::Enum, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl From<&Level> for LogLevel {
    fn from(l: &Level) -> Self {
        match *l {
            Level::TRACE => LogLevel::Trace,
            Level::DEBUG => LogLevel::Debug,
            Level::INFO => LogLevel::Info,
            Level::WARN => LogLevel::Warn,
            Level::ERROR => LogLevel::Error,
        }
    }
}

/// Implemented by the app. Called from whichever thread logged; keep it quick.
#[uniffi::export(with_foreign)]
pub trait LogSink: Send + Sync {
    /// `message` is the event name (`loop.returned`) and `fields` the rest as
    /// `key=value` pairs separated by spaces.
    fn log(&self, level: LogLevel, target: String, message: String, fields: String);
}

struct Visitor {
    message: String,
    fields: String,
}

impl Visit for Visitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
            self.message = self.message.trim_matches('"').to_string();
        } else {
            if !self.fields.is_empty() {
                self.fields.push(' ');
            }
            let _ = write!(self.fields, "{}={:?}", field.name(), value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            if !self.fields.is_empty() {
                self.fields.push(' ');
            }
            let _ = write!(self.fields, "{}={}", field.name(), value);
        }
    }
}

struct SinkLayer {
    sink: Arc<dyn LogSink>,
    min: LogLevel,
}

impl<S: Subscriber> Layer<S> for SinkLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let level = LogLevel::from(event.metadata().level());
        if level < self.min {
            return;
        }
        let mut v = Visitor { message: String::new(), fields: String::new() };
        event.record(&mut v);
        self.sink.log(level, event.metadata().target().to_string(), v.message, v.fields);
    }
}

static INSTALLED: OnceLock<()> = OnceLock::new();

/// Routes the core's log events to `sink` at `min_level` and above. The
/// first call installs the subscriber for the process; later calls fail.
#[uniffi::export]
pub fn set_log_sink(sink: Arc<dyn LogSink>, min_level: LogLevel) -> bool {
    if INSTALLED.get().is_some() {
        return false;
    }
    let ok = tracing_subscriber::registry().with(SinkLayer { sink, min: min_level }).try_init().is_ok();
    if ok {
        let _ = INSTALLED.set(());
    }
    ok
}
