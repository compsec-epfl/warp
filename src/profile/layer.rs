//! Tracing Layer that emits one JSON record per closed span.
//!
//! Span fields are captured via a [`FieldVisitor`] on `on_new_span`;
//! counter / timing snapshots are stashed in span extensions on
//! `on_enter` and differenced on `on_close`.
//!
//! Schema (version `warp.profile.v1`):
//!
//! ```json
//! {
//!   "schema": "warp.profile.v1",
//!   "phase": "twin_constraint",
//!   "wall_ns": 123456,
//!   "cpu_ns": 98765,
//!   "rss_delta_bytes": 1024,
//!   "counters": { "twin_constraint_rounds": 10, ... },
//!   "dimensions": { "log_l": 3, "log_m": 2, "log_n": 5 }
//! }
//! ```
//!
//! One record per line (newline-delimited JSON), written to the configured
//! `io::Write` sink. The enclosing module gates this file behind the
//! `profile` feature; no per-file `cfg` is needed here.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Mutex;
use std::time::Instant;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id};
use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

use crate::profile::counters::{self, Counter, Snapshot};
use crate::profile::{rss, timing};

/// What we stash on each span at enter-time.
struct SpanStart {
    wall: Instant,
    cpu_ns: Option<u64>,
    rss_bytes: Option<u64>,
    counters: Snapshot,
}

/// Dimensions (numeric span fields) captured at span-creation time.
struct Dimensions(BTreeMap<String, i128>);

impl Visit for Dimensions {
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().to_owned(), value as i128);
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().to_owned(), value as i128);
    }
    fn record_i128(&mut self, field: &Field, value: i128) {
        self.0.insert(field.name().to_owned(), value);
    }
    fn record_u128(&mut self, field: &Field, value: u128) {
        self.0.insert(field.name().to_owned(), value as i128);
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().to_owned(), value as i128);
    }
    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
}

/// A tracing `Layer` that emits `warp.profile.v1` JSON records on
/// span close. Thread-safe: wraps the writer in a `Mutex`.
pub struct JsonLayer<W: Write + Send + 'static> {
    writer: Mutex<W>,
}

impl<W: Write + Send + 'static> JsonLayer<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }
}

impl<S, W> Layer<S> for JsonLayer<W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: Write + Send + 'static,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut dims = Dimensions(BTreeMap::new());
        attrs.record(&mut dims);
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(dims);
        }
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let start = SpanStart {
            wall: Instant::now(),
            cpu_ns: timing::thread_cpu_ns(),
            rss_bytes: rss::peak_rss_bytes(),
            counters: counters::snapshot(),
        };
        span.extensions_mut().insert(start);
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let ext = span.extensions();
        let Some(start) = ext.get::<SpanStart>() else {
            return;
        };

        let wall_ns = start.wall.elapsed().as_nanos() as u64;
        let cpu_ns = match (timing::thread_cpu_ns(), start.cpu_ns) {
            (Some(end), Some(begin)) => Some(end.saturating_sub(begin)),
            _ => None,
        };
        let rss_delta = match (rss::peak_rss_bytes(), start.rss_bytes) {
            (Some(end), Some(begin)) => Some(end.saturating_sub(begin) as i64),
            _ => None,
        };
        let delta = counters::snapshot().delta(&start.counters);

        let dims_default = Dimensions(BTreeMap::new());
        let dims = ext.get::<Dimensions>().unwrap_or(&dims_default);

        let mut out = Vec::with_capacity(256);
        let _ = write!(out, "{{\"schema\":\"warp.profile.v1\",\"phase\":");
        write_json_string(&mut out, span.name());
        let _ = write!(out, ",\"wall_ns\":{wall_ns}");
        if let Some(c) = cpu_ns {
            let _ = write!(out, ",\"cpu_ns\":{c}");
        }
        if let Some(r) = rss_delta {
            let _ = write!(out, ",\"rss_delta_bytes\":{r}");
        }

        // counters
        let _ = write!(out, ",\"counters\":{{");
        let mut first = true;
        for (c, v) in delta.iter_nonzero() {
            if !first {
                let _ = write!(out, ",");
            }
            first = false;
            let _ = write!(out, "\"{}\":{}", c.name(), v);
        }
        let _ = write!(out, "}}");

        // dimensions
        let _ = write!(out, ",\"dimensions\":{{");
        let mut first = true;
        for (k, v) in &dims.0 {
            if !first {
                let _ = write!(out, ",");
            }
            first = false;
            write_json_string(&mut out, k);
            let _ = write!(out, ":{v}");
        }
        let _ = writeln!(out, "}}}}");

        if let Ok(mut w) = self.writer.lock() {
            let _ = w.write_all(&out);
        }
        // ignore counter on unused-import warning for Counter when delta is empty
        let _ = Counter::ALL.len();
    }
}

fn write_json_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for b in s.bytes() {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x00..=0x1F => {
                let _ = write!(out, "\\u{b:04x}");
            }
            _ => out.push(b),
        }
    }
    out.push(b'"');
}
