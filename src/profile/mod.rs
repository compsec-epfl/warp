//! Profile instrumentation.
//!
//! The library always emits `tracing` spans at IOR boundaries; this
//! module installs a subscriber that renders those spans. Rendering is
//! off by default — the `profile` cargo feature is required to bring in
//! `tracing-subscriber` and `libc` (for `clock_gettime` / `getrusage`).
//!
//! Two sinks are provided:
//! * [`init()`] / [`init_fmt()`] — human-readable text on stderr.
//! * [`init_json(writer)`] — newline-delimited JSON records to any
//!   `io::Write` sink (stderr, a file, a pipe). Schema:
//!   `warp.profile.v1`. See [`layer`] for the field list.
//!
//! Each installs a global subscriber the first time it is called; later
//! calls are no-ops. Without the feature, every init function returns
//! `false` and records nothing.

pub mod counters;
pub mod rss;
pub mod timing;

#[cfg(feature = "profile")]
pub mod layer;

/// Install a human-readable stderr subscriber (mimics the old
/// `[PROFILE]` lines). No-op without the `profile` feature.
#[cfg(feature = "profile")]
pub fn init() -> bool {
    init_fmt()
}

#[cfg(not(feature = "profile"))]
pub fn init() -> bool {
    false
}

/// Human-readable fmt subscriber on stderr. Reads `RUST_LOG` to pick a
/// filter; defaults to `warp=info`.
#[cfg(feature = "profile")]
pub fn init_fmt() -> bool {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warp=info"));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            fmt::layer()
                .with_target(false)
                .with_span_events(fmt::format::FmtSpan::CLOSE)
                .with_writer(std::io::stderr),
        )
        .try_init()
        .is_ok()
}

#[cfg(not(feature = "profile"))]
pub fn init_fmt() -> bool {
    false
}

/// Install the JSON subscriber. One `warp.profile.v1` record per closed
/// span is written to `writer`. Reads `RUST_LOG` like [`init_fmt`].
#[cfg(feature = "profile")]
pub fn init_json<W>(writer: W) -> bool
where
    W: std::io::Write + Send + 'static,
{
    use tracing_subscriber::{prelude::*, EnvFilter};
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warp=info"));
    tracing_subscriber::registry()
        .with(env_filter)
        .with(layer::JsonLayer::new(writer))
        .try_init()
        .is_ok()
}

#[cfg(not(feature = "profile"))]
pub fn init_json<W>(_writer: W) -> bool
where
    W: std::io::Write + Send + 'static,
{
    false
}
