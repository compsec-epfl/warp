//! Opt-in profile instrumentation. The `profile` feature pulls in
//! `tracing-subscriber` and `libc` and lets `init_fmt`/`init_json` render
//! the always-emitted spans. Without the feature, init functions no-op.

pub mod counters;
pub mod rss;
pub mod timing;

#[cfg(feature = "profile")]
pub mod layer;

#[cfg(feature = "profile")]
pub fn init() -> bool {
    init_fmt()
}

#[cfg(not(feature = "profile"))]
pub fn init() -> bool {
    false
}

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
