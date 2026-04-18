//! Profile instrumentation helpers.
//!
//! Spans are always emitted by the phase modules (via the `tracing` crate,
//! which is zero-cost without a subscriber). Installing a subscriber that
//! renders those spans is gated on the `profile` feature so release builds
//! do not pull in `tracing-subscriber`.
//!
//! Plan O replaces the human-format subscriber below with JSON output plus
//! op-counter macros (`field_muls`, `merkle_hashes`, …) for ingestion by
//! Plan B's regression detector.

/// Install a human-readable `tracing-subscriber` on stderr that mimics the
/// old `[PROFILE]` lines. Feature-gated: a no-op when `profile` is off.
///
/// Safe to call multiple times; only the first call installs the global
/// subscriber. Returns `true` if this call performed the install.
#[cfg(feature = "profile")]
pub fn init() -> bool {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    // The default filter shows every span at INFO+; override via RUST_LOG.
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

/// No-op when the `profile` feature is off.
#[cfg(not(feature = "profile"))]
pub fn init() -> bool {
    false
}
