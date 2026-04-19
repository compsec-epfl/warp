//! Per-phase wall-time collector for the `profile` feature.
//!
//! Consumer pattern:
//! ```ignore
//! warp::profile::reset();
//! warp.prove(...)?;
//! for (name, dur) in warp::profile::drain() { ... }
//! ```
//!
//! With the feature off, [`phase!`] is a zero-cost block and `reset` /
//! `drain` don't exist — callers should also `#[cfg(feature = "profile")]`.

#[cfg(feature = "profile")]
use std::sync::Mutex;
#[cfg(feature = "profile")]
use std::time::Duration;

#[cfg(feature = "profile")]
static TIMINGS: Mutex<Vec<(&'static str, Duration)>> = Mutex::new(Vec::new());

#[cfg(feature = "profile")]
pub fn record(name: &'static str, dur: Duration) {
    TIMINGS.lock().unwrap().push((name, dur));
}

#[cfg(feature = "profile")]
pub fn reset() {
    TIMINGS.lock().unwrap().clear();
}

#[cfg(feature = "profile")]
pub fn drain() -> Vec<(&'static str, Duration)> {
    std::mem::take(&mut *TIMINGS.lock().unwrap())
}

/// Wrap an expression block to record its wall-time under `name`. No-op
/// when `profile` is off (the block runs identically but the timing scaffold
/// is elided by the compiler).
#[macro_export]
macro_rules! phase {
    ($name:expr, $body:block) => {{
        #[cfg(feature = "profile")]
        let __phase_t0 = ::std::time::Instant::now();
        let __phase_res = $body;
        #[cfg(feature = "profile")]
        $crate::profile::record($name, __phase_t0.elapsed());
        __phase_res
    }};
}
