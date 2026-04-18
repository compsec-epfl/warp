//! CPU-time accounting for the current thread.
//!
//! Wall time is available from `std::time::Instant`. CPU time is not — we
//! need `clock_gettime(CLOCK_THREAD_CPUTIME_ID)` (Linux / macOS Monterey+)
//! or `CLOCK_PROCESS_CPUTIME_ID` (older macOS) or `GetThreadTimes`
//! (Windows; not supported here).
//!
//! Returns `None` if the platform clock isn't available.
//!
//! Without the `profile` feature this module compiles to stubs that always
//! return `None`.

#[cfg(feature = "profile")]
pub fn thread_cpu_ns() -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: timespec is a POD; the kernel writes to it on success.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
        if rc == 0 {
            Some((ts.tv_sec as u64).saturating_mul(1_000_000_000) + (ts.tv_nsec as u64))
        } else {
            None
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(not(feature = "profile"))]
pub fn thread_cpu_ns() -> Option<u64> {
    None
}
