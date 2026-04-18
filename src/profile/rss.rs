//! Peak resident-set-size accounting via `getrusage(RUSAGE_SELF)`.
//!
//! Linux reports `ru_maxrss` in kilobytes; macOS reports it in bytes. We
//! normalise to bytes. The kernel tracks the peak RSS for the process (not
//! the current thread), so this value is monotonic — useful only via
//! deltas across intervals.
//!
//! Returns `None` if the syscall fails.
//!
//! Without the `profile` feature this module compiles to stubs that always
//! return `None`.

#[cfg(feature = "profile")]
pub fn peak_rss_bytes() -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // SAFETY: rusage is a POD; the kernel writes the full struct on success.
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
        if rc != 0 {
            return None;
        }
        let maxrss = ru.ru_maxrss as u64;
        #[cfg(target_os = "macos")]
        {
            Some(maxrss) // bytes
        }
        #[cfg(target_os = "linux")]
        {
            Some(maxrss.saturating_mul(1024)) // kilobytes -> bytes
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(not(feature = "profile"))]
pub fn peak_rss_bytes() -> Option<u64> {
    None
}
