//! Process peak RSS via `getrusage(RUSAGE_SELF)`. `ru_maxrss` is bytes on
//! macOS, kilobytes on Linux; we return bytes. Monotonic — use deltas.

#[cfg(feature = "profile")]
pub fn peak_rss_bytes() -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        // SAFETY: rusage is POD; kernel writes on success.
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
        if rc != 0 {
            return None;
        }
        let maxrss = ru.ru_maxrss as u64;
        #[cfg(target_os = "macos")]
        {
            Some(maxrss)
        }
        #[cfg(target_os = "linux")]
        {
            Some(maxrss.saturating_mul(1024))
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
