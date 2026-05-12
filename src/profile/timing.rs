//! Thread CPU time via `clock_gettime(CLOCK_THREAD_CPUTIME_ID)`. `None`
//! off Linux/macOS or without the `profile` feature.

#[cfg(feature = "profile")]
pub fn thread_cpu_ns() -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: timespec is POD; the kernel writes on success.
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
