//! Process-level hardening, applied once at startup.
//!
//! This module protects it in memory: no swap, no core
//! dumps. Both are best-effort by nature — the daemon reports what it actually obtained
//! rather than assuming.

use std::io;

/// What the process actually obtained. Logged at startup and asserted in tests, so an
/// operator never has to guess which guarantees are in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hardening {
    /// Core dumps are disabled.
    pub core_dumps_disabled: bool,
    /// The whole address space is locked against swap.
    pub memory_locked: bool,
}

/// Disable core dumps by setting both RLIMIT_CORE limits to zero.
///
/// Lowering the HARD limit too is what makes this irreversible for the lifetime of the
/// process: a soft limit alone could be raised again by anything running in-process.
pub fn disable_core_dumps() -> io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is fully initialised and outlives the call; setrlimit reads it and
    // does not retain the pointer.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Current soft limit on core dump size. Exists so tests can assert the effect rather
/// than trust the call's return value.
pub fn core_dump_limit() -> io::Result<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, writable rlimit for the duration of the call.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut lim) };
    if rc == 0 {
        Ok(lim.rlim_cur)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Lock the entire address space against swap, current and future pages.
///
/// Linux only. macOS declares `mlockall` but the kernel returns ENOSYS — measured on
/// Darwin 25.6, 2026-10-02. Per-page `mlock` does work there, but it cannot reach the
/// long-lived key held inside `nostr-connect`, whose allocation we do not control
#[cfg(target_os = "linux")]
pub fn lock_all_memory() -> io::Result<()> {
    // SAFETY: mlockall takes only flags and touches no memory we own.
    let rc = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
pub fn lock_all_memory() -> io::Result<()> {
    Err(io::Error::from_raw_os_error(libc::ENOSYS))
}

/// Apply every hardening step, and report what was obtained.
///
/// Never fails the process: a developer laptop that cannot lock memory must still be able
/// to run the daemon. The cost of that leniency is paid by logging loudly.
pub fn harden() -> Hardening {
    let core_dumps_disabled = match disable_core_dumps() {
        Ok(()) => true,
        Err(e) => {
            tracing::error!(error = %e, "could not disable core dumps");
            false
        }
    };

    let memory_locked = match lock_all_memory() {
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "memory is NOT locked: the key may reach swap. Expected on macOS; \
                 on Linux, check RLIMIT_MEMLOCK"
            );
            false
        }
    };

    tracing::info!(
        core_dumps_disabled,
        memory_locked,
        "process hardening applied"
    );

    Hardening {
        core_dumps_disabled,
        memory_locked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabling_core_dumps_is_observable() {
        // Assert the effect, not the return code: a syscall that claims success but
        // leaves the limit untouched would be worse than one that fails loudly.
        disable_core_dumps().expect("setrlimit(RLIMIT_CORE) must succeed");
        assert_eq!(core_dump_limit().unwrap(), 0);
    }

    #[test]
    fn harden_reports_core_dumps_and_never_panics() {
        let h = harden();
        assert!(h.core_dumps_disabled);
        // `memory_locked` is platform-dependent on purpose: false on macOS, true on
        // Linux when RLIMIT_MEMLOCK allows it. Asserting either way would make this test
        // lie on one of the two.
    }

    /// On Linux the lock is observable in /proc; macOS offers no equivalent.
    #[cfg(target_os = "linux")]
    #[test]
    fn locked_memory_is_visible_in_proc() {
        if lock_all_memory().is_err() {
            eprintln!("skipping: RLIMIT_MEMLOCK too low in this environment");
            return;
        }
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let vmlck: u64 = status
            .lines()
            .find(|l| l.starts_with("VmLck:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|v| v.parse().ok())
            .expect("VmLck missing from /proc/self/status");
        assert!(vmlck > 0, "mlockall returned success but VmLck is 0");
    }
}
