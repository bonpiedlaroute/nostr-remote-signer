//! Custody, policy and audit for a NIP-46 remote signer.
//!
//! AGPL-3.0: the daemon side. The reusable traits live in `nostr-remote-signer-core`,
//! under Apache-2.0.

pub mod access;
pub mod actions;
pub mod audit_log;
pub mod hardening;
pub mod policy;
pub mod rate;
pub mod relay;
pub mod sealed;
pub mod unwrap;

/// `var` if set, `default` otherwise.
pub fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}
