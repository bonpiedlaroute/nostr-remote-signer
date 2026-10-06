//! What the bunker agrees to do, decided in memory.
//!
//! Default-deny: a method or a kind that the file does not name is refused. Loaded once at
//! startup; hot reload belongs to C2, together with revocation, which needs it.

use std::collections::HashSet;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result, bail};
use nostr::nips::nip46::{NostrConnectMethod, NostrConnectRequest};
use nostr_remote_signer_core::DenyReason;
use serde::Deserialize;

use crate::rate::RateConfig;

/// On-disk shape. `deny_unknown_fields` so a typo — `allowed_kind` — fails loudly instead
/// of silently producing a policy that refuses everything.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    allowed_methods: Vec<String>,
    allowed_kinds: Vec<u16>,
    rate_limit: RateLimitFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RateLimitFile {
    per_caller: RateConfig,
    global: RateConfig,
}

#[derive(Debug, Clone)]
pub struct Policy {
    allowed_methods: HashSet<NostrConnectMethod>,
    allowed_kinds: HashSet<u16>,
    pub per_caller: RateConfig,
    pub global: RateConfig,
}

impl Policy {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read policy at {}", path.display()))?;
        Self::from_json(&raw).with_context(|| format!("invalid policy at {}", path.display()))
    }

    pub fn from_json(raw: &str) -> Result<Self> {
        let file: PolicyFile = serde_json::from_str(raw)?;

        let mut allowed_methods = HashSet::new();
        for name in &file.allowed_methods {
            let method = NostrConnectMethod::from_str(name)
                .map_err(|_| anyhow::anyhow!("unknown NIP-46 method `{name}`"))?;
            allowed_methods.insert(method);
        }
        if !allowed_methods.contains(&NostrConnectMethod::Connect) {
            bail!("`connect` must be allowed: without it no bunker:// client can ever attach");
        }

        validate_rate("per_caller", file.rate_limit.per_caller)?;
        validate_rate("global", file.rate_limit.global)?;

        Ok(Self {
            allowed_methods,
            allowed_kinds: file.allowed_kinds.into_iter().collect(),
            per_caller: file.rate_limit.per_caller,
            global: file.rate_limit.global,
        })
    }

    /// Pure function of the request: no state, no clock, no I/O.
    pub fn evaluate(&self, req: &NostrConnectRequest) -> Result<(), DenyReason> {
        if !self.allowed_methods.contains(&req.method()) {
            return Err(DenyReason::MethodNotAllowed);
        }
        if let Some(kind) = request_kind(req)
            && !self.allowed_kinds.contains(&kind)
        {
            return Err(DenyReason::KindNotAllowed);
        }
        Ok(())
    }
}

/// NaN and infinity are both rejected: an infinite rate is a disabled limit, and NaN would
/// make every comparison in the token bucket false.
fn validate_rate(name: &str, rate: RateConfig) -> Result<()> {
    if rate.burst == 0 || !rate.per_second.is_finite() || rate.per_second <= 0.0 {
        bail!("rate_limit.{name}: burst must be >= 1 and per_second finite and > 0");
    }
    Ok(())
}

/// The event kind a request asks to sign, if any. Shared by the policy and the journal so
/// both always agree on what was asked.
pub fn request_kind(req: &NostrConnectRequest) -> Option<u16> {
    match req {
        NostrConnectRequest::SignEvent(unsigned) => Some(unsigned.kind.as_u16()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use nostr::prelude::*;

    use super::*;

    const POLICY: &str = r#"{
        "allowed_methods": ["connect", "get_public_key", "sign_event", "ping"],
        "allowed_kinds": [9, 27235],
        "rate_limit": {
            "per_caller": { "burst": 20, "per_second": 2.0 },
            "global":     { "burst": 100, "per_second": 10.0 }
        }
    }"#;

    fn sign(kind: u16) -> NostrConnectRequest {
        let author = Keys::generate().public_key();
        NostrConnectRequest::SignEvent(UnsignedEvent::new(
            author,
            Timestamp::now(),
            Kind::from(kind),
            [],
            "",
        ))
    }

    #[test]
    fn the_shipped_example_policy_is_valid() {
        // The file operators copy must never rot: if it stops parsing, this fails first.
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../policy.example.json");
        let p = Policy::load(path).unwrap();
        // And it must keep A3 working: kind 9 (Buzz message) and 27235 (NIP-98 auth).
        assert_eq!(p.evaluate(&sign(9)), Ok(()));
        assert_eq!(p.evaluate(&sign(27235)), Ok(()));
    }

    #[test]
    fn allows_a_listed_method() {
        let p = Policy::from_json(POLICY).unwrap();
        assert_eq!(p.evaluate(&NostrConnectRequest::Ping), Ok(()));
    }

    #[test]
    fn refuses_an_unlisted_method() {
        // nip44_decrypt is not listed: a compromised agent cannot use the bunker as a
        // decryption oracle for the custodied identity's direct messages.
        let p = Policy::from_json(POLICY).unwrap();
        let req = NostrConnectRequest::Nip44Decrypt {
            public_key: Keys::generate().public_key(),
            ciphertext: String::new(),
        };
        assert_eq!(p.evaluate(&req), Err(DenyReason::MethodNotAllowed));
    }

    #[test]
    fn allows_a_listed_kind() {
        let p = Policy::from_json(POLICY).unwrap();
        assert_eq!(p.evaluate(&sign(9)), Ok(()));
        assert_eq!(p.evaluate(&sign(27235)), Ok(()));
    }

    #[test]
    fn refuses_an_unlisted_kind() {
        let p = Policy::from_json(POLICY).unwrap();
        assert_eq!(p.evaluate(&sign(1)), Err(DenyReason::KindNotAllowed));
    }

    #[test]
    fn rejects_an_unknown_method_name() {
        let bad = POLICY.replace("\"ping\"", "\"pong\"");
        assert!(Policy::from_json(&bad).is_err());
    }

    #[test]
    fn rejects_a_misspelt_field() {
        let bad = POLICY.replace("allowed_kinds", "allowed_kind");
        assert!(Policy::from_json(&bad).is_err());
    }

    #[test]
    fn rejects_a_policy_without_connect() {
        let bad = POLICY.replace("\"connect\", ", "");
        assert!(Policy::from_json(&bad).is_err());
    }

    #[test]
    fn rejects_non_finite_rates() {
        // JSON cannot carry NaN or infinity, so test the validation itself: a future config
        // source (TOML, environment) could reach it with either.
        for per_second in [f64::INFINITY, f64::NAN, -1.0] {
            let rate = RateConfig {
                burst: 1,
                per_second,
            };
            assert!(
                validate_rate("test", rate).is_err(),
                "{per_second} accepted"
            );
        }
        assert!(
            validate_rate(
                "test",
                RateConfig {
                    burst: 1,
                    per_second: 0.5
                }
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_a_zero_rate() {
        let bad = POLICY.replace("\"burst\": 20", "\"burst\": 0");
        assert!(Policy::from_json(&bad).is_err());
    }
}
