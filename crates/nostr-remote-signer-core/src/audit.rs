//! Per-signature audit: the contract.
//!
//! A record carries WHO asked, WHAT method, WHICH kind, and the DECISION — never the
//! content, never the tags. Nothing here can leak a message.

use core::fmt;

use nostr::key::PublicKey;

/// Seconds since the Unix epoch. One clock for every journal line, so records and gap
/// markers can be ordered against each other.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Why a request was refused. Closed set on purpose: an audit line is read by people and
/// scripts, and a free-form reason would drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// The NIP-46 method is not in the policy allowlist.
    MethodNotAllowed,
    /// `sign_event` for a kind the policy does not allow.
    KindNotAllowed,
    /// The caller, or the bunker as a whole, exceeded its rate.
    RateLimited,
    /// No valid agent credential.
    Unauthorized,
    /// The credential was revoked after the caller connected.
    Revoked,
}

impl DenyReason {
    /// Stable identifier written to the journal.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MethodNotAllowed => "method_not_allowed",
            Self::KindNotAllowed => "kind_not_allowed",
            Self::RateLimited => "rate_limited",
            Self::Unauthorized => "unauthorized",
            Self::Revoked => "revoked",
        }
    }
}

/// The outcome of one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Approved,
    Denied(DenyReason),
}

impl Decision {
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved)
    }
}

/// One line of the journal.
///
/// There is deliberately no field that could hold request content: the absence is
/// structural, not a convention someone could forget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// Unix seconds.
    pub at: u64,
    /// The custodied identity addressed.
    pub identity: PublicKey,
    /// The NIP-46 client key that sent the request.
    pub caller: PublicKey,
    /// The agent behind the caller, if any — even a revoked one.
    pub agent: Option<String>,
    /// NIP-46 method name, as on the wire: `sign_event`, `get_public_key`…
    pub method: String,
    /// Event kind, for `sign_event` only.
    pub kind: Option<u16>,
    pub decision: Decision,
}

impl AuditRecord {
    /// One JSON object, no trailing newline. Flat on purpose, so `jq` and `grep` work
    /// without knowing the schema.
    pub fn to_json_line(&self) -> String {
        let (decision, reason) = match self.decision {
            Decision::Approved => ("approved", None),
            Decision::Denied(r) => ("denied", Some(r.as_str())),
        };
        serde_json::json!({
            "at": self.at,
            "identity": self.identity.to_hex(),
            "caller": self.caller.to_hex(),
            "agent": self.agent,
            "method": self.method,
            "kind": self.kind,
            "decision": decision,
            "reason": reason,
        })
        .to_string()
    }
}

/// Where audit records go.
///
/// CONTRACT: `record` is called from `NostrConnectSignerActions::approve`, which is
/// synchronous. An implementation MUST NOT block and MUST NOT perform I/O. It returns
/// nothing because the caller could do nothing useful with an error mid-decision: a sink
/// that cannot keep up must account for what it lost itself.
pub trait AuditSink: fmt::Debug + Send + Sync {
    fn record(&self, record: AuditRecord);
}
