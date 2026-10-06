//! The decision point: policy, rate limits and journal, behind `NostrConnectSignerActions`.

use std::sync::Arc;

use nostr::key::PublicKey;
use nostr::nips::nip46::NostrConnectRequest;
use nostr_connect::signer::NostrConnectSignerActions;
use nostr_remote_signer_core::{AuditRecord, AuditSink, Decision, DenyReason, unix_now};

use crate::policy::{Policy, request_kind};
use crate::rate::RateLimiter;

#[derive(Debug)]
pub struct PolicyActions<S> {
    policy: Arc<Policy>,
    per_caller: RateLimiter<PublicKey>,
    /// One bucket for the whole bunker. Per-caller limits alone are defeated by a client
    /// that generates a fresh NIP-46 key per request; this one is not.
    global: RateLimiter<()>,
    audit: S,
}

impl<S: AuditSink> PolicyActions<S> {
    pub fn new(policy: Arc<Policy>, audit: S) -> Self {
        Self {
            per_caller: RateLimiter::new(policy.per_caller),
            global: RateLimiter::new(policy.global),
            policy,
            audit,
        }
    }

    /// Decide, without side effects other than spending rate-limit tokens.
    pub fn decide(&self, caller: &PublicKey, req: &NostrConnectRequest) -> Decision {
        // Rate first: every request costs a token, allowed or not. Otherwise the policy
        // could be probed for free, at unbounded speed.
        if !self.per_caller.check(caller) || !self.global.check(&()) {
            return Decision::Denied(DenyReason::RateLimited);
        }
        match self.policy.evaluate(req) {
            Ok(()) => Decision::Approved,
            Err(reason) => Decision::Denied(reason),
        }
    }
}

impl<S: AuditSink> NostrConnectSignerActions for PolicyActions<S> {
    /// Synchronous by contract: in-memory decision, non-blocking journal, no I/O.
    fn approve(&self, caller: &PublicKey, req: &NostrConnectRequest) -> bool {
        let decision = self.decide(caller, req);
        let kind = request_kind(req);

        self.audit.record(AuditRecord {
            at: unix_now(),
            caller: *caller,
            method: req.method().to_string(),
            kind,
            decision,
        });

        tracing::info!(
            caller = %caller,
            method = %req.method(),
            kind = ?kind,
            approved = decision.is_approved(),
            "request decided"
        );
        decision.is_approved()
    }
}
