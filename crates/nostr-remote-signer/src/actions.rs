//! The decision point: credentials, rate limits, policy and journal, behind
//! `NostrConnectSignerActions`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use nostr::key::PublicKey;
use nostr::nips::nip46::NostrConnectRequest;
use nostr_connect::signer::NostrConnectSignerActions;
use nostr_remote_signer_core::{AuditRecord, AuditSink, Decision, DenyReason, unix_now};
use tokio::sync::watch;

use crate::access::{Agents, token_hash};
use crate::policy::{Policy, request_kind};
use crate::rate::RateLimiter;

/// State shared by every identity.
#[derive(Debug)]
pub struct Gate<S> {
    policy: Policy,
    per_caller: RateLimiter<PublicKey>,
    /// One bucket for the whole bunker. Per-caller limits alone are defeated by a client
    /// that generates a fresh NIP-46 key per request; this one is not.
    global: RateLimiter<()>,
    agents: watch::Receiver<Arc<Agents>>,
    audit: S,
}

impl<S> Gate<S> {
    pub fn new(policy: Policy, agents: watch::Receiver<Arc<Agents>>, audit: S) -> Self {
        Self {
            per_caller: RateLimiter::new(policy.per_caller),
            global: RateLimiter::new(policy.global),
            policy,
            agents,
            audit,
        }
    }
}

#[derive(Debug, Clone)]
struct Session {
    token_hash: String,
    /// Names the agent in the journal even after revocation.
    agent: String,
}

/// One per identity.
#[derive(Debug)]
pub struct PolicyActions<S> {
    gate: Arc<Gate<S>>,
    identity: PublicKey,
    sessions: Mutex<HashMap<PublicKey, Session>>,
}

impl<S: AuditSink> PolicyActions<S> {
    pub fn new(gate: Arc<Gate<S>>, identity: PublicKey) -> Self {
        Self {
            gate,
            identity,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Also binds the caller on an approved `connect`.
    pub fn decide(
        &self,
        caller: &PublicKey,
        req: &NostrConnectRequest,
    ) -> (Option<String>, Decision) {
        // Clone, so the watch lock is not held.
        let agents = Arc::clone(&self.gate.agents.borrow());
        let mut sessions = self.sessions.lock().unwrap_or_else(|p| p.into_inner());

        let auth = self.authenticate(&agents, sessions.get(caller), req);
        let agent = match &auth {
            Ok(session) => Some(session.agent.clone()),
            Err((agent, _)) => agent.clone(),
        };

        // Rate first: every request costs a token, allowed or not. Otherwise the policy
        // could be probed for free, at unbounded speed.
        if !self.gate.per_caller.check(caller) || !self.gate.global.check(&()) {
            return (agent, Decision::Denied(DenyReason::RateLimited));
        }
        let session = match auth {
            Ok(session) => session,
            Err((_, reason)) => return (agent, Decision::Denied(reason)),
        };
        if let Err(reason) = self.gate.policy.evaluate(req) {
            return (agent, Decision::Denied(reason));
        }

        if matches!(req, NostrConnectRequest::Connect { .. }) {
            // Latest connect wins: at most one session per agent.
            sessions.retain(|_, s| s.token_hash != session.token_hash);
            sessions.insert(*caller, session);
        }
        (agent, Decision::Approved)
    }

    fn authenticate(
        &self,
        agents: &Agents,
        session: Option<&Session>,
        req: &NostrConnectRequest,
    ) -> Result<Session, (Option<String>, DenyReason)> {
        match req {
            NostrConnectRequest::Connect { secret, .. } => {
                let Some(hash) = secret.as_deref().map(token_hash) else {
                    return Err((None, DenyReason::Unauthorized));
                };
                match agents.get(&hash) {
                    Some(a) if a.identity == self.identity => Ok(Session {
                        token_hash: hash,
                        agent: a.name.clone(),
                    }),
                    Some(a) => Err((Some(a.name.clone()), DenyReason::Unauthorized)),
                    None => Err((None, DenyReason::Unauthorized)),
                }
            }
            // Re-checked against the current list: this is what revokes.
            _ => match session {
                None => Err((None, DenyReason::Unauthorized)),
                Some(s) => match agents.get(&s.token_hash) {
                    Some(a) if a.identity == self.identity => Ok(s.clone()),
                    _ => Err((Some(s.agent.clone()), DenyReason::Revoked)),
                },
            },
        }
    }
}

impl<S: AuditSink> NostrConnectSignerActions for PolicyActions<S> {
    /// Synchronous by contract: in-memory decision, non-blocking journal, no I/O.
    fn approve(&self, caller: &PublicKey, req: &NostrConnectRequest) -> bool {
        let (agent, decision) = self.decide(caller, req);
        let kind = request_kind(req);

        tracing::info!(
            identity = %self.identity,
            caller = %caller,
            agent = agent.as_deref().unwrap_or("-"),
            method = %req.method(),
            kind = ?kind,
            approved = decision.is_approved(),
            "request decided"
        );

        self.gate.audit.record(AuditRecord {
            at: unix_now(),
            identity: self.identity,
            caller: *caller,
            agent,
            method: req.method().to_string(),
            kind,
            decision,
        });
        decision.is_approved()
    }
}
