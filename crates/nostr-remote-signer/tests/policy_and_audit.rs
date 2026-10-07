//! C1 acceptance: "a refused signature, and the journal line that proves it".
//! C2 acceptance: "you revoke, and the agent can no longer act" (plan §7).
//!
//! Drives the real decision point — `PolicyActions::approve`, the method `nostr-connect`
//! calls — through the real channel and writer thread, into a real file on disk.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use nostr::prelude::*;
use nostr_connect::signer::NostrConnectSignerActions;
use nostr_remote_signer::access::{Agents, token_hash};
use nostr_remote_signer::actions::{Gate, PolicyActions};
use nostr_remote_signer::audit_log::{ChannelAuditSink, audit_channel};
use nostr_remote_signer::policy::Policy;
use nostr_remote_signer_core::{AuditRecord, AuditSink, Decision, unix_now};
use serde_json::Value;
use tokio::sync::watch;

const POLICY: &str = r#"{
    "allowed_methods": ["connect", "get_public_key", "sign_event", "ping"],
    "allowed_kinds": [9, 27235],
    "rate_limit": {
        "per_caller": { "burst": 3,   "per_second": 0.001 },
        "global":     { "burst": 100, "per_second": 0.001 }
    }
}"#;

/// `bot` acts for alice, `ops` for bob.
const BOT_TOKEN: &str = "token-of-bot";
const OPS_TOKEN: &str = "token-of-ops";

fn sign(kind: u16, content: &str) -> NostrConnectRequest {
    NostrConnectRequest::SignEvent(UnsignedEvent::new(
        Keys::generate().public_key(),
        Timestamp::now(),
        Kind::from(kind),
        [],
        content,
    ))
}

fn connect(secret: Option<&str>) -> NostrConnectRequest {
    NostrConnectRequest::Connect {
        remote_signer_public_key: Keys::generate().public_key(),
        secret: secret.map(String::from),
    }
}

struct Bunker {
    alice: PolicyActions<ChannelAuditSink>,
    bob: PolicyActions<ChannelAuditSink>,
    alice_key: PublicKey,
    bob_key: PublicKey,
    agents: watch::Sender<Arc<Agents>>,
}

impl Bunker {
    fn new(raw_policy: &str, sink: ChannelAuditSink) -> Self {
        let alice_key = Keys::generate().public_key();
        let bob_key = Keys::generate().public_key();
        let (agents, rx) = watch::channel(Arc::new(Agents::default()));
        let gate = Arc::new(Gate::new(Policy::from_json(raw_policy).unwrap(), rx, sink));
        let bunker = Self {
            alice: PolicyActions::new(Arc::clone(&gate), alice_key),
            bob: PolicyActions::new(gate, bob_key),
            alice_key,
            bob_key,
            agents,
        };
        bunker.set_agents(&[("bot", alice_key, BOT_TOKEN), ("ops", bob_key, OPS_TOKEN)]);
        bunker
    }

    /// What SIGHUP does.
    fn set_agents(&self, entries: &[(&str, PublicKey, &str)]) {
        let agents: Vec<_> = entries
            .iter()
            .map(|(name, identity, token)| {
                serde_json::json!({
                    "name": name,
                    "identity": identity.to_hex(),
                    "token_sha256": token_hash(token),
                })
            })
            .collect();
        let raw = serde_json::json!({ "agents": agents }).to_string();
        let served = HashSet::from([self.alice_key, self.bob_key]);
        self.agents
            .send_replace(Arc::new(Agents::from_json(&raw, &served).unwrap()));
    }

    /// A fresh transport key, connected to alice as `bot`.
    fn connected(&self) -> PublicKey {
        let caller = Keys::generate().public_key();
        assert!(self.alice.approve(&caller, &connect(Some(BOT_TOKEN))));
        caller
    }
}

/// A journal file unique to one test: tests share a process, so the pid is not enough.
fn journal(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("c1-{test}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("audit.log");
    let _ = std::fs::remove_file(&path);
    path
}

fn read_lines(path: &PathBuf) -> (String, Vec<Value>) {
    let raw = std::fs::read_to_string(path).unwrap();
    let lines = raw
        .lines()
        .map(|l| serde_json::from_str(l).expect("every journal line is JSON"))
        .collect();
    (raw, lines)
}

/// Run `body` against a live writer, then close the channel and wait for the disk.
fn with_journal<T>(
    test: &str,
    raw_policy: &str,
    body: impl FnOnce(&Bunker) -> T,
) -> (T, String, Vec<Value>) {
    let path = journal(test);
    let (sink, receiver) = audit_channel(64);
    let writer = receiver.spawn_writer(&path).unwrap();
    let out = {
        let bunker = Bunker::new(raw_policy, sink);
        body(&bunker)
        // `bunker` dropped here: last sender gone, channel closed.
    };
    writer.join().unwrap().unwrap();
    let (raw, lines) = read_lines(&path);
    (out, raw, lines)
}

// ---- C1: policy, rate, journal ---------------------------------------------------------

#[test]
fn a_refused_signature_leaves_the_journal_line_that_proves_it() {
    let ((caller, alice), raw, lines) = with_journal("refused", POLICY, |b| {
        let caller = b.connected();
        assert!(!b.alice.approve(&caller, &sign(1, "TOP SECRET payload")));
        (caller, b.alice_key)
    });

    assert_eq!(lines.len(), 2, "{raw}");
    let l = &lines[1];
    assert_eq!(l["decision"], "denied");
    assert_eq!(l["reason"], "kind_not_allowed");
    assert_eq!(l["method"], "sign_event");
    assert_eq!(l["kind"], 1);
    assert_eq!(l["caller"], caller.to_hex());
    assert_eq!(l["identity"], alice.to_hex());
    assert_eq!(l["agent"], "bot");
    assert!(l["at"].as_u64().unwrap() > 0);

    // The journal says who, what and which kind — never what was in the event.
    assert!(
        !raw.contains("TOP SECRET"),
        "content leaked into the journal: {raw}"
    );
}

#[test]
fn approved_requests_are_journaled_too() {
    let (_, _, lines) = with_journal("approved", POLICY, |b| {
        let caller = b.connected();
        assert!(b.alice.approve(&caller, &sign(9, "hello")));
        assert!(b.alice.approve(&caller, &NostrConnectRequest::GetPublicKey));
    });

    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0]["method"], "connect");
    assert_eq!(lines[0]["decision"], "approved");
    assert_eq!(lines[1]["decision"], "approved");
    assert_eq!(lines[1]["kind"], 9);
    assert_eq!(lines[1]["agent"], "bot");
    assert!(lines[1]["reason"].is_null());
    assert_eq!(lines[2]["method"], "get_public_key");
    assert!(lines[2]["kind"].is_null());
}

#[test]
fn an_unlisted_method_is_refused_and_journaled() {
    let decrypt_request = NostrConnectRequest::Nip44Decrypt {
        public_key: Keys::generate().public_key(),
        ciphertext: "opaque".into(),
    };

    let (_, _, lines) = with_journal("method", POLICY, |b| {
        let caller = b.connected();
        assert!(!b.alice.approve(&caller, &decrypt_request));
    });

    assert_eq!(lines[1]["reason"], "method_not_allowed");
    assert_eq!(lines[1]["method"], "nip44_decrypt");
}

#[test]
fn a_caller_over_its_rate_is_refused_and_journaled() {
    let (_, _, lines) = with_journal("per-caller", POLICY, |b| {
        // Burst of 3, connect included.
        let caller = b.connected();
        for _ in 0..2 {
            assert!(b.alice.approve(&caller, &NostrConnectRequest::Ping));
        }
        assert!(!b.alice.approve(&caller, &NostrConnectRequest::Ping));
    });

    assert_eq!(lines.len(), 4);
    assert_eq!(lines[3]["decision"], "denied");
    assert_eq!(lines[3]["reason"], "rate_limited");
    assert_eq!(lines[3]["agent"], "bot");
}

#[test]
fn rotating_caller_keys_does_not_escape_the_global_limit() {
    // Each request from a brand-new NIP-46 key: the per-caller buckets never fill, only the
    // global one can stop this — which is exactly why it exists.
    let tight_global = POLICY.replace(r#""burst": 100"#, r#""burst": 2"#);

    let (_, _, lines) = with_journal("global", &tight_global, |b| {
        for _ in 0..3 {
            let stranger = Keys::generate().public_key();
            assert!(!b.alice.approve(&stranger, &NostrConnectRequest::Ping));
        }
    });

    assert_eq!(lines[1]["reason"], "unauthorized");
    assert_eq!(lines[2]["reason"], "rate_limited");
}

#[test]
fn a_saturated_journal_writes_a_gap_instead_of_losing_lines_silently() {
    let path = journal("gap");
    let (sink, receiver) = audit_channel(2);
    let key = Keys::generate().public_key();
    let record = || AuditRecord {
        at: unix_now(),
        identity: key,
        caller: key,
        agent: None,
        method: "ping".into(),
        kind: None,
        decision: Decision::Approved,
    };

    // Writer not started yet: two records fit, three do not.
    for _ in 0..5 {
        sink.record(record());
    }
    let writer = receiver.spawn_writer(&path).unwrap();
    drop(sink);
    writer.join().unwrap().unwrap();

    let (raw, lines) = read_lines(&path);
    assert_eq!(lines.len(), 3, "{raw}");
    assert_eq!(lines[0]["method"], "ping");
    assert_eq!(lines[1]["method"], "ping");
    assert_eq!(lines[2]["event"], "audit_gap");
    assert_eq!(lines[2]["lost"], 3);
}

#[test]
fn the_journal_is_append_only_across_restarts() {
    let path = journal("append");
    for _ in 0..2 {
        let (sink, receiver) = audit_channel(8);
        let writer = receiver.spawn_writer(&path).unwrap();
        {
            let bunker = Bunker::new(POLICY, sink);
            bunker
                .alice
                .approve(&Keys::generate().public_key(), &NostrConnectRequest::Ping);
        }
        writer.join().unwrap().unwrap();
    }
    // A restart must add to the journal, never truncate it.
    assert_eq!(read_lines(&path).1.len(), 2);
}

#[cfg(unix)]
#[test]
fn the_journal_is_readable_by_its_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let path = journal("mode");
    let (sink, receiver) = audit_channel(1);
    let writer = receiver.spawn_writer(&path).unwrap();
    drop(sink);
    writer.join().unwrap().unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

// ---- C2: credentials, identities, revocation -------------------------------------------

#[test]
fn a_caller_that_never_connected_is_refused() {
    let (_, _, lines) = with_journal("no-connect", POLICY, |b| {
        let stranger = Keys::generate().public_key();
        assert!(!b.alice.approve(&stranger, &sign(9, "hello")));
    });

    assert_eq!(lines[0]["reason"], "unauthorized");
    assert!(lines[0]["agent"].is_null());
}

#[test]
fn a_connect_without_a_valid_secret_binds_nothing() {
    let (_, _, lines) = with_journal("bad-secret", POLICY, |b| {
        let caller = Keys::generate().public_key();
        assert!(!b.alice.approve(&caller, &connect(Some("guessed"))));
        assert!(!b.alice.approve(&caller, &connect(None)));
        assert!(!b.alice.approve(&caller, &sign(9, "hello")));
    });

    for line in &lines {
        assert_eq!(line["reason"], "unauthorized");
    }
}

#[test]
fn a_revoked_agent_is_refused_on_its_very_next_request() {
    let (_, _, lines) = with_journal("revoked", POLICY, |b| {
        let bot = b.connected();
        let ops = Keys::generate().public_key();
        assert!(b.bob.approve(&ops, &connect(Some(OPS_TOKEN))));
        assert!(b.alice.approve(&bot, &sign(9, "before")));

        b.set_agents(&[("ops", b.bob_key, OPS_TOKEN)]);

        assert!(!b.alice.approve(&bot, &sign(9, "after")));
        let restarted = Keys::generate().public_key();
        assert!(!b.alice.approve(&restarted, &connect(Some(BOT_TOKEN))));
        assert!(b.bob.approve(&ops, &sign(9, "still here")));
    });

    assert_eq!(lines[3]["decision"], "denied");
    assert_eq!(lines[3]["reason"], "revoked");
    assert_eq!(lines[3]["agent"], "bot");
    assert_eq!(lines[4]["reason"], "unauthorized");
    assert_eq!(lines[5]["decision"], "approved");
    assert_eq!(lines[5]["agent"], "ops");
}

#[test]
fn rotating_a_token_revokes_the_old_one() {
    let (_, _, lines) = with_journal("rotate", POLICY, |b| {
        let old = b.connected();
        b.set_agents(&[("bot", b.alice_key, "fresh-token")]);

        assert!(!b.alice.approve(&old, &sign(9, "old session")));
        let new = Keys::generate().public_key();
        assert!(b.alice.approve(&new, &connect(Some("fresh-token"))));
        assert!(b.alice.approve(&new, &sign(9, "new session")));
    });

    assert_eq!(lines[1]["reason"], "revoked");
    assert_eq!(lines[3]["decision"], "approved");
}

#[test]
fn an_agent_cannot_act_for_another_identity() {
    let (_, _, lines) = with_journal("identity", POLICY, |b| {
        let caller = Keys::generate().public_key();
        assert!(!b.bob.approve(&caller, &connect(Some(BOT_TOKEN))));
        assert!(b.alice.approve(&caller, &connect(Some(BOT_TOKEN))));
        assert!(!b.bob.approve(&caller, &sign(9, "hello")));
    });

    assert_eq!(lines[0]["reason"], "unauthorized");
    assert_eq!(lines[0]["agent"], "bot");
    assert_eq!(lines[2]["reason"], "unauthorized");
}

#[test]
fn a_new_connect_replaces_the_previous_transport_key() {
    let (_, _, lines) = with_journal("replace", POLICY, |b| {
        let first = b.connected();
        let second = b.connected();
        assert!(!b.alice.approve(&first, &sign(9, "stale")));
        assert!(b.alice.approve(&second, &sign(9, "live")));
    });

    assert_eq!(lines[2]["reason"], "unauthorized");
    assert_eq!(lines[3]["decision"], "approved");
}
