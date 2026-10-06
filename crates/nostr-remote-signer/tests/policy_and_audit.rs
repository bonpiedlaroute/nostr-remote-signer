//! C1 acceptance: "a refused signature, and the journal line that proves it" (plan §7).
//!
//! Drives the real decision point — `PolicyActions::approve`, the method `nostr-connect`
//! calls — through the real channel and writer thread, into a real file on disk.

use std::path::PathBuf;
use std::sync::Arc;

use nostr::prelude::*;
use nostr_connect::signer::NostrConnectSignerActions;
use nostr_remote_signer::actions::PolicyActions;
use nostr_remote_signer::audit_log::audit_channel;
use nostr_remote_signer::policy::Policy;
use nostr_remote_signer_core::{AuditRecord, AuditSink, Decision, unix_now};
use serde_json::Value;

const POLICY: &str = r#"{
    "allowed_methods": ["connect", "get_public_key", "sign_event", "ping"],
    "allowed_kinds": [9, 27235],
    "rate_limit": {
        "per_caller": { "burst": 3,   "per_second": 0.001 },
        "global":     { "burst": 100, "per_second": 0.001 }
    }
}"#;

fn policy(raw: &str) -> Arc<Policy> {
    Arc::new(Policy::from_json(raw).unwrap())
}

fn sign(kind: u16, content: &str) -> NostrConnectRequest {
    NostrConnectRequest::SignEvent(UnsignedEvent::new(
        Keys::generate().public_key(),
        Timestamp::now(),
        Kind::from(kind),
        [],
        content,
    ))
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
fn with_journal(
    test: &str,
    raw_policy: &str,
    body: impl FnOnce(&dyn NostrConnectSignerActions),
) -> (String, Vec<Value>) {
    let path = journal(test);
    let (sink, receiver) = audit_channel(64);
    let writer = receiver.spawn_writer(&path).unwrap();
    {
        let actions = PolicyActions::new(policy(raw_policy), sink);
        body(&actions);
        // `actions` dropped here: last sender gone, channel closed.
    }
    writer.join().unwrap().unwrap();
    read_lines(&path)
}

#[test]
fn a_refused_signature_leaves_the_journal_line_that_proves_it() {
    let caller = Keys::generate().public_key();

    let (raw, lines) = with_journal("refused", POLICY, |a| {
        assert!(!a.approve(&caller, &sign(1, "TOP SECRET payload")));
    });

    assert_eq!(lines.len(), 1, "{raw}");
    let l = &lines[0];
    assert_eq!(l["decision"], "denied");
    assert_eq!(l["reason"], "kind_not_allowed");
    assert_eq!(l["method"], "sign_event");
    assert_eq!(l["kind"], 1);
    assert_eq!(l["caller"], caller.to_hex());
    assert!(l["at"].as_u64().unwrap() > 0);

    // The journal says who, what and which kind — never what was in the event.
    assert!(
        !raw.contains("TOP SECRET"),
        "content leaked into the journal: {raw}"
    );
}

#[test]
fn approved_requests_are_journaled_too() {
    let caller = Keys::generate().public_key();

    let (_, lines) = with_journal("approved", POLICY, |a| {
        assert!(a.approve(&caller, &sign(9, "hello")));
        assert!(a.approve(&caller, &NostrConnectRequest::GetPublicKey));
    });

    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["decision"], "approved");
    assert_eq!(lines[0]["kind"], 9);
    assert!(lines[0]["reason"].is_null());
    assert_eq!(lines[1]["method"], "get_public_key");
    assert!(lines[1]["kind"].is_null());
}

#[test]
fn an_unlisted_method_is_refused_and_journaled() {
    let caller = Keys::generate().public_key();
    let decrypt_request = NostrConnectRequest::Nip44Decrypt {
        public_key: Keys::generate().public_key(),
        ciphertext: "opaque".into(),
    };

    let (_, lines) = with_journal("method", POLICY, |a| {
        assert!(!a.approve(&caller, &decrypt_request));
    });

    assert_eq!(lines[0]["reason"], "method_not_allowed");
    assert_eq!(lines[0]["method"], "nip44_decrypt");
}

#[test]
fn a_caller_over_its_rate_is_refused_and_journaled() {
    let caller = Keys::generate().public_key();

    let (_, lines) = with_journal("per-caller", POLICY, |a| {
        for _ in 0..3 {
            assert!(a.approve(&caller, &NostrConnectRequest::Ping));
        }
        assert!(!a.approve(&caller, &NostrConnectRequest::Ping));
    });

    assert_eq!(lines.len(), 4);
    assert_eq!(lines[3]["decision"], "denied");
    assert_eq!(lines[3]["reason"], "rate_limited");
}

#[test]
fn rotating_caller_keys_does_not_escape_the_global_limit() {
    // Each request from a brand-new NIP-46 key: the per-caller buckets never fill, only the
    // global one can stop this — which is exactly why it exists.
    let tight_global = POLICY.replace(r#""burst": 100"#, r#""burst": 2"#);

    let (_, lines) = with_journal("global", &tight_global, |a| {
        assert!(a.approve(&Keys::generate().public_key(), &NostrConnectRequest::Ping));
        assert!(a.approve(&Keys::generate().public_key(), &NostrConnectRequest::Ping));
        assert!(!a.approve(&Keys::generate().public_key(), &NostrConnectRequest::Ping));
    });

    assert_eq!(lines[2]["reason"], "rate_limited");
}

#[test]
fn a_saturated_journal_writes_a_gap_instead_of_losing_lines_silently() {
    let path = journal("gap");
    let (sink, receiver) = audit_channel(2);
    let caller = Keys::generate().public_key();
    let record = || AuditRecord {
        at: unix_now(),
        caller,
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
            let actions = PolicyActions::new(policy(POLICY), sink);
            actions.approve(&Keys::generate().public_key(), &NostrConnectRequest::Ping);
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
