//! A NIP-46 bunker with envelope-encrypted key custody, serving several identities.
//!
//! Every decision leaves one line in an append-only journal. Agents are revoked at
//! runtime: edit the agents file, then SIGHUP.

use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use nostr_connect::prelude::*;
use nostr_remote_signer::access::{self, Agents};
use nostr_remote_signer::actions::{Gate, PolicyActions};
use nostr_remote_signer::audit_log::audit_channel;
use nostr_remote_signer::hardening;
use nostr_remote_signer::policy::Policy;
use nostr_remote_signer::sealed::SealedKey;
use nostr_remote_signer::unwrap::passphrase::PassphraseUnwrapper;
use nostr_remote_signer_core::KeyUnwrapper;
use serde::Deserialize;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::task::JoinSet;

/// Bunker transport relay.
///
/// Must be a third-party relay WITHOUT authentication, accepting ephemeral kind 24133.
/// Public relays are a moving target: measure the WebSocket UPGRADE, not an HTTPS GET.
/// 2026-09-15: nos.lol and nostr.mom answer 101; relay.damus.io answers 503;
/// relay.nsec.app is down.
const RELAY: &str = "wss://nos.lol";

/// Pending journal records before the writer is considered behind. Losses beyond that are
/// counted and written as an `audit_gap` line, never silently dropped.
const AUDIT_QUEUE: usize = 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityFiles {
    /// Transport key, the one in the bunker:// URI.
    signer: String,
    /// Custodied key, the one that signs.
    user: String,
}

fn env_or(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}

async fn load_sealed(path: &str, unwrapper: &dyn KeyUnwrapper) -> Result<Keys> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read sealed key at {path}"))?;
    let sealed: SealedKey =
        serde_json::from_str(&raw).with_context(|| format!("{path} is not a valid sealed key"))?;

    tracing::info!(kek = %sealed.kek, path = %path, "opening sealed key");
    Ok(Keys::new(sealed.open(unwrapper).await?))
}

async fn load_identities(
    path: &str,
    unwrapper: &dyn KeyUnwrapper,
) -> Result<Vec<NostrConnectKeys>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read identities at {path}"))?;
    let files: Vec<IdentityFiles> =
        serde_json::from_str(&raw).with_context(|| format!("invalid identities at {path}"))?;
    if files.is_empty() {
        bail!("{path} lists no identity");
    }

    let mut seen = HashSet::new();
    let mut identities = Vec::with_capacity(files.len());
    for f in files {
        let keys = NostrConnectKeys::new(
            load_sealed(&f.signer, unwrapper).await?,
            load_sealed(&f.user, unwrapper).await?,
        );
        // Two serve loops on one transport key would both answer.
        if !seen.insert(keys.signer.public_key()) || !seen.insert(keys.user.public_key()) {
            bail!("{path}: a key is used twice ({} / {})", f.signer, f.user);
        }
        identities.push(keys);
    }
    Ok(identities)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "bunkerd=info,nostr_remote_signer=info,nostr_connect=info,nostr_sdk=warn".into()
            }),
        )
        .init();

    // Before anything touches a secret: no swap, no core dumps.
    let hardening = hardening::harden();

    // The root of trust. Chosen HERE, by process configuration — never by the sealed
    // file, which an attacker with disk write access could otherwise downgrade.
    let unwrapper = PassphraseUnwrapper::from_env()?;

    let identities_path = env_or("BUNKER_IDENTITIES", "identities.json");
    let identities = load_identities(&identities_path, &unwrapper).await?;
    let served: HashSet<PublicKey> = identities.iter().map(|k| k.user.public_key()).collect();

    // Default-deny policy. No policy file, no daemon: refusing to start beats approving
    // everything by accident.
    let policy_path = env_or("BUNKER_POLICY", "policy.json");
    let policy = Policy::load(&policy_path)?;

    let agents_path = env_or("BUNKER_AGENTS", "agents.json");
    let (agents_tx, agents_rx) = watch::channel(Arc::new(Agents::load(&agents_path, &served)?));
    // Before serving: the default action of SIGHUP kills the process.
    let mut hangup = signal(SignalKind::hangup())?;

    // Journal: the signing path only ever does a non-blocking try_send; a dedicated thread
    // owns the file and fsyncs every batch.
    let audit_path = env_or("BUNKER_AUDIT_LOG", "audit.log");
    let (audit, receiver) = audit_channel(AUDIT_QUEUE);
    let writer = receiver
        .spawn_writer(&audit_path)
        .with_context(|| format!("cannot open audit log at {audit_path}"))?;

    println!("\ntransport relay                  : {RELAY}");
    println!("root of trust                    : {}", unwrapper.name());
    println!(
        "memory locked / core dumps off   : {} / {}",
        hardening.memory_locked, hardening.core_dumps_disabled
    );
    println!("identities                       : {identities_path}");
    println!("policy                           : {policy_path}");
    println!("agents                           : {agents_path}");
    println!(
        "reload agents                    : kill -HUP {}",
        std::process::id()
    );
    println!("audit log                        : {audit_path}\n");

    let gate = Arc::new(Gate::new(policy, agents_rx, audit));
    let mut serving = JoinSet::new();
    for keys in identities {
        let user = keys.user.public_key();
        let actions = PolicyActions::new(Arc::clone(&gate), user);
        let signer = NostrConnectRemoteSigner::new(keys, [RELAY], None, None)?;
        println!("identity   : {}", user.to_bech32()?);
        println!("bunker URI : {}\n", signer.bunker_uri());
        serving.spawn(async move { signer.serve(actions).await });
    }
    // Only the serve loops may hold the journal sender, so stopping them closes it.
    drop(gate);

    tokio::spawn(async move {
        while hangup.recv().await.is_some() {
            agents_tx.send_replace(Arc::new(access::reload(&agents_path, &served)));
        }
    });

    tracing::info!("bunker listening - Ctrl-C to stop");

    // Flush the journal before reporting.
    let outcome = tokio::select! {
        Some(res) = serving.join_next() => res
            .context("serve loop panicked")
            .and_then(|r| r.context("serve loop failed")),
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown requested");
            Ok(())
        }
    };
    serving.shutdown().await;

    match writer.join() {
        Ok(Ok(())) => tracing::info!("audit log flushed"),
        Ok(Err(e)) => tracing::error!(error = %e, "audit writer failed"),
        Err(_) => tracing::error!("audit writer panicked"),
    }

    outcome
}
