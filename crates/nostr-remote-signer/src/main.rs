//! A NIP-46 bunker with envelope-encrypted key custody.
//!
//! Starts, prints its `bunker://...` URI, and serves NIP-46 requests under a default-deny
//! policy. Every decision — approved or not — leaves one line in an append-only journal.
//!
//! Both identities are opened from sealed files at boot: ONE call to the root of trust,
//! and no secret in clear on disk.

use std::sync::Arc;

use anyhow::{Context, Result};
use nostr_connect::prelude::*;
use nostr_remote_signer::actions::PolicyActions;
use nostr_remote_signer::audit_log::audit_channel;
use nostr_remote_signer::hardening;
use nostr_remote_signer::policy::Policy;
use nostr_remote_signer::sealed::SealedKey;
use nostr_remote_signer::unwrap::passphrase::PassphraseUnwrapper;
use nostr_remote_signer_core::KeyUnwrapper;

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

/// Open a sealed key. `var` overrides `default`, so a deployment can place the files
/// wherever it likes without a config format.
async fn load_sealed(var: &str, default: &str, unwrapper: &dyn KeyUnwrapper) -> Result<Keys> {
    let path = std::env::var(var).unwrap_or_else(|_| default.to_string());
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read sealed key at {path}"))?;
    let sealed: SealedKey =
        serde_json::from_str(&raw).with_context(|| format!("{path} is not a valid sealed key"))?;

    tracing::info!(kek = %sealed.kek, path = %path, "opening sealed key");
    Ok(Keys::new(sealed.open(unwrapper).await?))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bunkerd=info,nostr_connect=info,nostr_sdk=warn".into()),
        )
        .init();

    // Before anything touches a secret: no swap, no core dumps.
    let hardening = hardening::harden();

    // The root of trust. Chosen HERE, by process configuration — never by the sealed
    // file, which an attacker with disk write access could otherwise downgrade.
    let unwrapper = PassphraseUnwrapper::from_env()?;

    // `signer`: NIP-46 transport identity, the one in the bunker:// URI. Sealed too, so
    //           the URI survives a restart and clients need no reconfiguration.
    // `user`:   the custodied identity — the one that actually signs for the agent.
    let keys = NostrConnectKeys::new(
        load_sealed("BUNKER_SEALED_SIGNER", "signer.sealed.json", &unwrapper).await?,
        load_sealed("BUNKER_SEALED_KEY", "identity.sealed.json", &unwrapper).await?,
    );
    let user_public_key = keys.user.public_key();

    // Default-deny policy. No policy file, no daemon: refusing to start beats approving
    // everything by accident.
    let policy_path = std::env::var("BUNKER_POLICY").unwrap_or_else(|_| "policy.json".into());
    let policy = Arc::new(Policy::load(&policy_path)?);

    // Journal: the signing path only ever does a non-blocking try_send; a dedicated thread
    // owns the file and fsyncs every batch.
    let audit_path = std::env::var("BUNKER_AUDIT_LOG").unwrap_or_else(|_| "audit.log".into());
    let (audit, receiver) = audit_channel(AUDIT_QUEUE);
    let writer = receiver
        .spawn_writer(&audit_path)
        .with_context(|| format!("cannot open audit log at {audit_path}"))?;

    let actions = PolicyActions::new(policy, audit);
    let signer = NostrConnectRemoteSigner::new(keys, [RELAY], None, None)?;

    println!("\nbunker URI:\n {}\n", signer.bunker_uri());
    println!(
        "user public key (signed identity): {}",
        user_public_key.to_bech32()?
    );
    println!("transport relay                  : {RELAY}");
    println!("root of trust                    : {}\n", unwrapper.name());
    println!(
        "memory locked / core dumps off   : {} / {}",
        hardening.memory_locked, hardening.core_dumps_disabled
    );
    println!("policy                           : {policy_path}");
    println!("audit log                        : {audit_path}\n");

    tracing::info!("bunker listening - Ctrl-C to stop");

    tokio::select! {
        res = signer.serve(actions) => res?,
        _ = tokio::signal::ctrl_c() => tracing::info!("shutdown requested"),
    }

    // `actions` — and with it the last journal sender — was dropped with the `serve`
    // future above, which closes the channel. Joining guarantees the final batch is on disk.
    match writer.join() {
        Ok(Ok(())) => tracing::info!("audit log flushed"),
        Ok(Err(e)) => tracing::error!(error = %e, "audit writer failed"),
        Err(_) => tracing::error!("audit writer panicked"),
    }

    Ok(())
}
