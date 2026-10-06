//! A NIP-46 bunker with envelope-encrypted key custody.
//!
//! Starts, prints its `bunker://...` URI, serves NIP-46 requests, approving everything.
//! Policy and audit arrive in block C1.
//!
//! Both identities are opened from sealed files at boot: ONE call to the root of trust,
//! and no secret in clear on disk.

use anyhow::{Context, Result};
use nostr_connect::prelude::*;
use nostr_remote_signer::hardening;
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

    let signer = NostrConnectRemoteSigner::new(keys, [RELAY], None, None)?;

    println!("\nbunker URI:\n {}\n", signer.bunker_uri());
    println!(
        "user public key (signed identity): {}",
        user_public_key.to_bech32()?
    );
    println!("transport relay                  : {RELAY}");
    println!("root of trust                    : {}\n", unwrapper.name());
    println!(
        "memory locked / core dumps off   : {} / {}\n",
        hardening.memory_locked, hardening.core_dumps_disabled
    );

    tracing::info!("bunker listening - Ctrl-C to stop");

    tokio::select! {
        res = signer.serve(ApproveAll) => res?,
        _ = tokio::signal::ctrl_c() => tracing::info!("shutdown requested"),
    }

    Ok(())
}

/// Approves everything. The real policy arrives in C1.
struct ApproveAll;

impl NostrConnectSignerActions for ApproveAll {
    /// Crate contract: **synchronous** signature, so never do I/O here.
    ///
    /// We log the caller and the method, never the content. `method()` and the `Display`
    /// impl of `NostrConnectMethod` already exist in `nostr`: nothing to rewrite.
    fn approve(&self, public_key: &PublicKey, req: &NostrConnectRequest) -> bool {
        tracing::info!(caller = %public_key, method = %req.method(), "request approved");
        true
    }
}
