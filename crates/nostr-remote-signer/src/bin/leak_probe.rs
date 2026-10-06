//! Diagnostic: exercise every path that could leak a secret, then exit.
//!
//! Run by tests/no_secret_in_output.rs, which greps the output. Also the artefact behind
//! the "grep nsec" step of the reproducible demo.
//!
//! Usage:
//!   BUNKER_PASSPHRASE=… BUNKER_SEALED_KEY=… cargo run --bin leak_probe

use anyhow::{Context, Result};
use nostr::key::Keys;
use nostr::prelude::ToBech32;
use nostr_remote_signer::hardening;
use nostr_remote_signer::sealed::SealedKey;
use nostr_remote_signer::unwrap::passphrase::PassphraseUnwrapper;

#[tokio::main]
async fn main() -> Result<()> {
    // Deliberately the loudest subscriber we can build: if a secret can reach a log
    // line, it must reach THIS output.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_target(true)
        .init();

    let h = hardening::harden();
    println!("hardening: {h:?}");

    let unwrapper = PassphraseUnwrapper::from_env()?;
    // The Debug impl must redact the passphrase here.
    println!("unwrapper: {unwrapper:?}");
    tracing::trace!(?unwrapper, "unwrapper built");

    let path = std::env::var("BUNKER_SEALED_KEY").context("BUNKER_SEALED_KEY is not set")?;
    let raw = std::fs::read_to_string(&path)?;
    let sealed: SealedKey = serde_json::from_str(&raw)?;
    println!("sealed: {sealed:?}");
    tracing::trace!(?sealed, "sealed key parsed");

    let secret = sealed.open(&unwrapper).await?;
    let keys = Keys::new(secret);

    // The three shapes most likely to leak: Debug on the key pair, Debug on the secret
    // itself, and a tracing field.
    println!("keys: {keys:?}");
    println!("secret: {:?}", keys.secret_key());
    tracing::trace!(?keys, secret = ?keys.secret_key(), "identity opened");

    // Printed on purpose: the test uses it to prove the probe really opened the key
    // rather than failing early and trivially passing.
    println!("public key: {}", keys.public_key().to_bech32()?);
    Ok(())
}
