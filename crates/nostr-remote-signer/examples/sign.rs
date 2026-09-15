//!  Acceptance test: obtain a signed event while holding no key for the signed identity
//!
//! Usage: cargo run -p nostr-remote-siger --example sign -- 'bunker://...'
//!
//! What this proves, and it is the whole of the point of the project: this process generates an
//! EPHEMERAL transport key, asks the bunker who it signs for, and receives a fullly signed event
//! whoe author is the USER identity , a secret key this process never saw.
//!
//! No NIP-46 framing is wirtten by hand here: `finalize_async` performs
//! `get_public_key`
//! then `sign_event` over the wire (nostr `event/builder.rs:171`).

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use nostr_connect::prelude::*;

/// Applies to every request, no to the session as a whole (nostr-connect `client.rs:249`).
/// 30s leaves room for a congested public relay.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sign=info, nostr_connect=info, nostr_sdk=warn".into()),
        )
        .init();

    let arg = std::env::args()
        .nth(1)
        .context("usage: cargo run --example sign -- 'bunker://..'")?;
    let uri = NostrConnectUri::parse(&arg)?;

    // the only key this process holds. It signs kind:24133 envelopes and nothing else.
    let client_keys = Keys::generate();

    println!(
        "caller transport key : {}",
        client_keys.public_key().to_bech32()?
    );

    // Nothing reaches the network yet: `NostrConnect`bootstraps lazily on the first request
    let connect = NostrConnect::new(uri, client_keys, REQUEST_TIMEOUT, None)?;

    // 1. get_public_key triggers the bootstrap: add relays, connect, subscribe and send the
    // NIP-46 `connect` request. Cached afterwards, so later calls cost nothing
    let user_public_key = connect.get_public_key_async().await?;
    println!("signed identity       : {}", user_public_key.to_bech32()?);

    // 2. sign_event, the bunker applies its policy, signs, and returns the event
    let event = EventBuilder::new(Kind::TextNote, "signed by a key this process never held")
        .finalize_async(&connect)
        .await?;

    // 3. The proof, verified locally, never trust the remote signer on its word
    ensure!(
        event.pubkey == user_public_key,
        "signed by the wrong identity: {} != {}",
        event.pubkey,
        user_public_key
    );
    event.verify().context("invalid event id or signature")?;

    println!("\n✅ event signed remotely");
    println!("      id      : {}", event.id);
    println!("      author  : {}", event.pubkey.to_bech32()?);
    println!("      kind    : {}", event.kind.as_u16());
    println!("\n{}\n", event.as_json());

    // `shutdown` consumes `connect`, so it must come last.
    connect.shutdown().await;
    Ok(())
}
