//! A3 acceptance  test: post a real Buzz message from a host that holds no signing key.
//!
//! Usage:
//!     cargo run -p nostr-remote-signer --example buzz_message -- \
//!         '<bunker-uri>' '<channel-uuid>' [relay-http-base]
//!
//!     two remote signatures are required here, and this process performs neither:
//!         1. the kind:9 Buzz message itself;
//!         2. the kind:27235 NIP-98 event authorizing `POST /events`.
//!
//! The Buzz relay mandates NIP-98 on its HTTP bridge whenever BUZZ_REQUIRE_AUTH_TOKEN is
//! true (buzz-relay/src/api/bridge.rs:744-755); the `X-Pubkey` dev fallback is closed then.

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use nostr_connect::prelude::*;
use sha2::{Digest, Sha256};

const USAGE: &str = "usage: cargo run --example buzz_message -- \
                        '<bunker-uri>' '<channel-uuid' [relay-http-base]";

/// Applies to every NIP-46 request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Buzz message kind - mirrors
const KIND_BUZZ_MESSAGE: u16 = 9;

/// Lowercase hex. Three lines beat a dependency for one hash
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "buzz_message=info,nostr_connect=info,nostr_sdk=warn".into()),
        )
        .init();

    let mut args = std::env::args().skip(1);
    let bunker = args.next().context(USAGE)?;
    let channel_id = args.next().context(USAGE)?;
    let relay_http = args
        .next()
        .unwrap_or_else(|| "http://127.0.0.1:3000".to_string());
    // The only key this process holds: an ephemeral NIP-46 transport key
    let connect = NostrConnect::new(
        NostrConnectUri::parse(&bunker)?,
        Keys::generate(),
        REQUEST_TIMEOUT,
        None,
    )?;

    let author = connect.get_public_key_async().await?;
    println!("custodied identity : {}", author.to_bech32()?);
    println!("channel            : {channel_id}");

    // ---- signature 1: the Buzz message -------------------------------------------------
    let message = EventBuilder::new(
        Kind::Custom(KIND_BUZZ_MESSAGE),
        "posted by a key this host never held",
    )
    .tag(Tag::parse(["h", &channel_id])?)
    .finalize_async(&connect)
    .await?;

    ensure!(
        message.pubkey == author,
        "message signed by the wrong identity: {} != {}",
        message.pubkey,
        author
    );
    message.verify().context("invalid message signature")?;

    let body = message.as_json();
    println!("message event id    : {}", message.id);

    // ---- signature 2: the NIP-98 authorisation ------------------------------------------
    let url = format!("{relay_http}/events");
    let auth = EventBuilder::new(Kind::HttpAuth, "")
        .tags([
            Tag::parse(["u", &url])?,
            Tag::parse(["method", "POST"])?,
            Tag::parse(["nonce", &Keys::generate().public_key().to_hex()])?,
            Tag::parse(["payload", &hex(&Sha256::digest(body.as_bytes()))])?,
        ])
        .finalize_async(&connect)
        .await?;

    let authorization = format!("Nostr {}", BASE64.encode(auth.as_json()));

    // ---- POST ---------------------------------------------------------------------------
    //
    // reqwest derives the `Host` header from the URL, and the relay rebuilds the expected
    // NIP-98 URL from that same header
    let response = reqwest::Client::new()
        .post(&url)
        .header("Authorization", authorization)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .context("POST /events failed")?;

    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    println!("\nPOST {url} -> {status}\n{text}");
    ensure!(status.is_success(), "relay rejected the submission");

    println!("\n✅ Buzz message posted, signed remotely, no key on this host");

    connect.shutdown().await;
    Ok(())
}
