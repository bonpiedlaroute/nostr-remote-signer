//! A1 acceptance test: send a NIP-46 `ping` to the bunker and wait for the `pong``
//!
//! Usage: cargo run -p nostr-remote-signer --example ping -- 'bunker://...'

use std::time::Duration;

use anyhow::{Context, Result, bail};
use nostr_sdk::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let arg = std::env::args()
        .nth(1)
        .context("usage: cargo run --example ping -- 'bunker://...'")?;

    let (remote_signer_public_key, relays) = match NostrConnectUri::parse(&arg)? {
        NostrConnectUri::Bunker {
            remote_signer_public_key,
            relays,
            ..
        } => (remote_signer_public_key, relays),
        NostrConnectUri::Client { .. } => bail!("expected a bunke:// URI, got nostrconnect://"),
    };

    // Ephemeral caller key: this is all the agent host ever holds.
    let keys = Keys::generate();

    let client = Client::default();

    for relay in relays {
        client.add_relay(relay).await?;
    }
    client.connect().and_wait(Duration::from_secs(10)).await;

    // Subscribe before publishing, otherwise the reponse may land before the subscription.
    client
        .subscribe(
            Filter::new()
                .pubkey(keys.public_key())
                .kind(Kind::NostrConnect)
                .since(Timestamp::now()),
        )
        .await?;

    let mut notifications = client.notifications();

    let msg = NostrConnectMessage::request(&NostrConnectRequest::Ping);
    let req_id = msg.id().to_string();
    let event = NostrConnectEventBuilder::new(remote_signer_public_key, msg).finalize(&keys)?;
    let output = client.send_event(&event).await?;

    if output.success.is_empty() {
        bail!("no relay accepted the event: {:?}", output.failed);
    }
    println!(
        "ping sent (id={req_id}) to {} relay(s)",
        output.success.len()
    );

    let wait_pong = async {
        while let Some(notification) = notifications.next().await {
            let ClientNotification::Event { event, .. } = notification else {
                continue;
            };

            if event.kind != Kind::NostrConnect || event.pubkey != remote_signer_public_key {
                continue;
            }

            let json = nip44::decrypt(keys.secret_key(), &event.pubkey, &event.content)?;
            let msg = NostrConnectMessage::from_json(json)?;
            if msg.id() != req_id {
                continue;
            }

            let res = msg.to_response(NostrConnectMethod::Ping)?;
            return match res.result {
                Some(ResponseResult::Pong) => {
                    println!("✅ pong");
                    Ok(())
                }
                other => bail!("unexpected response: {other:?} / error {:?}", res.error),
            };
        }
        bail!("notification stream closed without a response")
    };

    tokio::time::timeout(Duration::from_secs(30), wait_pong)
        .await
        .context("no pong within 30s")??;

    client.shutdown().await;
    Ok(())
}
