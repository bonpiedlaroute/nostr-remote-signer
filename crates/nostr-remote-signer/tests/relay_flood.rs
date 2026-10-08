//! C3 acceptance: "a flood of junk no longer drives up the vault's CPU" (plan §7).
//!
//! The vault pays a NIP-44 decryption for every event it receives, before its policy can
//! refuse anything. The measure is therefore how many junk events reach a subscriber that
//! listens exactly as the vault does.

use std::collections::HashSet;
use std::time::Duration;

use nostr_remote_signer::rate::RateConfig;
use nostr_remote_signer::relay::BunkerOnly;
use nostr_sdk::prelude::*;

const FLOOD: usize = 50;
const BURST: u32 = 5;

async fn client(url: &RelayUrl) -> Client {
    let client = Client::default();
    client.add_relay(url.clone()).await.unwrap();
    client.connect().and_wait(Duration::from_secs(5)).await;
    client
}

#[tokio::test]
async fn a_flood_reaches_the_vault_at_a_bounded_rate() {
    let signer = Keys::generate();
    let rate = RateConfig {
        burst: BURST,
        per_second: 0.001,
    };
    let relay = LocalRelay::builder()
        .write_policy(BunkerOnly::new(
            HashSet::from([signer.public_key()]),
            rate,
            rate,
        ))
        .build();
    relay.run().await.unwrap();
    let url = relay.url().await;

    // The vault's subscription, as `NostrConnectRemoteSigner` makes it.
    let vault = client(&url).await;
    let mut inbox = vault.notifications();
    vault
        .subscribe(
            Filter::new()
                .pubkey(signer.public_key())
                .kind(Kind::NostrConnect),
        )
        .await
        .unwrap();
    // The relay must hold the subscription before the flood starts.
    while let Some(n) = inbox.next().await {
        if let ClientNotification::Message { message, .. } = n
            && matches!(*message, RelayMessage::EndOfStoredEvents(_))
        {
            break;
        }
    }

    let attacker = client(&url).await;
    for _ in 0..FLOOD {
        let junk = EventBuilder::new(Kind::NostrConnect, "junk")
            .tag(Tag::public_key(signer.public_key()))
            .finalize(&Keys::generate())
            .unwrap();
        let _ = attacker.send_event(&junk).await;
    }

    let mut delivered = 0;
    while let Ok(Some(n)) = tokio::time::timeout(Duration::from_millis(500), inbox.next()).await {
        if matches!(n, ClientNotification::Event { .. }) {
            delivered += 1;
        }
    }
    println!("flood: {FLOOD} sent, {delivered} delivered to the vault");
    assert_eq!(delivered, BURST as usize);

    // Same source address as the flood, yet the bunker's answer still goes through.
    let answer = EventBuilder::new(Kind::NostrConnect, "answer")
        .tag(Tag::public_key(Keys::generate().public_key()))
        .finalize(&signer)
        .unwrap();
    let sent = vault.send_event(&answer).await.unwrap();
    assert!(sent.failed.is_empty(), "{:?}", sent.failed);
}
