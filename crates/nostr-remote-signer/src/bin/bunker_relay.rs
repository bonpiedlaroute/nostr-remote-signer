//! The bunker's own transport relay, so the vault no longer depends on a public one.
//!
//! Usage:
//!   BUNKER_RELAY_SIGNERS=<hex>,<hex> cargo run -p nostr-remote-signer --bin bunker-relay
//!
//! The signer keys are the ones in the bunker:// URIs; bunkerd prints the list.

use std::collections::HashSet;
use std::net::SocketAddr;

use anyhow::{Context, Result};
use nostr_remote_signer::env_or;
use nostr_remote_signer::rate::RateConfig;
use nostr_remote_signer::relay::BunkerOnly;
use nostr_sdk::prelude::*;

const PER_IP: RateConfig = RateConfig {
    burst: 20,
    per_second: 2.0,
};
/// The vault's decrypt budget: it decrypts before its policy can refuse. Matches the
/// global limit of policy.example.json.
const GLOBAL: RateConfig = RateConfig {
    burst: 100,
    per_second: 10.0,
};
const MAX_CONNECTIONS: usize = 256;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bunker_relay=info,nostr_sdk=warn".into()),
        )
        .init();

    let listen: SocketAddr = env_or("BUNKER_RELAY_LISTEN", "127.0.0.1:7777")
        .parse()
        .context("BUNKER_RELAY_LISTEN must be ip:port")?;
    let signers = std::env::var("BUNKER_RELAY_SIGNERS")
        .context("BUNKER_RELAY_SIGNERS is not set")?
        .split(',')
        .map(|s| PublicKey::parse(s.trim()))
        .collect::<Result<HashSet<_>, _>>()
        .context("BUNKER_RELAY_SIGNERS: invalid public key")?;

    let relay = LocalRelay::builder()
        .addr(listen.ip())
        .port(listen.port())
        .max_connections(MAX_CONNECTIONS)
        // Per connection, checked before the signature. Must let the bunker's answers through.
        .rate_limit(RateLimit {
            max_reqs: 10,
            notes_per_minute: (GLOBAL.per_second * 60.0) as u32,
        })
        .write_policy(BunkerOnly::new(signers.clone(), PER_IP, GLOBAL))
        .build();
    relay.run().await?;

    println!("\ntransport relay : {}", relay.url().await);
    println!("signers         : {}\n", signers.len());
    tracing::info!("relay listening - Ctrl-C to stop");

    tokio::signal::ctrl_c().await?;
    Ok(())
}
