//!  A1 - Minimal NIP-46 bunker
//! Starts, print its `bunker://...` URI serves NIP-46 requests, approving everything.

use anyhow::Result;
use nostr_connect::prelude::*;

/// Bunker transport relay.
///
/// must be a third-party relay without authentication.`relay.nsec.app` is dedicated to
/// NIP-46 (kind 24133); 
const RELAY: &str = "wss://nos.lol";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "bunkerd=info,nostr_connect=info,nostr_sdk=warn".into()),
        )
        .init();

    //`signer`: NIP-46 trasnport idenity the one adevertised in the bunker:// URI
    //`user`: identity we sign on behalf of
    let keys = NostrConnectKeys::new(Keys::generate(), Keys::generate());
    let user_public_key = keys.user.public_key();

    let signer = NostrConnectRemoteSigner::new(keys, [RELAY], None, None)?;

    println!("\nbunker URI:\n {}\n", signer.bunker_uri());
    println!(
        "user public ket (signed identity): {}",
        user_public_key.to_bech32()?
    );
    println!("transport relay                  : {RELAY}\n");

    tracing::info!("bunker listening - Ctrl-C to stop");

    tokio::select! {
        res = signer.serve(ApproveAll) => res?,
        _ = tokio::signal::ctrl_c() => tracing::info!("shutdown requested"),
    }

    Ok(())
}

struct ApproveAll;

impl NostrConnectSignerActions for ApproveAll {
    /// Crate contract: **synchronous** signature, so never do I/O here
    ///
    /// We log the caller and the method, never the content. `method()` and the
    /// `Display`impl of `NostrConnectMethod` already exist in `nostr`: nothing to rewrite
    fn approve(&self, public_key: &PublicKey, req: &NostrConnectRequest) -> bool {
        tracing::info!(caller = %public_key, method = %req.method(), "request approved");
        true
    }
}
