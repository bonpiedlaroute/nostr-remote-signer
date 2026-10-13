//! A stand-in for AWS KMS, for the vault under QEMU: AWS has not signed QEMU's attestation
//! documents, so the real KMS refuses them.
//!
//! Usage:
//!   cargo run -p nostr-remote-signer --features fake-kms --example fake_kms -- [addr] [pcr0]
//!
//! Listens on addr, 127.0.0.1:8000 by default. With pcr0, in hex as `nitro-cli` prints it,
//! only that image may decrypt; without it, any attested enclave may. Every Decrypt logs
//! the PCR0 of the enclave that asked.
//!
//! It encrypts nothing: a key sealed with it is as good as in clear. Dev identities only.

use anyhow::{Context, Result};
use nostr_remote_signer::unwrap::fake_kms;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();

    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:8000".to_string());
    let pcr0 = args
        .next()
        .map(|hex| fake_kms::parse_pcr(&hex).context("pcr0: 96 hex digits expected"))
        .transpose()?;

    let listener = TcpListener::bind(&addr)
        .await
        .with_context(|| format!("cannot listen on {addr}"))?;
    tracing::warn!("fake KMS on http://{addr}: it encrypts nothing, dev identities only");
    tracing::info!(
        "Decrypt for {}",
        if pcr0.is_some() {
            "the image with that PCR0 only"
        } else {
            "any attested enclave"
        }
    );
    fake_kms::serve(listener, pcr0).await;
    Ok(())
}
