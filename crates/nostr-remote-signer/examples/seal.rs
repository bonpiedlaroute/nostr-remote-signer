//! Seal a Nostr secret key into a sealed-key file.
//!
//! Usage:
//!   BUNKER_PASSPHRASE='…' cargo run -p nostr-remote-signer --example seal -- [out-path]
//!
//! Reads the secret from stdin so it never lands in shell history or the process table.
//! Prints the public key: that is the value to register with `buzz-admin add-member`.

use std::io::{BufRead, Write};

use anyhow::{Context, Result};
use nostr::prelude::*;
use nostr_remote_signer::sealed::SealedKey;
use nostr_remote_signer::unwrap::passphrase::PassphraseUnwrapper;
use nostr_remote_signer_core::KeyUnwrapper;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<()> {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "identity.sealed.json".to_string());
    let unwrapper = PassphraseUnwrapper::from_env()?;

    eprint!("secret key (nsec or hex), then Enter: ");
    std::io::stderr().flush()?;
    let mut line = Zeroizing::new(String::new());
    std::io::stdin().lock().read_line(&mut line)?;

    let keys = Keys::parse(line.trim()).context("not a valid secret key")?;
    let sealed = SealedKey::seal(keys.secret_key(), &unwrapper).await?;

    std::fs::write(&out, serde_json::to_string_pretty(&sealed)?)
        .with_context(|| format!("cannot write {out}"))?;

    println!("sealed with : {}", unwrapper.name());
    println!("written to  : {out}");
    println!("public key  : {}", keys.public_key().to_bech32()?);
    Ok(())
}
