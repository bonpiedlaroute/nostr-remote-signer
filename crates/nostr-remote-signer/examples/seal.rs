//! Seal a Nostr secret key into a sealed-key file.
//!
//! Usage:
//!   BUNKER_PASSPHRASE='…' cargo run -p nostr-remote-signer --example seal -- [out-path]
//!   BUNKER_ROOT_OF_TRUST=aws-kms BUNKER_KMS_KEY_ID='…' \
//!     cargo run -p nostr-remote-signer --features aws --example seal -- [out-path] [from]
//!
//! Reads the secret from stdin so it never lands in shell history or the process table.
//! With `from`, a file sealed with BUNKER_PASSPHRASE, the secret comes from that file
//! instead: the key moves to another root of trust without ever reaching the terminal.
//! Prints the public key: that is the value to register with `buzz-admin add-member`.

use std::io::{BufRead, Write};

use anyhow::{Context, Result};
use nostr::prelude::*;
use nostr_remote_signer::sealed::SealedKey;
use nostr_remote_signer::unwrap::{self, passphrase::PassphraseUnwrapper};
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let out = args
        .next()
        .unwrap_or_else(|| "identity.sealed.json".to_string());
    let from = args.next();
    let unwrapper = unwrap::from_env().await?;

    let keys = match from {
        Some(from) => {
            let sealed = SealedKey::read(&from)?;
            Keys::new(sealed.open(&PassphraseUnwrapper::from_env()?).await?)
        }
        None => {
            eprint!("secret key (nsec or hex), then Enter: ");
            std::io::stderr().flush()?;
            let mut line = Zeroizing::new(String::new());
            std::io::stdin().lock().read_line(&mut line)?;
            Keys::parse(line.trim()).context("not a valid secret key")?
        }
    };
    let sealed = SealedKey::seal(keys.secret_key(), unwrapper.as_ref()).await?;

    std::fs::write(&out, serde_json::to_string_pretty(&sealed)?)
        .with_context(|| format!("cannot write {out}"))?;

    println!("sealed with : {}", unwrapper.name());
    println!("written to  : {out}");
    println!("public key  : {}", keys.public_key().to_bech32()?);
    Ok(())
}
