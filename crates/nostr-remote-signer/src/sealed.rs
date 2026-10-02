//! Envelope encryption for a Nostr secret key
//!
//! A random data key (DEK) encrypts the secret with XChaCha20-Poly1305; the root of trust
//! only ever sees the 32-byte DEK. XChaCha rather than AES-GCM for its 192-bit nonce: a
//! random nonce carries no birthday-bound concern, so there is no counter to persist.

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use nostr::key::SecretKey;
use nostr_remote_signer_core::{DATA_KEY_LEN, KeyUnwrapper};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Bump when the on-disk layout changes. Refusing an unknown version beats guessing.
const SEALED_VERSION: u8 = 1;

/// A secret key at rest. Safe to commit to disk; useless without the root of trust.
///
/// Fields are base64 so the file stays greppable and diffable — an operator can see which
/// root of trust sealed it without a tool.
#[derive(Debug, Serialize, Deserialize)]
pub struct SealedKey {
    pub version: u8,
    /// Which root of trust wrapped the data key. Diagnostics only — never trusted for
    /// dispatch: the caller chooses the unwrapper, the file does not get to.
    pub kek: String,
    pub wrapped_dek: String,
    pub nonce: String,
    pub ciphertext: String,
}

impl SealedKey {
    /// Seal a secret key. Run offline, once per identity.
    pub async fn seal(secret: &SecretKey, unwrapper: &dyn KeyUnwrapper) -> Result<Self> {
        let dek = XChaCha20Poly1305::generate_key(&mut OsRng);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext = XChaCha20Poly1305::new(&dek)
            .encrypt(&nonce, secret.secret_bytes().as_ref())
            .map_err(|_| anyhow::anyhow!("sealing failed"))?;

        let wrapped_dek = unwrapper.wrap_data_key(dek.as_slice()).await?;

        Ok(Self {
            version: SEALED_VERSION,
            kek: unwrapper.name().to_string(),
            wrapped_dek: BASE64.encode(&wrapped_dek),
            nonce: BASE64.encode(nonce.as_slice()),
            ciphertext: BASE64.encode(&ciphertext),
        })
    }

    /// Open a sealed key. Exactly ONE call to the root of trust, at boot.
    pub async fn open(&self, unwrapper: &dyn KeyUnwrapper) -> Result<SecretKey> {
        if self.version != SEALED_VERSION {
            bail!(
                "sealed key version {} is not supported (expected {SEALED_VERSION})",
                self.version
            );
        }

        let wrapped = BASE64
            .decode(&self.wrapped_dek)
            .context("wrapped_dek is not valid base64")?;
        let nonce_bytes = BASE64
            .decode(&self.nonce)
            .context("nonce is not valid base64")?;
        let ciphertext = BASE64
            .decode(&self.ciphertext)
            .context("ciphertext is not valid base64")?;

        let dek: Zeroizing<Vec<u8>> = unwrapper.unwrap_data_key(&wrapped).await?;

        if dek.len() != DATA_KEY_LEN {
            bail!("unwrapped data key has the wrong length");
        }

        let cipher = XChaCha20Poly1305::new_from_slice(&dek)
            .map_err(|_| anyhow::anyhow!("invalid data key"))?;

        // Zeroizing so a failed parse below does not leave the secret in a stray Vec.
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(XNonce::from_slice(&nonce_bytes), ciphertext.as_ref())
                // No detail on purpose: a wrong passphrase and a tampered file must be
                // indistinguishable to an attacker probing the daemon.
                .map_err(|_| anyhow::anyhow!("cannot open sealed key"))?,
        );

        SecretKey::from_slice(&plaintext).context("sealed payload is not a valid secret key")
    }
}

#[cfg(test)]
mod tests {
    use nostr::key::Keys;
    use nostr::prelude::ToBech32;

    use super::*;
    use crate::unwrap::passphrase::{PASSPHRASE_ENV, PassphraseUnwrapper};

    fn unwrapper() -> PassphraseUnwrapper {
        // SAFETY: tests in one binary share a process; this value is the same for all of
        // them, so the race is benign.
        unsafe { std::env::set_var(PASSPHRASE_ENV, "correct horse battery staple") };
        PassphraseUnwrapper::from_env().unwrap()
    }

    #[tokio::test]
    async fn round_trip_preserves_the_secret() {
        let keys = Keys::generate();
        let sealed = SealedKey::seal(keys.secret_key(), &unwrapper())
            .await
            .unwrap();
        let opened = sealed.open(&unwrapper()).await.unwrap();
        assert_eq!(opened.secret_bytes(), keys.secret_key().secret_bytes());
    }

    #[tokio::test]
    async fn sealing_twice_gives_different_bytes() {
        // Fresh DEK and nonce every time: two seals of the same key must not match.
        let keys = Keys::generate();
        let a = SealedKey::seal(keys.secret_key(), &unwrapper())
            .await
            .unwrap();
        let b = SealedKey::seal(keys.secret_key(), &unwrapper())
            .await
            .unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.wrapped_dek, b.wrapped_dek);
    }

    #[tokio::test]
    async fn a_tampered_ciphertext_is_rejected() {
        // The AEAD tag must catch a single flipped bit — this is what separates envelope
        // encryption from obfuscation.
        let keys = Keys::generate();
        let mut sealed = SealedKey::seal(keys.secret_key(), &unwrapper())
            .await
            .unwrap();
        let mut raw = BASE64.decode(&sealed.ciphertext).unwrap();
        raw[0] ^= 0x01;
        sealed.ciphertext = BASE64.encode(&raw);
        assert!(sealed.open(&unwrapper()).await.is_err());
    }

    #[tokio::test]
    async fn the_sealed_file_never_contains_the_secret() {
        // The claim of B1, as an assertion rather than a sentence in the README.
        let keys = Keys::generate();
        let sealed = SealedKey::seal(keys.secret_key(), &unwrapper())
            .await
            .unwrap();
        let json = serde_json::to_string(&sealed).unwrap();
        let secret_hex: String = keys
            .secret_key()
            .secret_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(!json.contains(&secret_hex));
        assert!(!json.contains(&keys.secret_key().to_bech32().unwrap()));
    }
}
