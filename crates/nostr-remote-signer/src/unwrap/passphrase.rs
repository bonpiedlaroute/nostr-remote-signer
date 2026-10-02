//! Passphrase-backed root of trust, for development and single-operator deployments.
//!
//! `age` rather than a hand-rolled scrypt + AEAD: it is an audited, specified format, and
//! the wrapped data key can be inspected with the `age` CLI during incident response.

use std::io::{Read, Write};
use std::iter;

use age::secrecy::SecretString;
use nostr_remote_signer_core::{KeyUnwrapError, KeyUnwrapper, UnwrapFuture};
use zeroize::Zeroizing;

/// Environment variable holding the passphrase.
pub const PASSPHRASE_ENV: &str = "BUNKER_PASSPHRASE";

pub struct PassphraseUnwrapper {
    passphrase: SecretString,
}

// Hand-written so the passphrase can never reach a log line through `{:?}`.
// B2 will make this discipline a test rather than a convention.
impl std::fmt::Debug for PassphraseUnwrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PassphraseUnwrapper")
            .field("passphrase", &"[REDACTED]")
            .finish()
    }
}

impl PassphraseUnwrapper {
    pub fn from_env() -> Result<Self, KeyUnwrapError> {
        let raw = std::env::var(PASSPHRASE_ENV)
            .map_err(|_| KeyUnwrapError::Configuration(format!("{PASSPHRASE_ENV} is not set")))?;
        if raw.is_empty() {
            return Err(KeyUnwrapError::Configuration(format!(
                "{PASSPHRASE_ENV} is empty"
            )));
        }
        Ok(Self {
            passphrase: SecretString::from(raw),
        })
    }
}

impl KeyUnwrapper for PassphraseUnwrapper {
    fn wrap_data_key<'a>(&'a self, data_key: &'a [u8]) -> UnwrapFuture<'a, Vec<u8>> {
        Box::pin(async move {
            let encryptor = age::Encryptor::with_user_passphrase(self.passphrase.clone());
            let mut out = Vec::new();
            let mut writer = encryptor
                .wrap_output(&mut out)
                .map_err(|e| KeyUnwrapError::Backend(e.to_string()))?;
            writer
                .write_all(data_key)
                .map_err(|e| KeyUnwrapError::Backend(e.to_string()))?;
            writer
                .finish()
                .map_err(|e| KeyUnwrapError::Backend(e.to_string()))?;
            Ok(out)
        })
    }

    fn unwrap_data_key<'a>(&'a self, wrapped: &'a [u8]) -> UnwrapFuture<'a, Zeroizing<Vec<u8>>> {
        Box::pin(async move {
            let decryptor = age::Decryptor::new(wrapped).map_err(|_| KeyUnwrapError::Invalid)?;
            let identity = age::scrypt::Identity::new(self.passphrase.clone());
            let mut reader = decryptor
                .decrypt(iter::once(&identity as _))
                .map_err(|_| KeyUnwrapError::Invalid)?;
            let mut out = Zeroizing::new(Vec::new());
            reader
                .read_to_end(&mut out)
                .map_err(|_| KeyUnwrapError::Invalid)?;
            Ok(out)
        })
    }

    fn name(&self) -> &'static str {
        "passphrase"
    }
}
