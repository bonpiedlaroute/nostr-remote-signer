//! Roots of trust.
//!
//! One module per backend. The envelope itself lives in `crate::sealed` and is shared by
//! all of them — a backend only ever wraps and unwraps a 32-byte data key.

pub mod passphrase;

#[cfg(feature = "aws")]
pub mod kms;
#[cfg(feature = "aws")]
pub mod nsm;
#[cfg(feature = "aws")]
pub mod recipient;

use nostr_remote_signer_core::{KeyUnwrapError, KeyUnwrapper};

/// Environment variable naming the root of trust.
pub const ROOT_OF_TRUST_ENV: &str = "BUNKER_ROOT_OF_TRUST";

/// The root of trust this process is configured with: `passphrase` by default, `aws-kms`,
/// or `nitro` (KMS, attested from inside an enclave).
pub async fn from_env() -> Result<Box<dyn KeyUnwrapper>, KeyUnwrapError> {
    select(&crate::env_or(ROOT_OF_TRUST_ENV, "passphrase")).await
}

async fn select(name: &str) -> Result<Box<dyn KeyUnwrapper>, KeyUnwrapError> {
    match name {
        "passphrase" => Ok(Box::new(passphrase::PassphraseUnwrapper::from_env()?)),
        #[cfg(feature = "aws")]
        "aws-kms" => Ok(Box::new(kms::KmsUnwrapper::from_env(None).await?)),
        #[cfg(all(feature = "aws", target_os = "linux"))]
        "nitro" => Ok(Box::new(
            kms::KmsUnwrapper::from_env(Some(Box::new(nsm::Nsm))).await?,
        )),
        other => Err(KeyUnwrapError::Configuration(format!(
            "{ROOT_OF_TRUST_ENV}={other}: not a root of trust this build provides"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_unknown_root_of_trust_is_refused() {
        let err = select("rot13").await.unwrap_err();
        assert!(matches!(err, KeyUnwrapError::Configuration(_)), "{err}");
    }
}
