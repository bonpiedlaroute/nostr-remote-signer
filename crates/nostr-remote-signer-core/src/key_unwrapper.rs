//! The root-of-trust boundary
//!
//! This trait covers exactly one thing: wrapping and unwrapping a 32-byte data key.
//! The AEAD that protects the secret itself lives once, in the daemon - backends nevers
//! reimplement it. That is the difference from a `KeyManager`-style trait that encrypts
//! arbitrary payloads: there, each backend carries its own security model

use core::fmt;
use core::future::Future;
use core::pin::Pin;

use zeroize::Zeroizing;

/// Length of a data key, in bytes. 256 bits, matching XChaCha20-Poly1305.
pub const DATA_KEY_LEN: usize = 32;

/// Boxed future returned by the trait methods.
pub type UnwrapFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, KeyUnwrapError>> + Send + 'a>>;

#[derive(Debug, thiserror::Error)]
pub enum KeyUnwrapError {
    /// the backend is misconfigured - missing passphrase, missing key id, bad region
    #[error("key unwrapper configuration: {0}")]
    Configuration(String),
    /// The root of trust refused or could not be reached
    #[error("key unwrapper backend: {0}")]
    Backend(String),
    /// The wrapper data key is malformed or was not produced by this root of trust
    ///
    /// Deliberately carries no detail: a padding-oracle style probe must learn nothing
    #[error("wrapped data key is invalid")]
    Invalid,
}

/// Wraps and unwraps data keys against a root of trust
///
/// Implementations are the only place that knows where trust commes from: a passphrase, a
/// cloud KMS, or in block D, a KMS that only releases to an attested enclave image.
pub trait KeyUnwrapper: fmt::Debug + Send + Sync {
    /// Encrypt a data key with the root of trust.
    fn wrap_data_key<'a>(&'a self, data_key: &'a [u8]) -> UnwrapFuture<'a, Vec<u8>>;

    /// Decrypt a data key previously produced by `wrap_data_key``
    fn unwrap_data_key<'a>(&'a self, wrapped: &'a [u8]) -> UnwrapFuture<'a, Zeroizing<Vec<u8>>>;

    /// Short, stable name of this root of trust`"passphrase"`, `"aws-kms"`, `"nitro"`.
    ///
    /// Goes into the sealed file and the audit line, so an operator can tell at a glance what
    /// protects a given identity.
    fn name(&self) -> &'static str;
}
