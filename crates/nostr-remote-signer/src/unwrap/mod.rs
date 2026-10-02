//! Roots of trust.
//!
//! One module per backend. The envelope itself lives in `crate::sealed` and is shared by
//! all of them — a backend only ever wraps and unwraps a 32-byte data key.

pub mod passphrase;

#[cfg(feature = "aws")]
pub mod kms;
