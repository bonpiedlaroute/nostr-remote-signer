//! Protocol core for NIP-46 remote signer: traits and shared types
//!
//! Apache-2.0 on purpose , this is the crate an upstream project can adopt

pub mod key_unwrapper;
pub use key_unwrapper::{DATA_KEY_LEN, KeyUnwrapError, KeyUnwrapper, UnwrapFuture};
