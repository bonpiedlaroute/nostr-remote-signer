//! This is a regression guard, not a discovery: `nostr` and `secp256k1` already redact.
//! The test exists so that a future `#[derive(Debug)]` on a secret-bearing struct fails
//! here rather than in production logs.

use nostr::key::Keys;
use nostr::prelude::ToBech32;

/// Every encoding the same secret could plausibly appear in.
fn encodings(keys: &Keys) -> Vec<String> {
    let bytes = keys.secret_key().secret_bytes();
    vec![
        bytes.iter().map(|b| format!("{b:02x}")).collect(),
        bytes.iter().map(|b| format!("{b:02X}")).collect(),
        keys.secret_key().to_bech32().unwrap(),
    ]
}

fn assert_clean(label: &str, rendered: &str, keys: &Keys) {
    for e in encodings(keys) {
        assert!(
            !rendered.contains(&e),
            "{label} leaked the secret key: {rendered}"
        );
    }
}

#[test]
fn keys_debug_does_not_leak() {
    let keys = Keys::generate();
    assert_clean("Keys", &format!("{keys:?}"), &keys);
    assert_clean("SecretKey", &format!("{:?}", keys.secret_key()), &keys);
}

#[test]
fn keys_debug_still_identifies_the_identity() {
    // Redaction must not go so far that logs become useless: the PUBLIC key is what
    // makes an audit line worth writing, and it must survive.
    let keys = Keys::generate();
    let rendered = format!("{keys:?}");
    assert!(rendered.contains(&keys.public_key().to_hex()));
}

#[tokio::test]
async fn sealed_key_debug_does_not_leak() {
    use nostr_remote_signer::sealed::SealedKey;
    use nostr_remote_signer::unwrap::passphrase::{PASSPHRASE_ENV, PassphraseUnwrapper};

    // SAFETY: single-threaded test; the value is identical for every test in this file.
    unsafe { std::env::set_var(PASSPHRASE_ENV, "correct horse battery staple") };
    let unwrapper = PassphraseUnwrapper::from_env().unwrap();

    let keys = Keys::generate();
    let sealed = SealedKey::seal(keys.secret_key(), &unwrapper)
        .await
        .unwrap();

    assert_clean("SealedKey", &format!("{sealed:?}"), &keys);
    assert_clean("PassphraseUnwrapper", &format!("{unwrapper:?}"), &keys);

    // The passphrase itself must not survive a Debug either.
    assert!(!format!("{unwrapper:?}").contains("correct horse battery staple"));
}
