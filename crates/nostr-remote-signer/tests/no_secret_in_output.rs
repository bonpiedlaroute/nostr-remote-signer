//! A unit test on `Debug` cannot catch a leak through a log macro, a panic message or a
//! third-party crate. A subprocess can, because it sees exactly what an operator sees.

use std::process::Command;

use nostr::key::Keys;
use nostr::prelude::ToBech32;
use nostr_remote_signer::sealed::SealedKey;
use nostr_remote_signer::unwrap::passphrase::{PASSPHRASE_ENV, PassphraseUnwrapper};

const PASSPHRASE: &str = "correct horse battery staple";

#[tokio::test]
async fn no_secret_reaches_the_process_output() {
    // SAFETY: single-threaded test.
    unsafe { std::env::set_var(PASSPHRASE_ENV, PASSPHRASE) };
    let unwrapper = PassphraseUnwrapper::from_env().unwrap();

    let keys = Keys::generate();
    let sealed = SealedKey::seal(keys.secret_key(), &unwrapper)
        .await
        .unwrap();

    let dir = std::env::temp_dir().join(format!("b2-leak-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("identity.sealed.json");
    std::fs::write(&path, serde_json::to_string(&sealed).unwrap()).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_leak_probe"))
        .env(PASSPHRASE_ENV, PASSPHRASE)
        .env("BUNKER_SEALED_KEY", &path)
        .env("RUST_LOG", "trace")
        .output()
        .expect("leak_probe must run");

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Guard against the test passing for the wrong reason: a probe that crashed before
    // opening the key would trivially contain no secret.
    assert!(out.status.success(), "leak_probe failed:\n{combined}");
    assert!(
        combined.contains(&keys.public_key().to_bech32().unwrap()),
        "leak_probe did not open the key; this test proves nothing:\n{combined}"
    );

    let bytes = keys.secret_key().secret_bytes();
    let candidates = [
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        bytes.iter().map(|b| format!("{b:02X}")).collect::<String>(),
        keys.secret_key().to_bech32().unwrap(),
        PASSPHRASE.to_string(),
    ];
    for c in candidates {
        assert!(
            !combined.contains(&c),
            "a secret reached the process output: {c}\n--- output ---\n{combined}"
        );
    }

    // Also check the sealed file on disk, for the same reason B1 did.
    let on_disk = std::fs::read_to_string(&path).unwrap();
    for c in [
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        keys.secret_key().to_bech32().unwrap(),
    ] {
        assert!(!on_disk.contains(&c));
    }

    std::fs::remove_dir_all(&dir).ok();
}
