//! The parent's side of the enclave's journal: keep on disk what the vault writes.
//!
//! Usage: BUNKER_AUDIT_LOG=audit.log journal-sink

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use nostr_remote_signer::audit_log::{keep, open_append};
    use nostr_remote_signer::env_or;
    use vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener};

    /// Must match BUNKER_AUDIT_LOG in enclave/Dockerfile.
    const JOURNAL_PORT: u32 = 7001;

    let path = env_or("BUNKER_AUDIT_LOG", "audit.log");
    let mut file = open_append(path.as_ref()).with_context(|| format!("cannot open {path}"))?;
    let listener = VsockListener::bind(&VsockAddr::new(VMADDR_CID_ANY, JOURNAL_PORT))
        .context("cannot listen on vsock")?;
    println!("keeping the enclave's journal in {path} (vsock port {JOURNAL_PORT})");

    // One writer at a time: the vault keeps a single connection, and reconnects if it drops.
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                if let Err(e) = keep(stream, &mut file) {
                    eprintln!("journal connection: {e}");
                }
            }
            Err(e) => eprintln!("journal accept: {e}"),
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("journal-sink runs on a Linux parent instance only");
    std::process::exit(1);
}
