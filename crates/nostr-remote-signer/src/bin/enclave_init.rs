//! The enclave's entrypoint: provide what an enclave lacks, then run the vault.
//!
//! An enclave has no network and no disk, only vsock to its parent. This brings the
//! loopback interface up, fetches the passphrase from the parent, bridges the transport
//! relay's TCP port to the parent, then runs the given program and exits with it.
//!
//! Usage (the image's ENTRYPOINT): enclave-init /bunkerd

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    enclave::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("enclave-init runs inside a Linux enclave only");
    std::process::exit(1);
}

/// `echo` adds a newline; a passphrase never ends with one.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn trim_passphrase(raw: &mut String) {
    let len = raw.trim_end_matches(['\n', '\r']).len();
    raw.truncate(len);
}

#[cfg(target_os = "linux")]
mod enclave {
    use std::io::{self, Read};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    use anyhow::{Context, Result, bail};
    use nostr_remote_signer::unwrap::passphrase::PASSPHRASE_ENV;
    use vsock::{VsockAddr, VsockStream};
    use zeroize::Zeroizing;

    /// The parent instance, as seen from any Nitro enclave.
    const PARENT_CID: u32 = 3;
    /// Must match enclave/parent.sh.
    const PASSPHRASE_PORT: u32 = 7000;
    /// The relay's TCP port inside the enclave, and the vsock port to the parent.
    const RELAY_PORT: u16 = 7777;

    pub fn main() -> Result<()> {
        let mut args = std::env::args().skip(1);
        let program = args
            .next()
            .context("usage: enclave-init <program> [args...]")?;
        // Tests only: outside an enclave, the "parent" is the local CID (1).
        let parent = match std::env::var("ENCLAVE_PARENT_CID") {
            Ok(cid) => cid.parse().context("ENCLAVE_PARENT_CID")?,
            Err(_) => PARENT_CID,
        };

        loopback_up().context("cannot bring the loopback interface up")?;

        let passphrase = fetch_passphrase(parent)?;

        let listener = TcpListener::bind(("127.0.0.1", RELAY_PORT))
            .context("cannot listen for the relay bridge")?;
        thread::spawn(move || bridge(listener, VsockAddr::new(parent, RELAY_PORT.into())));

        let status = Command::new(&program)
            .args(args)
            .env(PASSPHRASE_ENV, passphrase.as_str())
            .status()
            .with_context(|| format!("cannot run {program}"))?;
        std::process::exit(status.code().unwrap_or(1));
    }

    /// An enclave boots with `lo` down, so nothing could reach 127.0.0.1. Bringing it up is
    /// enough: the kernel assigns 127.0.0.1/8 to a loopback interface on its own.
    fn loopback_up() -> io::Result<()> {
        // SAFETY: two ioctls on a socket we own, with an `ifreq` we own and initialise.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut req: libc::ifreq = std::mem::zeroed();
            for (dst, src) in req.ifr_name.iter_mut().zip(b"lo\0") {
                *dst = *src as libc::c_char;
            }
            let mut rc = libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut req as *mut libc::ifreq);
            // Already up (a container, a second run): nothing to do, and no privilege needed.
            if rc == 0 && (req.ifr_ifru.ifru_flags & libc::IFF_UP as libc::c_short) == 0 {
                req.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
                rc = libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &req as *const libc::ifreq);
            }
            let err = io::Error::last_os_error();
            libc::close(fd);
            if rc == 0 { Ok(()) } else { Err(err) }
        }
    }

    /// Connect to the parent, read the passphrase to EOF. The parent may not be listening
    /// yet when the enclave boots: retry for up to five minutes.
    fn fetch_passphrase(parent: u32) -> Result<Zeroizing<String>> {
        let addr = VsockAddr::new(parent, PASSPHRASE_PORT);
        let mut stream = None;
        for attempt in 0..600 {
            match VsockStream::connect(&addr) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(_) if attempt == 0 => {
                    eprintln!("waiting for the passphrase on vsock port {PASSPHRASE_PORT}");
                }
                Err(_) => {}
            }
            thread::sleep(Duration::from_millis(500));
        }
        let mut stream = stream.context("the parent never served the passphrase")?;

        let mut raw = Zeroizing::new(String::new());
        stream
            .read_to_string(&mut raw)
            .context("cannot read the passphrase")?;
        super::trim_passphrase(&mut raw);
        if raw.is_empty() {
            bail!("the parent sent an empty passphrase");
        }
        Ok(raw)
    }

    fn bridge(listener: TcpListener, parent: VsockAddr) {
        for client in listener.incoming().flatten() {
            thread::spawn(move || {
                if let Err(e) = splice(client, parent) {
                    eprintln!("relay bridge: {e}");
                }
            });
        }
    }

    /// Copy both ways until each side closes.
    fn splice(client: TcpStream, parent: VsockAddr) -> io::Result<()> {
        let upstream = VsockStream::connect(&parent)?;
        let (mut from_client, mut to_parent) = (client.try_clone()?, upstream.try_clone()?);
        let up = thread::spawn(move || {
            let _ = io::copy(&mut from_client, &mut to_parent);
            let _ = to_parent.shutdown(Shutdown::Write);
        });
        let (mut from_parent, mut to_client) = (upstream, client);
        let _ = io::copy(&mut from_parent, &mut to_client);
        let _ = to_client.shutdown(Shutdown::Write);
        let _ = up.join();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::trim_passphrase;

    #[test]
    fn strips_what_echo_adds_and_nothing_else() {
        for (raw, expected) in [
            ("secret", "secret"),
            ("secret\n", "secret"),
            ("secret\r\n", "secret"),
            ("  secret  ", "  secret  "),
        ] {
            let mut s = raw.to_string();
            trim_passphrase(&mut s);
            assert_eq!(s, expected, "{raw:?}");
        }
    }
}
