//! The enclave's entrypoint: provide what an enclave lacks, then run the vault.
//!
//! An enclave has no network and no disk, only vsock to its parent. This brings the
//! loopback interface up, fetches the passphrase and the agents from the parent, bridges
//! the transport relay's TCP port to the parent, then runs the given program and exits
//! with it. Meanwhile, it keeps the program's agents in step with the parent's.
//!
//! Usage (the image's ENTRYPOINT): enclave-init /bunkerd

use std::{fs, io};

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

/// What the vault gets when the parent serves no list: no agent at all.
const NO_AGENTS: &[u8] = br#"{ "agents": [] }"#;

/// Make the vault's copy match what the parent served, or hold no agent when it served
/// nothing: an outage never keeps a revoked agent alive. True if the copy changed.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn sync_agents(served: io::Result<Vec<u8>>, path: &str, current: &mut Vec<u8>) -> io::Result<bool> {
    let agents = served.unwrap_or_else(|e| {
        if current.as_slice() != NO_AGENTS {
            eprintln!("agents: the parent serves none ({e}), every agent is revoked");
        }
        NO_AGENTS.to_vec()
    });
    if agents == *current {
        return Ok(false);
    }
    // Renamed into place: the vault never reads a half-written list.
    let tmp = format!("{path}.new");
    fs::write(&tmp, &agents)?;
    fs::rename(&tmp, path)?;
    *current = agents;
    Ok(true)
}

#[cfg(target_os = "linux")]
mod enclave {
    use std::io::{self, Read};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::process::Command;
    use std::thread;
    use std::time::Duration;

    use anyhow::{Context, Result, bail};
    use nostr_remote_signer::access::agents_path;
    use nostr_remote_signer::unwrap::passphrase::PASSPHRASE_ENV;
    use vsock::{VsockAddr, VsockStream};
    use zeroize::Zeroizing;

    use super::sync_agents;

    /// The parent instance, as seen from any Nitro enclave.
    const PARENT_CID: u32 = 3;
    /// Must match enclave/parent.sh.
    const PASSPHRASE_PORT: u32 = 7000;
    const AGENTS_PORT: u32 = 7002;
    /// The relay's TCP port inside the enclave, and the vsock port to the parent.
    const RELAY_PORT: u16 = 7777;
    /// A change on the parent reaches the vault within this.
    const AGENTS_POLL: Duration = Duration::from_secs(1);

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

        let agents_addr = VsockAddr::new(parent, AGENTS_PORT);
        let agents_path = agents_path();
        let mut agents = Vec::new();
        sync_agents(fetch(&agents_addr), &agents_path, &mut agents)
            .with_context(|| format!("cannot write the agents to {agents_path}"))?;

        let listener = TcpListener::bind(("127.0.0.1", RELAY_PORT))
            .context("cannot listen for the relay bridge")?;
        thread::spawn(move || bridge(listener, VsockAddr::new(parent, RELAY_PORT.into())));

        // Inherited across exec: until the vault installs its handler, which it does before
        // reading the agents, a SIGHUP is ignored instead of killing it.
        // SAFETY: SIG_IGN runs no code.
        unsafe { libc::signal(libc::SIGHUP, libc::SIG_IGN) };
        let mut vault = Command::new(&program)
            .args(args)
            .env(PASSPHRASE_ENV, passphrase.as_str())
            .spawn()
            .with_context(|| format!("cannot run {program}"))?;
        // Wiped now: process::exit runs no destructor.
        drop(passphrase);

        let pid = vault.id() as libc::pid_t;
        thread::spawn(move || {
            loop {
                thread::sleep(AGENTS_POLL);
                match sync_agents(fetch(&agents_addr), &agents_path, &mut agents) {
                    // SAFETY: a signal to our own child; no memory is involved.
                    Ok(true) => unsafe {
                        libc::kill(pid, libc::SIGHUP);
                    },
                    Ok(false) => {}
                    Err(e) => eprintln!("agents: cannot write {agents_path}: {e}"),
                }
            }
        });

        let status = vault.wait().context("cannot wait for the vault")?;
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

    /// The parent sends its whole list on every connection, then closes.
    fn fetch(addr: &VsockAddr) -> io::Result<Vec<u8>> {
        let mut stream = VsockStream::connect(addr)?;
        // A parent that never finishes serves no list.
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut agents = Vec::new();
        stream.read_to_end(&mut agents)?;
        Ok(agents)
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
    use super::*;

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

    #[test]
    fn the_agents_follow_the_parent_and_fail_closed() {
        let path = std::env::temp_dir().join(format!("d15-agents-{}.json", std::process::id()));
        let path = path.to_str().unwrap();
        let list = br#"{ "agents": ["a"] }"#.to_vec();
        let away = || Err(io::ErrorKind::ConnectionRefused.into());
        let mut current = Vec::new();

        assert!(sync_agents(Ok(list.clone()), path, &mut current).unwrap());
        assert_eq!(fs::read(path).unwrap(), list);
        assert!(!sync_agents(Ok(list.clone()), path, &mut current).unwrap());

        assert!(sync_agents(away(), path, &mut current).unwrap());
        assert_eq!(fs::read(path).unwrap(), NO_AGENTS);
        assert!(!sync_agents(away(), path, &mut current).unwrap());

        assert!(sync_agents(Ok(list.clone()), path, &mut current).unwrap());
        assert_eq!(fs::read(path).unwrap(), list);
        fs::remove_file(path).unwrap();
    }
}
