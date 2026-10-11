//! The append-only journal: a bounded channel feeding a dedicated writer thread.
//!
//! The signing path does one non-blocking `try_send` and nothing else, so the writer can
//! afford to make every batch durable before the next: an fsync on a local file, or an
//! acknowledgement from the parent instance for an enclave, which has no disk.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use nostr_remote_signer_core::{AuditRecord, AuditSink, unix_now};
use tokio::sync::mpsc;

/// The sending half, handed to the policy. Cheap to clone.
#[derive(Debug, Clone)]
pub struct ChannelAuditSink {
    tx: mpsc::Sender<AuditRecord>,
    dropped: Arc<AtomicU64>,
}

impl AuditSink for ChannelAuditSink {
    fn record(&self, record: AuditRecord) {
        // Never block the decision. If the writer cannot keep up, COUNT what is lost: an
        // audit log that drops lines silently is worse than none, because it is trusted.
        if self.tx.try_send(record).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The receiving half, until it is turned into a writer thread.
#[derive(Debug)]
pub struct AuditReceiver {
    rx: mpsc::Receiver<AuditRecord>,
    dropped: Arc<AtomicU64>,
}

/// A journal channel holding at most `capacity` pending records.
pub fn audit_channel(capacity: usize) -> (ChannelAuditSink, AuditReceiver) {
    let (tx, rx) = mpsc::channel(capacity);
    let dropped = Arc::new(AtomicU64::new(0));
    (
        ChannelAuditSink {
            tx,
            dropped: Arc::clone(&dropped),
        },
        AuditReceiver { rx, dropped },
    )
}

/// Where journal lines end up. `append` returns once the lines are durable.
pub trait Journal: Send + 'static {
    fn append(&mut self, lines: &[String]) -> io::Result<()>;
}

impl Journal for File {
    fn append(&mut self, lines: &[String]) -> io::Result<()> {
        for line in lines {
            write_line(self, line)?;
        }
        self.sync_data()
    }
}

impl AuditReceiver {
    /// Open `path` for append and drain the channel into it on a dedicated OS thread.
    ///
    /// The thread ends when every sink has been dropped; join the handle to be sure the
    /// last batch is durable.
    pub fn spawn_writer(self, path: impl AsRef<Path>) -> io::Result<JoinHandle<io::Result<()>>> {
        let file = open_append(path.as_ref())?;
        self.spawn(file)
    }

    /// The journal kept by the parent instance, at `CID:PORT` over vsock.
    #[cfg(target_os = "linux")]
    pub fn spawn_vsock(self, addr: &str) -> io::Result<JoinHandle<io::Result<()>>> {
        let (cid, port) = parse_cid_port(addr)?;
        let addr = vsock::VsockAddr::new(cid, port);
        self.spawn(StreamJournal::new(move || {
            vsock::VsockStream::connect(&addr)
        }))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn spawn_vsock(self, _addr: &str) -> io::Result<JoinHandle<io::Result<()>>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "a vsock journal needs Linux",
        ))
    }

    /// Drain the channel into `journal` on a dedicated OS thread.
    pub fn spawn(self, journal: impl Journal) -> io::Result<JoinHandle<io::Result<()>>> {
        thread::Builder::new()
            .name("audit-writer".into())
            .spawn(move || self.run(journal))
    }

    fn run(mut self, mut journal: impl Journal) -> io::Result<()> {
        // A plain OS thread, not a tokio task: blocking_recv and fsync stay out of the
        // async runtime entirely.
        while let Some(first) = self.rx.blocking_recv() {
            let mut batch = vec![first.to_json_line()];
            while let Ok(next) = self.rx.try_recv() {
                batch.push(next.to_json_line());
            }
            // Losses happen while the queue is full, i.e. AFTER what was queued: the marker
            // goes after the batch, where the hole actually is.
            batch.extend(self.gap());
            journal.append(&batch)?;
        }
        match self.gap() {
            Some(gap) => journal.append(&[gap]),
            None => Ok(()),
        }
    }

    fn gap(&self) -> Option<String> {
        let lost = self.dropped.swap(0, Ordering::Relaxed);
        (lost > 0).then(|| {
            serde_json::json!({ "at": unix_now(), "event": "audit_gap", "lost": lost }).to_string()
        })
    }
}

/// How long to wait before calling an unreachable keeper again.
const RETRY: Duration = Duration::from_secs(1);

/// A journal kept by someone else, over a stream: the parent instance, for an enclave.
///
/// Line protocol: the journal lines, then an empty line asking for a commit; the keeper
/// answers `ok` once they are on its disk (see [`keep`]). If the connection breaks, the
/// batch is sent again on a new one: at worst a duplicate batch, never a silent loss.
/// While the keeper is away, the writer waits and the channel fills: what overflows is
/// counted and recorded as an `audit_gap`, as with a slow disk.
pub struct StreamJournal<C, S> {
    connect: C,
    conn: Option<BufReader<S>>,
    unreachable: bool,
}

impl<C, S> StreamJournal<C, S>
where
    C: FnMut() -> io::Result<S>,
    S: Read + Write,
{
    pub fn new(connect: C) -> Self {
        Self {
            connect,
            conn: None,
            unreachable: false,
        }
    }

    fn try_append(&mut self, lines: &[String]) -> io::Result<()> {
        let conn = match &mut self.conn {
            Some(conn) => conn,
            None => self.conn.insert(BufReader::new((self.connect)()?)),
        };
        let mut batch = String::new();
        for line in lines {
            batch.push_str(line);
            batch.push('\n');
        }
        batch.push('\n');
        conn.get_mut().write_all(batch.as_bytes())?;

        let mut answer = String::new();
        conn.read_line(&mut answer)?;
        if answer != "ok\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("journal keeper answered {answer:?}"),
            ));
        }
        Ok(())
    }
}

impl<C, S> Journal for StreamJournal<C, S>
where
    C: FnMut() -> io::Result<S> + Send + 'static,
    S: Read + Write + Send + 'static,
{
    fn append(&mut self, lines: &[String]) -> io::Result<()> {
        loop {
            match self.try_append(lines) {
                Ok(()) => {
                    if self.unreachable {
                        tracing::info!("journal keeper reachable again");
                        self.unreachable = false;
                    }
                    return Ok(());
                }
                Err(e) => {
                    if !self.unreachable {
                        tracing::warn!(error = %e, "journal keeper unreachable, retrying");
                        self.unreachable = true;
                    }
                    self.conn = None;
                    thread::sleep(RETRY);
                }
            }
        }
    }
}

/// The keeper's side of [`StreamJournal`]: append each committed batch to `file`, fsync,
/// then acknowledge. Returns when the writer disconnects.
///
/// A batch is written only once complete: a connection lost mid-batch leaves nothing
/// behind, and the writer sends the batch again.
pub fn keep(stream: impl Read + Write, file: &mut File) -> io::Result<()> {
    let mut conn = BufReader::new(stream);
    let mut batch = String::new();
    let mut line = String::new();
    loop {
        line.clear();
        if conn.read_line(&mut line)? == 0 || !line.ends_with('\n') {
            return Ok(());
        }
        if line == "\n" {
            file.write_all(batch.as_bytes())?;
            file.sync_data()?;
            batch.clear();
            conn.get_mut().write_all(b"ok\n")?;
        } else {
            batch.push_str(&line);
        }
    }
}

/// `"3:7001"` → `(3, 7001)`.
pub fn parse_cid_port(addr: &str) -> io::Result<(u32, u32)> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, format!("not CID:PORT: {addr}"));
    let (cid, port) = addr.split_once(':').ok_or_else(invalid)?;
    Ok((
        cid.parse().map_err(|_| invalid())?,
        port.parse().map_err(|_| invalid())?,
    ))
}

/// One `write` per line: with O_APPEND, each line lands atomically.
fn write_line(file: &mut File, line: &str) -> io::Result<()> {
    let mut buf = String::with_capacity(line.len() + 1);
    buf.push_str(line);
    buf.push('\n');
    file.write_all(buf.as_bytes())
}

pub fn open_append(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    // Metadata, not secrets — but who signs what, and when, is still nobody else's business.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    use nostr::key::Keys;
    use nostr_remote_signer_core::Decision;

    use super::*;

    fn temp(test: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("d14-{test}-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    /// A keeper on its own thread, behind one end of a socket pair.
    fn keeper(path: &Path) -> (UnixStream, JoinHandle<()>) {
        let (writer_end, keeper_end) = UnixStream::pair().unwrap();
        let mut file = open_append(path).unwrap();
        let handle = thread::spawn(move || keep(keeper_end, &mut file).unwrap());
        (writer_end, handle)
    }

    fn lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    #[test]
    fn batches_reach_the_keeper_in_order() {
        let path = temp("order");
        let (conn, keeper) = keeper(&path);
        let mut conn = Some(conn);
        let mut journal = StreamJournal::new(move || {
            conn.take()
                .ok_or_else(|| io::Error::other("one connection only"))
        });

        journal.append(&["a".into(), "b".into()]).unwrap();
        journal.append(&["c".into()]).unwrap();
        // Durable on return: the keeper has fsynced before acknowledging.
        assert_eq!(lines(&path), ["a", "b", "c"]);

        drop(journal);
        keeper.join().unwrap();
    }

    #[test]
    fn a_batch_lost_in_transit_is_sent_again_and_kept_once() {
        let path = temp("resend");
        // First keeper: takes the batch, then dies before the commit is acknowledged.
        let (first, keeper_end) = UnixStream::pair().unwrap();
        let crash = thread::spawn(move || {
            let mut conn = BufReader::new(keeper_end);
            let mut line = String::new();
            conn.read_line(&mut line).unwrap();
        });
        let (second, keeper) = keeper(&path);
        let mut conns = vec![second, first];
        let mut journal = StreamJournal::new(move || {
            conns
                .pop()
                .ok_or_else(|| io::Error::other("no more connections"))
        });

        journal.append(&["only once".into()]).unwrap();
        crash.join().unwrap();
        assert_eq!(lines(&path), ["only once"]);

        drop(journal);
        keeper.join().unwrap();
    }

    #[test]
    fn the_keeper_writes_nothing_uncommitted() {
        let path = temp("uncommitted");
        let (mut conn, keeper) = keeper(&path);
        // A complete line without its commit, then half a line: then the writer is gone.
        conn.write_all(b"complete\nhalf a li").unwrap();
        drop(conn);
        keeper.join().unwrap();
        assert!(lines(&path).is_empty());
    }

    #[test]
    fn the_writer_thread_journals_through_a_keeper() {
        let path = temp("pipeline");
        let (conn, keeper) = keeper(&path);
        let mut conn = Some(conn);
        let (sink, receiver) = audit_channel(8);
        let writer = receiver
            .spawn(StreamJournal::new(move || {
                conn.take()
                    .ok_or_else(|| io::Error::other("one connection only"))
            }))
            .unwrap();

        let caller = Keys::generate().public_key();
        for _ in 0..3 {
            sink.record(AuditRecord {
                at: unix_now(),
                identity: caller,
                caller,
                agent: Some("bot".into()),
                method: "ping".into(),
                kind: None,
                decision: Decision::Approved,
            });
        }
        drop(sink);
        writer.join().unwrap().unwrap();
        keeper.join().unwrap();

        let lines = lines(&path);
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|l| l.contains("\"agent\":\"bot\"")));
    }

    #[test]
    fn parses_a_vsock_address() {
        assert_eq!(parse_cid_port("3:7001").unwrap(), (3, 7001));
        for bad in ["3", "3:", ":7001", "x:7001", "3:port"] {
            assert!(parse_cid_port(bad).is_err(), "{bad}");
        }
    }
}
