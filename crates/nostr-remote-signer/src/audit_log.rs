//! The append-only journal: a bounded channel feeding a dedicated writer thread.
//!
//! Keycast removed its per-operation log partly for performance: it did "DB query +
//! UPDATE + INSERT" on the signing path. Here the signing path does one non-blocking
//! `try_send` and nothing else. The writer can therefore afford what the signing path
//! never could: an fsync after every batch.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::{self, JoinHandle};

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

impl AuditReceiver {
    /// Open `path` for append and drain the channel into it on a dedicated OS thread.
    ///
    /// The thread ends when every sink has been dropped; join the handle to be sure the
    /// last batch reached the disk.
    pub fn spawn_writer(self, path: impl AsRef<Path>) -> io::Result<JoinHandle<io::Result<()>>> {
        let file = open_append(path.as_ref())?;
        thread::Builder::new()
            .name("audit-writer".into())
            .spawn(move || self.run(file))
    }

    fn run(mut self, mut file: File) -> io::Result<()> {
        // A plain OS thread, not a tokio task: blocking_recv and fsync stay out of the
        // async runtime entirely.
        while let Some(first) = self.rx.blocking_recv() {
            write_line(&mut file, &first.to_json_line())?;
            while let Ok(next) = self.rx.try_recv() {
                write_line(&mut file, &next.to_json_line())?;
            }
            // Losses happen while the queue is full, i.e. AFTER what was queued: write the
            // marker after the batch, where the hole actually is.
            self.write_gap(&mut file)?;
            file.sync_data()?;
        }
        self.write_gap(&mut file)?;
        file.sync_data()
    }

    fn write_gap(&self, file: &mut File) -> io::Result<()> {
        let lost = self.dropped.swap(0, Ordering::Relaxed);
        if lost > 0 {
            let line = serde_json::json!({ "at": unix_now(), "event": "audit_gap", "lost": lost });
            write_line(file, &line.to_string())?;
        }
        Ok(())
    }
}

/// One `write` per line: with O_APPEND, each line lands atomically.
fn write_line(file: &mut File, line: &str) -> io::Result<()> {
    let mut buf = String::with_capacity(line.len() + 1);
    buf.push_str(line);
    buf.push('\n');
    file.write_all(buf.as_bytes())
}

fn open_append(path: &Path) -> io::Result<File> {
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
