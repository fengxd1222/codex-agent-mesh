//! Process-attempt helpers: allowlisted environment, receipts, and disk spools.
//!
//! This module does not spawn providers. [`crate::supervisor`] is the only
//! owner of the suspended-create / job / receipt / resume sequence. The
//! helpers here stay free of `SQLite` so spool I/O never holds a reader.

#![allow(clippy::missing_errors_doc)]

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};

use thiserror::Error;

#[cfg(windows)]
pub use mesh_win32::{ProcessIdentity, ProcessWait};

/// Default per-attempt combined stdout+stderr spool quota.
pub const DEFAULT_SPOOL_QUOTA_BYTES: u64 = 8 * 1024 * 1024;
const SPOOL_READ_BUFFER_BYTES: usize = 8192;

/// Names a provider process may inherit. Values are never logged or persisted.
pub const DEFAULT_PROVIDER_ENV_NAMES: &[&str] = &[
    "PATH",
    "Path",
    "PATHEXT",
    "SystemRoot",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "LOCALAPPDATA",
    "APPDATA",
    "ComSpec",
    "COMSPEC",
    "windir",
    "WINDIR",
];

/// Shared counters for one attempt's stdout/stderr spools.
#[derive(Debug)]
pub struct SpoolQuota {
    written: AtomicU64,
    exceeded: AtomicBool,
    limit: u64,
}

impl SpoolQuota {
    #[must_use]
    pub fn new(limit: u64) -> Arc<Self> {
        Arc::new(Self {
            written: AtomicU64::new(0),
            exceeded: AtomicBool::new(false),
            limit,
        })
    }

    #[must_use]
    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn exceeded(&self) -> bool {
        self.exceeded.load(Ordering::Relaxed)
    }

    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }
}

/// Disk-backed stdout/stderr capture for one attempt.
pub struct AttemptSpools {
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    quota: Arc<SpoolQuota>,
    stdout: Option<JoinHandle<io::Result<u64>>>,
    stderr: Option<JoinHandle<io::Result<u64>>>,
}

impl AttemptSpools {
    /// Starts bounded drain threads. The callers must supply already-piped
    /// parent read ends; this function never inspects `SQLite`.
    pub fn start(
        attempt_root: &Path,
        stdout: File,
        stderr: File,
        quota: Arc<SpoolQuota>,
    ) -> Result<Self, ProcessSupportError> {
        fs::create_dir_all(attempt_root)?;
        let stdout_path = attempt_root.join("stdout.spool");
        let stderr_path = attempt_root.join("stderr.spool");
        let stdout_file = create_spool_file(&stdout_path)?;
        let stderr_file = create_spool_file(&stderr_path)?;
        let stdout_quota = Arc::clone(&quota);
        let stderr_quota = Arc::clone(&quota);
        Ok(Self {
            stdout_path,
            stderr_path,
            quota,
            stdout: Some(
                thread::Builder::new()
                    .name("mesh-spool-stdout".into())
                    .spawn(move || drain_to_spool(stdout, stdout_file, &stdout_quota))
                    .map_err(ProcessSupportError::from)?,
            ),
            stderr: Some(
                thread::Builder::new()
                    .name("mesh-spool-stderr".into())
                    .spawn(move || drain_to_spool(stderr, stderr_file, &stderr_quota))
                    .map_err(ProcessSupportError::from)?,
            ),
        })
    }

    #[must_use]
    pub fn quota(&self) -> &SpoolQuota {
        &self.quota
    }

    /// Joins drain threads and returns how many bytes landed on disk.
    pub fn join(&mut self) -> Result<(u64, u64), ProcessSupportError> {
        let stdout = join_spool(self.stdout.take())?;
        let stderr = join_spool(self.stderr.take())?;
        Ok((stdout, stderr))
    }
}

impl Drop for AttemptSpools {
    fn drop(&mut self) {
        let _ = self.join();
    }
}

/// Builds the in-memory environment from an allowlist of *names*.
///
/// Inherited values for names not on the list are dropped. `extra` may add
/// explicit test or adapter variables. Secret values are not recorded.
#[must_use]
pub fn build_allowlisted_environment(
    allowlist: &[&str],
    extra: &[(OsString, OsString)],
) -> Vec<(OsString, OsString)> {
    let mut pairs: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(key, _)| {
            allowlist
                .iter()
                .any(|allowed| key.eq_ignore_ascii_case(OsStr::new(allowed)))
        })
        .collect();
    for (key, value) in extra {
        if let Some(existing) = pairs
            .iter_mut()
            .find(|(present, _)| present.eq_ignore_ascii_case(key))
        {
            existing.1.clone_from(value);
        } else {
            pairs.push((key.clone(), value.clone()));
        }
    }
    pairs
}

fn create_spool_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
}

fn drain_to_spool(mut reader: File, mut writer: File, quota: &SpoolQuota) -> io::Result<u64> {
    let mut buffer = [0_u8; SPOOL_READ_BUFFER_BYTES];
    let mut written = 0_u64;
    // Bytes are flushed per read (at most 8 KiB). Incomplete UTF-8 at a
    // chunk edge stays on disk as raw octets; the daemon never materializes
    // the stream as one String.
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                written =
                    written.saturating_add(write_quota(&mut writer, quota, &buffer[..count])?);
                if quota.exceeded() {
                    // Stop reading so the pipe fills and the child pauses
                    // until the supervisor kills the job tree.
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => break,
            Err(error) => return Err(error),
        }
    }
    let _ = writer.flush();
    Ok(written)
}

fn write_quota(writer: &mut File, quota: &SpoolQuota, chunk: &[u8]) -> io::Result<u64> {
    let accepted = apply_quota(quota, chunk.len() as u64);
    if accepted == 0 {
        return Ok(0);
    }
    let take = usize::try_from(accepted)
        .unwrap_or(chunk.len())
        .min(chunk.len());
    writer.write_all(&chunk[..take])?;
    Ok(accepted)
}

fn apply_quota(quota: &SpoolQuota, incoming: u64) -> u64 {
    if incoming == 0 {
        return 0;
    }
    let previous = quota.written.fetch_add(incoming, Ordering::Relaxed);
    if previous >= quota.limit {
        quota.exceeded.store(true, Ordering::Relaxed);
        quota.written.fetch_sub(incoming, Ordering::Relaxed);
        return 0;
    }
    let remaining = quota.limit - previous;
    if incoming > remaining {
        quota.exceeded.store(true, Ordering::Relaxed);
        let overflow = incoming - remaining;
        quota.written.fetch_sub(overflow, Ordering::Relaxed);
        remaining
    } else {
        incoming
    }
}

fn join_spool(handle: Option<JoinHandle<io::Result<u64>>>) -> Result<u64, ProcessSupportError> {
    let Some(handle) = handle else {
        return Ok(0);
    };
    handle
        .join()
        .map_err(|_| ProcessSupportError::SpoolThreadPanicked)?
        .map_err(ProcessSupportError::from)
}

/// Redaction-safe helper errors. Paths and environment values are omitted.
#[derive(Debug, Error)]
pub enum ProcessSupportError {
    #[error("attempt spool thread panicked")]
    SpoolThreadPanicked,
    #[error("attempt spool I/O failed")]
    Io(#[from] io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_forwards_named_variables_and_drops_secrets() {
        let env = build_allowlisted_environment(
            &["PATH", "Path"],
            &[(OsString::from("MESH_EXTRA"), OsString::from("1"))],
        );
        assert!(
            env.iter()
                .any(|(key, _)| key.eq_ignore_ascii_case(OsStr::new("PATH")))
        );
        assert!(
            env.iter()
                .any(|(key, value)| key == "MESH_EXTRA" && value == "1")
        );
        assert!(env.iter().all(|(key, _)| {
            key.eq_ignore_ascii_case(OsStr::new("PATH")) || key == "MESH_EXTRA"
        }));
    }

    #[test]
    fn spool_quota_stops_unbounded_growth() {
        let dir = tempfile::tempdir().expect("tempdir");
        let quota = SpoolQuota::new(32);
        let source = dir.path().join("source.bin");
        fs::write(&source, [b'x'; 64]).expect("source");
        let empty = dir.path().join("empty.bin");
        fs::write(&empty, []).expect("empty");
        let stdout_read = File::open(&source).expect("stdout source");
        let stderr_read = File::open(&empty).expect("stderr source");
        let attempt_root = dir.path().join("attempt");
        let mut spools =
            AttemptSpools::start(&attempt_root, stdout_read, stderr_read, quota.clone())
                .expect("start spools");
        let (stdout_bytes, _) = spools.join().expect("join");
        assert!(quota.exceeded());
        assert!(stdout_bytes <= 32);
        assert!(quota.written() <= 32);
        let on_disk = fs::metadata(&spools.stdout_path)
            .expect("stdout metadata")
            .len();
        assert!(on_disk <= 32);
    }

    #[cfg(windows)]
    #[test]
    fn process_identity_rejects_malformed_receipts() {
        assert!(ProcessIdentity::decode("").is_err());
        assert!(ProcessIdentity::decode("v2:1:00:C:\\x.exe").is_err());
        let parsed = ProcessIdentity::decode(r"v1:9:000000000000000a:C:\mesh\a.exe").expect("ok");
        assert_eq!(parsed.pid(), 9);
        assert_eq!(parsed.creation_time(), 10);
    }
}
