//! M4 Git workspace lifecycle for delegated write attempts.
//!
//! This module implements canonical Git admission, a per-repository
//! administrative lock keyed by the canonical common-directory identity, one
//! unique detached worktree per attempt, finalization evidence capture, and
//! path-safe cleanup that never mutates the user's checkout.
//!
//! Safety boundaries implemented here:
//!
//! - Admission rejects non-Git paths, bare repositories, unborn repositories,
//!   missing base commits, in-progress merge/rebase/cherry-pick/revert
//!   operations, and any dirty tracked/untracked state. Porcelain output is
//!   parsed strictly from the NUL-terminated machine format; no shell string
//!   parsing is used and every Git argument is a distinct absolute path.
//! - Each attempt receives a fresh `UUID`-named detached worktree inside the
//!   configured mesh data root. A failed attempt's worktree is never reused;
//!   the user's branch is never merged, rebased, pushed, or otherwise mutated.
//! - Every prepared worktree is durably registered through the sole writer
//!   (`WriterHandle::register_worktree`) in the same critical section that
//!   created it. If registration fails, the freshly created worktree is
//!   removed so an unregistered directory can never linger as mesh-owned.
//! - Cleanup removes only a path recorded as owned by the exact attempt,
//!   verifies Git and the filesystem still agree about it, and never runs a
//!   broad prune over user worktrees. External Git GC or manual removal is a
//!   diagnosed failure, not destructive repair.
//!
//! The worktree itself is repository separation, not a sandbox: an agent can
//! still use absolute paths, network tools, or credentials.

use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fmt, fs,
    io::{BufReader, Read},
    path::{Component, Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    sync::{Arc, Mutex, MutexGuard, PoisonError, Weak},
    thread,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::{
    allow_current_directory,
    domain::{EffectProfile, InteractionResponseKind, IsolationLevel, WorkspaceMode},
    storage::{InteractionResponseEvidence, StorageError},
    writer::WriterHandle,
};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Output cap for `git diff` evidence payloads.
const MAX_DIFF_BYTES: usize = 64 * 1024 * 1024;
/// Output cap for status, tree, file-list, and plumbing listings.
const MAX_LISTING_BYTES: usize = 16 * 1024 * 1024;
/// Output cap for captured stderr diagnostics.
const MAX_STDERR_BYTES: usize = 1024 * 1024;
/// Maximum number of status entries embedded in a dirty-workspace error.
const DIRTY_SAMPLE_LIMIT: usize = 50;
/// Read buffer used while draining child process output.
const DRAIN_BUFFER_BYTES: usize = 8192;

/// Valid index (`X`) status letters of `git status --porcelain=v1`.
const PORCELAIN_X: &[u8] = b" MTADRCU?!";
/// Valid working-tree (`Y`) status letters of `git status --porcelain=v1`.
const PORCELAIN_Y: &[u8] = b" MTDRCU?!";

/// Environment variable allowlist inherited by Git child processes.
const INHERITED_ENV_KEYS: &[&str] = &[
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
];

/// A repository operation whose in-progress state blocks admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GitOperation {
    /// `MERGE_HEAD` is present.
    Merge,
    /// `rebase-merge` or `rebase-apply` is present.
    Rebase,
    /// The sequencer is active for a cherry-pick.
    CherryPick,
    /// The sequencer is active for a revert.
    Revert,
    /// The sequencer is active for another operation.
    Sequencer,
}

impl fmt::Display for GitOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Merge => "merge",
            Self::Rebase => "rebase",
            Self::CherryPick => "cherry-pick",
            Self::Revert => "revert",
            Self::Sequencer => "sequencer operation",
        })
    }
}

/// One strictly parsed `git status --porcelain=v1 -z` entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StatusEntry {
    /// Index status letter.
    pub x: char,
    /// Working-tree status letter.
    pub y: char,
    /// Working-tree path. For rename/copy entries this is the destination.
    pub path: String,
    /// Source path, present only for rename/copy entries.
    pub orig_path: Option<String>,
}

/// Actionable breakdown of a dirty workspace found during admission.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DirtySummary {
    /// Total number of non-clean entries.
    pub total: usize,
    /// Entries with staged content changes (index letter, not conflicted).
    pub staged: usize,
    /// Entries with unstaged content changes (working-tree letter, not conflicted).
    pub unstaged: usize,
    /// Untracked entries.
    pub untracked: usize,
    /// Unmerged/conflicted entries.
    pub conflicted: usize,
    /// Bounded sample of the first entries, for diagnostics.
    pub sample: Vec<StatusEntry>,
}

impl DirtySummary {
    fn from_entries(entries: &[StatusEntry]) -> Self {
        let mut staged = 0;
        let mut unstaged = 0;
        let mut untracked = 0;
        let mut conflicted = 0;
        for entry in entries {
            if entry.x == 'U' || entry.y == 'U' {
                conflicted += 1;
            } else {
                if matches!(entry.x, 'M' | 'T' | 'A' | 'D' | 'R' | 'C') {
                    staged += 1;
                }
                if matches!(entry.y, 'M' | 'T' | 'D' | 'R' | 'C') {
                    unstaged += 1;
                }
                if entry.x == '?' {
                    untracked += 1;
                }
            }
        }
        Self {
            total: entries.len(),
            staged,
            unstaged,
            untracked,
            conflicted,
            sample: entries.iter().take(DIRTY_SAMPLE_LIMIT).cloned().collect(),
        }
    }

    /// Renders an actionable one-line description for error display.
    #[must_use]
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.conflicted > 0 {
            parts.push(format!("{} conflicted", self.conflicted));
        }
        if self.staged > 0 {
            parts.push(format!("{} staged", self.staged));
        }
        if self.unstaged > 0 {
            parts.push(format!("{} modified", self.unstaged));
        }
        if self.untracked > 0 {
            parts.push(format!("{} untracked", self.untracked));
        }
        let mut text = parts.join(", ");
        if let Some(first) = self.sample.first() {
            use std::fmt::Write as _;
            let _ = write!(text, " (first: {})", first.path);
        }
        text
    }
}

impl fmt::Display for DirtySummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.describe())
    }
}

/// One untracked artifact file listed during finalization capture.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactFile {
    /// Repository-relative path.
    pub path: String,
    /// Byte length on disk at capture time.
    pub byte_length: u64,
    /// Whether the artifact is a directory rather than a file.
    pub is_directory: bool,
}

/// One strictly parsed `git ls-tree -r -z` entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TreeEntry {
    /// Git mode, e.g. `100644`.
    pub mode: String,
    /// Object type: `blob`, `tree`, or `commit`.
    pub object_type: String,
    /// Object id in hex.
    pub oid: String,
    /// Repository-relative path.
    pub path: String,
}

/// Bounded diff payload with an explicit truncation flag.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DiffEvidence {
    /// Captured diff bytes (may be truncated, see [`DiffEvidence::truncated`]).
    pub bytes: Vec<u8>,
    /// Whether the configured diff cap was reached and bytes were dropped.
    pub truncated: bool,
}

/// Finalization evidence captured from an owned attempt worktree.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FinalizationEvidence {
    /// Mesh worktree id of the recorded attempt.
    pub worktree_id: String,
    /// Canonical worktree path.
    pub path: String,
    /// Pinned base commit oid the attempt started from.
    pub base_oid: String,
    /// `HEAD` commit oid at capture time.
    pub head_oid: String,
    /// `HEAD^{tree}` object id at capture time.
    pub head_tree_oid: String,
    /// Full recursive tree listing of `HEAD^{tree}`.
    pub tree_entries: Vec<TreeEntry>,
    /// Strictly parsed working-tree status entries.
    pub status_entries: Vec<StatusEntry>,
    /// Untracked artifact files with on-disk byte lengths.
    pub untracked_files: Vec<ArtifactFile>,
    /// Diff from the pinned base to `HEAD` (usually empty; the mesh never
    /// commits, so a nonempty diff means the adapter committed).
    pub committed_diff: Option<DiffEvidence>,
    /// Diff from `HEAD` to the working tree (staged and unstaged changes).
    pub working_diff: Option<DiffEvidence>,
}

/// Successful canonical Git admission of a normal write task's source path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepoAdmission {
    /// Canonical top-level directory of the admitted checkout.
    pub working_root: PathBuf,
    /// Canonical common Git directory; also the administrative lock key.
    pub common_dir: PathBuf,
    /// Full resolved commit object id of the pinned base.
    pub base_oid: String,
}

/// Inputs for the disabled-by-default current-directory escape hatch.
pub struct CurrentDirectoryRequest<'a> {
    /// Existing directory requested as the provider cwd.
    pub path: &'a Path,
    /// Must be [`WorkspaceMode::CurrentDirectory`]; never inferred.
    pub workspace_mode: WorkspaceMode,
    /// Must be [`EffectProfile::CurrentDirectory`]; never inferred.
    pub effect_profile: EffectProfile,
    /// Safe-settings object or full `config` record. Absent opt-in is false.
    pub settings: &'a Value,
    /// Durable one-shot approve evidence. Deny/text/absent is not consent.
    pub approval: Option<&'a InteractionResponseEvidence>,
}

/// Admitted current-directory cwd. Isolation is always [`IsolationLevel::BestEffort`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CurrentDirectoryAdmission {
    /// Validated existing directory used as the spawn cwd.
    pub cwd: PathBuf,
    /// Always [`IsolationLevel::BestEffort`]. Never [`IsolationLevel::Enforced`].
    pub isolation: IsolationLevel,
}

impl CurrentDirectoryAdmission {
    fn best_effort(cwd: PathBuf) -> Self {
        Self {
            cwd,
            isolation: IsolationLevel::BestEffort,
        }
    }

    /// Isolation recorded for this hatch. Always best-effort.
    #[must_use]
    pub const fn isolation(&self) -> IsolationLevel {
        IsolationLevel::BestEffort
    }

    /// Attempt columns for a hatch admission. Isolation is never `ENFORCED`.
    #[must_use]
    pub fn attempt_spec(
        &self,
        adapter_instance_id: impl Into<String>,
        adapter_version: impl Into<String>,
        config_digest: impl Into<String>,
    ) -> crate::storage::AttemptSpec {
        crate::storage::AttemptSpec {
            effect_profile: EffectProfile::CurrentDirectory.as_str().into(),
            isolation_level: IsolationLevel::BestEffort.as_str().into(),
            retry_class: "AMBIGUOUS_AFTER_DISPATCH".into(),
            adapter_instance_id: adapter_instance_id.into(),
            adapter_version: adapter_version.into(),
            config_version: 1,
            config_digest: config_digest.into(),
            worktree_id: None,
        }
    }
}

/// A durably registered, unique detached worktree prepared for one attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedWorktree {
    /// Mesh-generated unique worktree id.
    pub worktree_id: String,
    /// Task the worktree is registered for.
    pub task_id: String,
    /// Canonical absolute worktree path inside the mesh worktrees root.
    pub path: PathBuf,
    /// Canonical top-level directory of the source checkout.
    pub repo_working_root: PathBuf,
    /// Canonical common Git directory of the source repository.
    pub repo_common_dir: PathBuf,
    /// Pinned base commit oid the worktree was created at.
    pub base_oid: String,
    /// Preparation timestamp (UTC microseconds).
    pub prepared_at_us: i64,
}

/// Typed worktree lifecycle failure.
#[derive(Debug, Error)]
pub enum WorktreeError {
    #[error("git executable was not found on PATH")]
    GitProgramMissing,
    #[error("path is not a Git repository: {0}")]
    NotAGitRepository(PathBuf),
    #[error("bare Git repository cannot host a worktree: {0}")]
    BareRepository(PathBuf),
    #[error("repository has no commits yet (unborn HEAD): {0}")]
    UnbornRepository(PathBuf),
    #[error("a {operation} is in progress and must be finished or aborted first: {path}")]
    OperationInProgress {
        operation: GitOperation,
        path: PathBuf,
    },
    #[error("requested base commit does not resolve to a commit: {requested}")]
    MissingBaseCommit { requested: String },
    #[error("invalid base reference (must be nonempty and not start with '-'): {0}")]
    InvalidBaseReference(String),
    #[error("repository identity changed since admission (expected {expected}, now {actual})")]
    RepositoryChanged { expected: PathBuf, actual: PathBuf },
    #[error("working tree is not clean: {0}")]
    DirtyWorkspace(Box<DirtySummary>),
    #[error(
        "current-directory escape hatch requires workspace.mode=current_directory and effect_profile=CURRENT_DIRECTORY"
    )]
    CurrentDirectoryRequestMismatch,
    #[error("current-directory escape hatch is disabled (allow_current_directory is not true)")]
    CurrentDirectoryDisabled,
    #[error("current-directory escape hatch requires a durable one-shot approval")]
    CurrentDirectoryApprovalRequired,
    #[error("current-directory path is not an existing directory: {0}")]
    CurrentDirectoryNotADirectory(PathBuf),
    #[error("current-directory path contains a junction or reparse point: {0}")]
    CurrentDirectoryReparse(PathBuf),
    #[error("worktree path escaped the mesh worktrees root: {0}")]
    PathEscapedWorktreesRoot(PathBuf),
    #[error("worktree is not owned by this manager: {0}")]
    WorktreeNotOwned(String),
    #[error("worktree is no longer present: {0}")]
    WorktreeMissing(String),
    #[error("worktree was modified outside the mesh; refusing destructive repair: {0}")]
    ExternalModification(String),
    #[error("Git protocol violation while parsing machine output: {0}")]
    ProtocolViolation(String),
    #[error("{kind} output exceeded the {limit}-byte bound")]
    OutputTruncated { kind: &'static str, limit: usize },
    #[error("git {command} failed (exit {exit_code:?}): {stderr}")]
    GitCommandFailed {
        command: &'static str,
        exit_code: Option<i32>,
        stderr: String,
    },
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// The `worktree` module result alias.
pub type Result<T> = std::result::Result<T, WorktreeError>;

/// Immutable resolved Git executable discovered from `PATH`.
#[derive(Clone, Debug)]
struct GitProgram(PathBuf);

impl GitProgram {
    /// Resolves `git.exe` (or `git`) from `PATH`. Quoted `PATH` entries are
    /// tolerated. The result is cached for the manager lifetime.
    fn discover() -> Result<Self> {
        let path_var = std::env::var_os("PATH").unwrap_or_default();
        for directory in std::env::split_paths(&path_var) {
            let directory = strip_quotes(directory);
            for name in ["git.exe", "git"] {
                let candidate = directory.join(name);
                if candidate.is_file() {
                    return Ok(Self(candidate));
                }
            }
        }
        Err(WorktreeError::GitProgramMissing)
    }

    /// Runs one bounded Git child process.
    ///
    /// The environment is an explicit allowlist plus `GIT_TERMINAL_PROMPT=0`,
    /// a disabled pager, and a fixed locale so machine output stays stable.
    /// stdout and stderr are drained concurrently and capped; exceeding the
    /// cap is reported as a typed truncation flag, never a hang or an
    /// unbounded allocation.
    ///
    /// # Panics
    ///
    /// Only if the piped stdout/stderr handles configured above are missing,
    /// which is a programming error.
    fn run(&self, cwd: &Path, args: &[OsString], stdout_cap: usize) -> Result<GitRun> {
        let mut command = Command::new(&self.0);
        command
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();
        for (key, value) in inherited_environment() {
            command.env(key, value);
        }
        command
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_PAGER", "cat")
            .env("LC_ALL", "C");
        #[cfg(windows)]
        command.creation_flags(CREATE_NO_WINDOW);

        let mut child = command.spawn()?;
        let stdout = child.stdout.take().expect("stdout was piped");
        let stderr = child.stderr.take().expect("stderr was piped");
        let stdout_reader = thread::spawn(move || capture(stdout, stdout_cap));
        let stderr_reader = thread::spawn(move || capture(stderr, MAX_STDERR_BYTES));
        let status = child.wait()?;
        let (stdout, stdout_truncated) = stdout_reader
            .join()
            .map_err(|_| WorktreeError::Io(std::io::Error::other("git stdout reader panicked")))?;
        let (stderr, stderr_truncated) = stderr_reader
            .join()
            .map_err(|_| WorktreeError::Io(std::io::Error::other("git stderr reader panicked")))?;
        Ok(GitRun {
            status,
            stdout,
            stdout_truncated,
            stderr,
            stderr_truncated,
        })
    }
}

fn strip_quotes(mut path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if text.len() >= 2 && text.starts_with('"') && text.ends_with('"') {
        path = PathBuf::from(&text[1..text.len() - 1]);
    }
    path
}

/// Result of one bounded Git child process invocation.
struct GitRun {
    status: ExitStatus,
    stdout: Vec<u8>,
    stdout_truncated: bool,
    stderr: Vec<u8>,
    stderr_truncated: bool,
}

impl GitRun {
    fn success(&self) -> bool {
        self.status.success()
    }

    fn ensure_success(self, command: &'static str) -> Result<Self> {
        if self.success() {
            Ok(self)
        } else {
            Err(self.failure(command))
        }
    }

    fn failure(&self, command: &'static str) -> WorktreeError {
        let mut stderr = String::from_utf8_lossy(&self.stderr).trim_end().to_string();
        if self.stderr_truncated {
            stderr.push_str("... (truncated)");
        }
        WorktreeError::GitCommandFailed {
            command,
            exit_code: self.status.code(),
            stderr,
        }
    }

    fn stdout_line(&self, command: &'static str) -> Result<String> {
        let text = std::str::from_utf8(&self.stdout).map_err(|_| {
            WorktreeError::ProtocolViolation("git output is not valid UTF-8".into())
        })?;
        let line = text.lines().next().ok_or_else(|| {
            WorktreeError::ProtocolViolation(format!("git {command} returned no output"))
        })?;
        Ok(line.trim().to_string())
    }
}

/// Per-repository administrative lock registry keyed by the canonical common
/// directory. Weak entries are pruned once no one holds the lock.
#[derive(Default)]
struct AdminLockRegistry(Mutex<BTreeMap<PathBuf, Weak<Mutex<()>>>>);

impl AdminLockRegistry {
    fn acquire(&self, key: &Path) -> Arc<Mutex<()>> {
        let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(lock) = map.get(key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        map.insert(key.to_path_buf(), Arc::downgrade(&lock));
        lock
    }
}

/// In-process ownership record of every worktree this manager prepared.
#[derive(Default)]
struct PreparedRegistry {
    map: Mutex<BTreeMap<String, PreparedWorktree>>,
    removed: Mutex<BTreeSet<String>>,
}

impl PreparedRegistry {
    fn lock(&self) -> MutexGuard<'_, BTreeMap<String, PreparedWorktree>> {
        self.map.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn is_removed(&self, worktree_id: &str) -> bool {
        self.removed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(worktree_id)
    }

    fn mark_removed(&self, worktree_id: &str) {
        self.removed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(worktree_id.to_string());
    }
}

/// Owns mesh worktree preparation, evidence capture, and path-safe cleanup.
///
/// All worktree roots live under `<data_root>/worktrees`. One manager per
/// daemon generation owns the administrative lock registry and the
/// prepared-worktree ownership records.
#[derive(Clone)]
pub struct WorktreeManager {
    worktrees_root: PathBuf,
    writer: WriterHandle,
    git: GitProgram,
    admin_locks: Arc<AdminLockRegistry>,
    prepared: Arc<PreparedRegistry>,
}

impl WorktreeManager {
    /// Creates the manager, resolving `git.exe` from `PATH` and creating the
    /// mesh worktrees directory under the configured data root.
    ///
    /// # Errors
    ///
    /// Fails when `git` cannot be resolved from `PATH`, when the data root
    /// cannot be canonicalized, or when the worktrees directory cannot be
    /// created.
    pub fn new(data_root: impl AsRef<Path>, writer: WriterHandle) -> Result<Self> {
        Self::with_git(data_root, writer, GitProgram::discover()?)
    }

    fn with_git(
        data_root: impl AsRef<Path>,
        writer: WriterHandle,
        git: GitProgram,
    ) -> Result<Self> {
        let worktrees_root = data_root.as_ref().join("worktrees");
        fs::create_dir_all(&worktrees_root)?;
        let worktrees_root = worktrees_root.canonicalize()?;
        Ok(Self {
            worktrees_root,
            writer,
            git,
            admin_locks: Arc::default(),
            prepared: Arc::default(),
        })
    }

    /// The canonical root directory that owns every mesh worktree.
    #[must_use]
    pub fn worktrees_root(&self) -> &Path {
        &self.worktrees_root
    }

    /// Looks up a previously prepared worktree record.
    #[must_use]
    pub fn prepared(&self, worktree_id: &str) -> Option<PreparedWorktree> {
        self.prepared.lock().get(worktree_id).cloned()
    }

    /// Runs `f` while holding the per-repository administrative lock for the
    /// canonical common directory. Mesh-owned worktree add/remove operations
    /// for one repository are serialized; distinct repositories and
    /// already-created worktrees proceed concurrently.
    pub(crate) fn with_admin_lock<T>(
        &self,
        common_dir: &Path,
        f: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        let lock = self.admin_locks.acquire(common_dir);
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        f()
    }

    /// Canonically admits a source checkout for a normal write task.
    ///
    /// Rejects non-Git paths, bare repositories, in-progress merge/rebase/
    /// cherry-pick/revert operations, unborn repositories, missing base
    /// commits, and any dirty tracked or untracked state. The resolved base is
    /// a full commit object id; the returned admission is re-verified again
    /// inside [`WorktreeManager::prepare_admitted`] before the worktree is
    /// created.
    ///
    /// # Errors
    ///
    /// See the [`WorktreeError`] variants; each rejection is actionable and
    /// typed.
    pub fn admit_repository(&self, path: &Path, base_ref: &str) -> Result<RepoAdmission> {
        let user_path = path.canonicalize().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                WorktreeError::NotAGitRepository(path.to_path_buf())
            } else {
                WorktreeError::Io(error)
            }
        })?;

        // Repository identity first: `--git-common-dir` succeeds for both
        // normal and bare repositories and fails everywhere else.
        let common_raw = match self
            .git
            .run(
                &user_path,
                &[s("rev-parse"), s("--git-common-dir")],
                MAX_LISTING_BYTES,
            )?
            .ensure_success("rev-parse --git-common-dir")
        {
            Ok(run) => run.stdout_line("rev-parse --git-common-dir")?,
            Err(_) => return Err(WorktreeError::NotAGitRepository(path.to_path_buf())),
        };
        let common_dir = if Path::new(&common_raw).is_absolute() {
            PathBuf::from(&common_raw)
        } else {
            user_path.join(&common_raw)
        }
        .canonicalize()?;

        let is_bare = self
            .git
            .run(
                &user_path,
                &[s("rev-parse"), s("--is-bare-repository")],
                MAX_LISTING_BYTES,
            )?
            .ensure_success("rev-parse --is-bare-repository")?
            .stdout_line("rev-parse --is-bare-repository")?;
        match is_bare.as_str() {
            "false" => {}
            "true" => return Err(WorktreeError::BareRepository(user_path)),
            other => {
                return Err(WorktreeError::ProtocolViolation(format!(
                    "unexpected --is-bare-repository answer {other:?}"
                )));
            }
        }

        let top_level = match self
            .git
            .run(
                &user_path,
                &[s("rev-parse"), s("--show-toplevel")],
                MAX_LISTING_BYTES,
            )?
            .ensure_success("rev-parse --show-toplevel")
        {
            Ok(run) => run.stdout_line("rev-parse --show-toplevel")?,
            Err(_) => return Err(WorktreeError::NotAGitRepository(user_path)),
        };
        let top_level_path = PathBuf::from(&top_level);
        let working_root = PathBuf::from(top_level).canonicalize().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                WorktreeError::NotAGitRepository(top_level_path.clone())
            } else {
                WorktreeError::Io(error)
            }
        })?;

        if let Some((operation, marker)) = self.detect_in_progress_operation(&working_root)? {
            return Err(WorktreeError::OperationInProgress {
                operation,
                path: marker,
            });
        }

        let head_run = self
            .git
            .run(
                &working_root,
                &[s("rev-parse"), s("--verify"), s("HEAD^{commit}")],
                MAX_LISTING_BYTES,
            )?
            .ensure_success("rev-parse HEAD");
        if head_run.is_err() {
            return Err(WorktreeError::UnbornRepository(working_root));
        }

        let base_oid = self.resolve_base_oid(&working_root, base_ref)?;

        self.require_clean_status(&working_root)?;

        Ok(RepoAdmission {
            working_root,
            common_dir,
            base_oid,
        })
    }

    /// Admits the disabled-by-default current-directory escape hatch.
    ///
    /// Both gates are required: global `allow_current_directory` and a durable
    /// one-shot approve, plus an explicit `workspace.mode=current_directory`
    /// and `effect_profile=CURRENT_DIRECTORY`. This is never selected from a
    /// failed [`WorktreeManager::admit_repository`] call. Isolation is always
    /// [`IsolationLevel::BestEffort`]. No Git worktree is created.
    ///
    /// # Errors
    ///
    /// Rejects a mismatched mode/profile, a disabled or missing opt-in, a
    /// missing/non-approve interaction, a missing/non-directory path, and any
    /// junction or reparse hop on the requested path.
    pub fn admit_current_directory(
        &self,
        request: &CurrentDirectoryRequest<'_>,
    ) -> Result<CurrentDirectoryAdmission> {
        let admission = admit_current_directory_escape(request)?;
        debug_assert_eq!(admission.isolation, IsolationLevel::BestEffort);
        debug_assert_ne!(admission.isolation, IsolationLevel::Enforced);
        Ok(admission)
    }

    /// Requires `git status --porcelain=v1 -z` to report an empty workspace
    /// and rejects any dirty state with the typed summary.
    fn require_clean_status(&self, cwd: &Path) -> Result<()> {
        let status_run = self
            .git
            .run(
                cwd,
                &[
                    s("status"),
                    s("--porcelain=v1"),
                    s("-z"),
                    s("--untracked-files=all"),
                ],
                MAX_LISTING_BYTES,
            )?
            .ensure_success("status --porcelain")?;
        if status_run.stdout_truncated {
            return Err(WorktreeError::OutputTruncated {
                kind: "git status",
                limit: MAX_LISTING_BYTES,
            });
        }
        let entries = parse_porcelain_z(&status_run.stdout)?;
        if !entries.is_empty() {
            return Err(WorktreeError::DirtyWorkspace(Box::new(
                DirtySummary::from_entries(&entries),
            )));
        }
        Ok(())
    }

    /// Resolves `base_ref` to a full commit object id, rejecting invalid
    /// syntax and non-commit resolutions.
    fn resolve_base_oid(&self, working_root: &Path, base_ref: &str) -> Result<String> {
        if base_ref.is_empty() || base_ref.starts_with('-') {
            return Err(WorktreeError::InvalidBaseReference(base_ref.to_string()));
        }
        let spec = format!("{base_ref}^{{commit}}");
        let run = match self
            .git
            .run(
                working_root,
                &[
                    s("rev-parse"),
                    s("--verify"),
                    s("--end-of-options"),
                    s(&spec),
                ],
                MAX_LISTING_BYTES,
            )?
            .ensure_success("rev-parse --verify")
        {
            Ok(run) => run,
            Err(error) => {
                // A ref that does not resolve to a commit is the actionable
                // admission rejection, not a transport failure.
                let WorktreeError::GitCommandFailed { exit_code, .. } = &error else {
                    return Err(error);
                };
                return if exit_code == &Some(128) {
                    Err(WorktreeError::MissingBaseCommit {
                        requested: base_ref.to_string(),
                    })
                } else {
                    Err(error)
                };
            }
        };
        if run.stdout_truncated {
            return Err(WorktreeError::OutputTruncated {
                kind: "git rev-parse",
                limit: MAX_LISTING_BYTES,
            });
        }
        let oid = run.stdout_line("rev-parse --verify")?;
        if !valid_oid(&oid) {
            return Err(WorktreeError::ProtocolViolation(format!(
                "rev-parse returned a non-commit object id {oid:?}"
            )));
        }
        Ok(oid)
    }

    /// Detects in-progress repository operations via their Git directory
    /// markers, using `--path-format=absolute` so linked-worktree layouts are
    /// resolved correctly.
    fn detect_in_progress_operation(
        &self,
        working_root: &Path,
    ) -> Result<Option<(GitOperation, PathBuf)>> {
        for (marker, operation) in [
            ("MERGE_HEAD", GitOperation::Merge),
            ("rebase-merge", GitOperation::Rebase),
            ("rebase-apply", GitOperation::Rebase),
        ] {
            let marker_path = self.git_path(working_root, marker)?;
            if marker_path.exists() {
                return Ok(Some((operation, marker_path)));
            }
        }
        let sequencer = self.git_path(working_root, "sequencer")?;
        if sequencer.exists() {
            let cherry_pick = self.git_path(working_root, "CHERRY_PICK_HEAD")?;
            let revert = self.git_path(working_root, "REVERT_HEAD")?;
            let operation = if cherry_pick.exists() {
                GitOperation::CherryPick
            } else if revert.exists() {
                GitOperation::Revert
            } else {
                GitOperation::Sequencer
            };
            return Ok(Some((operation, sequencer)));
        }
        Ok(None)
    }

    fn git_path(&self, working_root: &Path, marker: &str) -> Result<PathBuf> {
        let raw = self
            .git
            .run(
                working_root,
                &[
                    s("rev-parse"),
                    s("--path-format=absolute"),
                    s("--git-path"),
                    s(marker),
                ],
                MAX_LISTING_BYTES,
            )?
            .ensure_success("rev-parse --git-path")?
            .stdout_line("rev-parse --git-path")?;
        Ok(PathBuf::from(raw))
    }

    /// Admits `repo_path` and immediately prepares a worktree from the
    /// resulting pinned admission.
    ///
    /// # Errors
    ///
    /// Any admission error, plus the preparation errors documented on
    /// [`WorktreeManager::prepare_admitted`].
    pub fn prepare_worktree(
        &self,
        task_id: &str,
        repo_path: &Path,
        base_ref: &str,
        now_us: i64,
    ) -> Result<PreparedWorktree> {
        let admission = self.admit_repository(repo_path, base_ref)?;
        self.prepare_admitted(task_id, &admission, now_us)
    }

    /// Creates one unique detached worktree at the pinned base commit and
    /// registers it durably for the task.
    ///
    /// The source repository identity, base object availability, and
    /// cleanliness are re-verified before the worktree is created. Creation,
    /// durable registration, and (on registration failure) removal all run
    /// under the per-repository administrative lock. A failed attempt's
    /// worktree is never reused: every call allocates a fresh `UUID`-named
    /// directory under the mesh worktrees root.
    ///
    /// # Errors
    ///
    /// Fails when re-verification fails, when `git worktree add` fails, or
    /// when durable registration through the sole writer fails. A
    /// registration failure also removes the freshly created worktree before
    /// returning.
    pub fn prepare_admitted(
        &self,
        task_id: &str,
        admission: &RepoAdmission,
        now_us: i64,
    ) -> Result<PreparedWorktree> {
        self.reverify_admission(admission)?;
        let worktree_id = format!("wt-{}", Uuid::new_v4());
        let path = self.worktrees_root.join(&worktree_id);
        // `path` carries Rust's canonical verbatim prefix; strip it for the
        // Git argv boundary. The writer re-canonicalizes on registration, so
        // the durable row keeps the canonical form.
        let path_arg = git_arg_path(&path);

        self.with_admin_lock(&admission.common_dir, || {
            self.git
                .run(
                    &admission.working_root,
                    &[
                        s("worktree"),
                        s("add"),
                        s("--detach"),
                        path_arg.clone(),
                        s(&admission.base_oid),
                    ],
                    MAX_LISTING_BYTES,
                )?
                .ensure_success("worktree add")?;
            match self.writer.register_worktree(
                &worktree_id,
                task_id,
                path.to_string_lossy().as_ref(),
                now_us,
            ) {
                Ok(()) => Ok(()),
                Err(error) => {
                    // The directory was created by this critical section but
                    // is not durably owned; remove it so no unregistered
                    // mesh worktree can linger.
                    let _ = self
                        .git
                        .run(
                            &admission.working_root,
                            &[s("worktree"), s("remove"), s("--force"), path_arg.clone()],
                            MAX_LISTING_BYTES,
                        )
                        .and_then(|run| run.ensure_success("worktree remove"));
                    Err(WorktreeError::Storage(error))
                }
            }
        })?;

        let canonical = path.canonicalize()?;
        if !canonical.starts_with(&self.worktrees_root) {
            return Err(WorktreeError::PathEscapedWorktreesRoot(canonical));
        }
        let prepared = PreparedWorktree {
            worktree_id: worktree_id.clone(),
            task_id: task_id.to_string(),
            path: canonical,
            repo_working_root: admission.working_root.clone(),
            repo_common_dir: admission.common_dir.clone(),
            base_oid: admission.base_oid.clone(),
            prepared_at_us: now_us,
        };
        self.prepared.lock().insert(worktree_id, prepared.clone());
        Ok(prepared)
    }

    /// Re-verifies that the admitted repository still has the same identity,
    /// still contains the pinned base object, and is still clean. This is the
    /// per-attempt gate between admission and worktree creation.
    fn reverify_admission(&self, admission: &RepoAdmission) -> Result<()> {
        if !admission.working_root.is_dir() {
            return Err(WorktreeError::RepositoryChanged {
                expected: admission.common_dir.clone(),
                actual: admission.working_root.clone(),
            });
        }
        let common_raw = self
            .git
            .run(
                &admission.working_root,
                &[s("rev-parse"), s("--git-common-dir")],
                MAX_LISTING_BYTES,
            )?
            .ensure_success("rev-parse --git-common-dir")?
            .stdout_line("rev-parse --git-common-dir")?;
        let common = if Path::new(&common_raw).is_absolute() {
            PathBuf::from(&common_raw)
        } else {
            admission.working_root.join(&common_raw)
        }
        .canonicalize()?;
        if common != admission.common_dir {
            return Err(WorktreeError::RepositoryChanged {
                expected: admission.common_dir.clone(),
                actual: common,
            });
        }
        let head_run = self
            .git
            .run(
                &admission.working_root,
                &[s("rev-parse"), s("--verify"), s("HEAD^{commit}")],
                MAX_LISTING_BYTES,
            )?
            .ensure_success("rev-parse HEAD");
        if head_run.is_err() {
            return Err(WorktreeError::UnbornRepository(
                admission.working_root.clone(),
            ));
        }
        let has_base = self
            .git
            .run(
                &admission.working_root,
                &[s("cat-file"), s("-e"), s(&admission.base_oid)],
                MAX_LISTING_BYTES,
            )?
            .success();
        if !has_base {
            return Err(WorktreeError::MissingBaseCommit {
                requested: admission.base_oid.clone(),
            });
        }
        self.require_clean_status(&admission.working_root)?;
        Ok(())
    }

    /// Captures finalization evidence from an owned attempt worktree:
    /// strict `git status`, committed and working diffs, the untracked
    /// artifact manifest with byte lengths, and the resulting tree metadata.
    ///
    /// The worktree is never mutated by capture. Preservation on failure or
    /// uncertainty is the caller's policy; this module only reads.
    ///
    /// # Errors
    ///
    /// Fails when the worktree is not owned by this manager, has been removed,
    /// or was modified outside the mesh. Git failures surface with bounded
    /// stderr diagnostics.
    pub fn capture_evidence(&self, worktree_id: &str) -> Result<FinalizationEvidence> {
        let record = self
            .prepared
            .lock()
            .get(worktree_id)
            .cloned()
            .ok_or_else(|| WorktreeError::WorktreeNotOwned(worktree_id.to_string()))?;
        if self.prepared.is_removed(worktree_id) {
            return Err(WorktreeError::WorktreeMissing(worktree_id.to_string()));
        }
        if !record.path.is_dir() || !record.path.join(".git").is_file() {
            return Err(WorktreeError::ExternalModification(format!(
                "worktree {worktree_id} no longer exists or lost its .git marker"
            )));
        }
        let cwd = &record.path;

        let head_oid = self.rev_parse_line(cwd, &[s("rev-parse"), s("--verify"), s("HEAD")])?;
        if !valid_oid(&head_oid) {
            return Err(WorktreeError::ProtocolViolation(format!(
                "rev-parse HEAD returned {head_oid:?}"
            )));
        }
        let head_tree_oid =
            self.rev_parse_line(cwd, &[s("rev-parse"), s("--verify"), s("HEAD^{tree}")])?;
        if !valid_oid(&head_tree_oid) {
            return Err(WorktreeError::ProtocolViolation(format!(
                "rev-parse HEAD^tree returned {head_tree_oid:?}"
            )));
        }

        let tree_listing = self
            .git
            .run(
                cwd,
                &[s("ls-tree"), s("-r"), s("-z"), s("HEAD^{tree}")],
                MAX_LISTING_BYTES,
            )?
            .ensure_success("ls-tree")?;
        if tree_listing.stdout_truncated {
            return Err(WorktreeError::OutputTruncated {
                kind: "git ls-tree",
                limit: MAX_LISTING_BYTES,
            });
        }
        let tree_entries = parse_ls_tree_z(&tree_listing.stdout)?;

        let status_run = self
            .git
            .run(
                cwd,
                &[
                    s("status"),
                    s("--porcelain=v1"),
                    s("-z"),
                    s("--untracked-files=all"),
                ],
                MAX_LISTING_BYTES,
            )?
            .ensure_success("status --porcelain")?;
        if status_run.stdout_truncated {
            return Err(WorktreeError::OutputTruncated {
                kind: "git status",
                limit: MAX_LISTING_BYTES,
            });
        }
        let status_entries = parse_porcelain_z(&status_run.stdout)?;

        let untracked_listing = self
            .git
            .run(
                cwd,
                &[
                    s("ls-files"),
                    s("--others"),
                    s("--exclude-standard"),
                    s("-z"),
                ],
                MAX_LISTING_BYTES,
            )?
            .ensure_success("ls-files --others")?;
        if untracked_listing.stdout_truncated {
            return Err(WorktreeError::OutputTruncated {
                kind: "git ls-files",
                limit: MAX_LISTING_BYTES,
            });
        }
        let untracked_files = Self::artifact_manifest(cwd, &untracked_listing.stdout)?;

        let committed_diff =
            self.diff_evidence(cwd, &[s("diff"), s(&record.base_oid), s("HEAD")])?;
        let working_diff = self.diff_evidence(cwd, &[s("diff"), s("HEAD")])?;

        Ok(FinalizationEvidence {
            worktree_id: worktree_id.to_string(),
            path: record.path.to_string_lossy().into_owned(),
            base_oid: record.base_oid,
            head_oid,
            head_tree_oid,
            tree_entries,
            status_entries,
            untracked_files,
            committed_diff,
            working_diff,
        })
    }

    fn rev_parse_line(&self, cwd: &Path, args: &[OsString]) -> Result<String> {
        let run = self.git.run(cwd, args, MAX_LISTING_BYTES)?;
        run.ensure_success("rev-parse")?.stdout_line("rev-parse")
    }

    fn diff_evidence(&self, cwd: &Path, args: &[OsString]) -> Result<Option<DiffEvidence>> {
        let run = self
            .git
            .run(cwd, args, MAX_DIFF_BYTES)?
            .ensure_success("diff")?;
        if run.stdout.is_empty() {
            return Ok(None);
        }
        Ok(Some(DiffEvidence {
            bytes: run.stdout,
            truncated: run.stdout_truncated,
        }))
    }

    fn artifact_manifest(cwd: &Path, listing: &[u8]) -> Result<Vec<ArtifactFile>> {
        let mut artifacts = Vec::new();
        for token in listing.split(|byte| *byte == 0) {
            if token.is_empty() {
                continue;
            }
            let relative = std::str::from_utf8(token).map_err(|_| {
                WorktreeError::ProtocolViolation("untracked path is not valid UTF-8".into())
            })?;
            let absolute = join_verified(cwd, relative)?;
            let metadata = absolute.metadata()?;
            let is_directory = metadata.is_dir();
            artifacts.push(ArtifactFile {
                path: relative.to_string(),
                byte_length: if is_directory { 0 } else { metadata.len() },
                is_directory,
            });
        }
        Ok(artifacts)
    }

    /// Removes an owned attempt worktree.
    ///
    /// Only a path recorded as owned by the exact attempt in this manager's
    /// registry is ever removed. Before removal, the filesystem state, the
    /// `.git` marker, the canonical path, and the source repository's
    /// `git worktree list` must all agree. External Git GC or manual removal
    /// is diagnosed as [`WorktreeError::ExternalModification`] and never
    /// triggers destructive repair. A broad `git worktree prune` is never
    /// invoked; the worktrees of other attempts and of the user are never
    /// touched.
    ///
    /// # Errors
    ///
    /// [`WorktreeError::WorktreeNotOwned`] for ids this manager never
    /// prepared, [`WorktreeError::ExternalModification`] when the filesystem
    /// and Git disagree, and bounded Git failures otherwise.
    pub fn remove_worktree(&self, worktree_id: &str) -> Result<()> {
        let record = self
            .prepared
            .lock()
            .get(worktree_id)
            .cloned()
            .ok_or_else(|| WorktreeError::WorktreeNotOwned(worktree_id.to_string()))?;

        self.with_admin_lock(&record.repo_common_dir, || {
            if self.prepared.is_removed(worktree_id) {
                return Ok(());
            }
            self.verify_intact_for_removal(&record)?;
            self.git
                .run(
                    &record.repo_working_root,
                    &[
                        s("worktree"),
                        s("remove"),
                        s("--force"),
                        git_arg_path(&record.path),
                    ],
                    MAX_LISTING_BYTES,
                )?
                .ensure_success("worktree remove")?;
            // Removal must converge: the directory is gone and the source
            // repository no longer records the worktree. Anything else is
            // external interference and is reported, never repaired.
            let still_listed =
                self.worktree_list_contains(&record.repo_working_root, &record.path)?;
            if record.path.exists() || still_listed {
                return Err(WorktreeError::ExternalModification(format!(
                    "worktree {worktree_id} did not converge to a removed state"
                )));
            }
            self.prepared.mark_removed(worktree_id);
            Ok(())
        })
    }

    /// Verifies that filesystem state, canonical path, and the source
    /// repository's worktree administration still agree about an owned
    /// worktree before it may be removed.
    fn verify_intact_for_removal(&self, record: &PreparedWorktree) -> Result<()> {
        if !record.path.is_dir() {
            return Err(WorktreeError::ExternalModification(format!(
                "worktree {} directory no longer exists",
                record.worktree_id
            )));
        }
        if !record.path.join(".git").is_file() {
            return Err(WorktreeError::ExternalModification(format!(
                "worktree {} lost its .git marker",
                record.worktree_id
            )));
        }
        let canonical = record.path.canonicalize()?;
        if canonical != record.path || !canonical.starts_with(&self.worktrees_root) {
            return Err(WorktreeError::ExternalModification(format!(
                "worktree {} path is no longer canonical or escaped the worktrees root",
                record.worktree_id
            )));
        }
        if !record.repo_working_root.is_dir() {
            return Err(WorktreeError::ExternalModification(format!(
                "source repository of worktree {} no longer exists",
                record.worktree_id
            )));
        }
        if !self.worktree_list_contains(&record.repo_working_root, &record.path)? {
            return Err(WorktreeError::ExternalModification(format!(
                "source repository no longer records worktree {}",
                record.worktree_id
            )));
        }
        Ok(())
    }

    fn worktree_list_contains(&self, repo_working_root: &Path, path: &Path) -> Result<bool> {
        let run = self
            .git
            .run(
                repo_working_root,
                &[s("worktree"), s("list"), s("--porcelain")],
                MAX_LISTING_BYTES,
            )?
            .ensure_success("worktree list")?;
        if run.stdout_truncated {
            return Err(WorktreeError::OutputTruncated {
                kind: "git worktree list",
                limit: MAX_LISTING_BYTES,
            });
        }
        for listed in parse_worktree_list(&run.stdout)? {
            let Ok(canonical) = listed.canonicalize() else {
                continue;
            };
            if canonical == path {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Runs one bounded Git child process through the resolved Git program.
    /// See [`GitProgram::run`] for the environment and cap contract.
    #[cfg(test)]
    fn run(&self, cwd: &Path, args: &[OsString], stdout_cap: usize) -> Result<GitRun> {
        self.git.run(cwd, args, stdout_cap)
    }
}

/// Builds a Git argv path from a canonical path.
///
/// Rust's `canonicalize` produces Windows verbatim (`\\?\`) paths, which
/// Git for Windows mangles into `//?/...` when used as arguments. Verbatim
/// prefixes are therefore stripped before the path crosses the argv boundary;
/// canonical comparison and containment checks keep using the verbatim form.
fn git_arg_path(path: &Path) -> OsString {
    let text = path.to_string_lossy();
    let stripped = text.strip_prefix(r"\\?\").unwrap_or(&text);
    OsString::from(stripped)
}

/// Builds one `OsString` argument from a UTF-8 string.
fn s(value: &str) -> OsString {
    OsString::from(value)
}

/// Drains a reader into memory while enforcing a hard byte cap. Bytes beyond
/// the cap are discarded (but still drained) so the child can never deadlock
/// on a full pipe and memory stays bounded.
fn capture(reader: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut reader = BufReader::new(reader);
    let mut out = Vec::new();
    let mut truncated = false;
    let mut buffer = [0u8; DRAIN_BUFFER_BYTES];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if !truncated {
                    let space = cap.saturating_sub(out.len());
                    out.extend_from_slice(&buffer[..count.min(space)]);
                    truncated = count > space;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    (out, truncated)
}

/// Returns the allowlisted environment for Git children.
fn inherited_environment() -> Vec<(OsString, OsString)> {
    std::env::vars_os()
        .filter(|(key, _)| {
            INHERITED_ENV_KEYS
                .iter()
                .any(|allowed| key.eq_ignore_ascii_case(OsStr::new(allowed)))
        })
        .collect()
}

fn protocol_violation(message: impl Into<String>) -> WorktreeError {
    WorktreeError::ProtocolViolation(message.into())
}

fn valid_oid(oid: &str) -> bool {
    (40..=64).contains(&oid.len()) && oid.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Joins a repository-relative path reported by Git onto a root, rejecting
/// absolute paths and `..` traversal as protocol violations.
fn join_verified(root: &Path, relative: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    let escaping = relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        });
    if escaping {
        return Err(protocol_violation(format!(
            "git reported an escaping path {}",
            relative.display()
        )));
    }
    Ok(root.join(relative))
}

enum PorcelainToken {
    Single(StatusEntry),
    Rename { x: char, y: char, path: String },
}

/// Strictly parses `git status --porcelain=v1 -z` output.
///
/// Every entry must start with two valid status letters followed by a space.
/// Rename/copy entries (`X` or `Y` in `R`/`C`) carry the destination path
/// followed by a second NUL-terminated token with the source path, matching
/// the observed wire layout (`R  <destination>\0<source>\0`). Anything else
/// is a protocol violation.
fn parse_porcelain_z(bytes: &[u8]) -> Result<Vec<StatusEntry>> {
    let mut entries = Vec::new();
    let mut tokens = bytes.split(|byte| *byte == 0);
    while let Some(token) = tokens.next() {
        if token.is_empty() {
            continue;
        }
        let token = parse_porcelain_token(token)?;
        match token {
            PorcelainToken::Single(entry) => entries.push(entry),
            PorcelainToken::Rename { x, y, path } => {
                let source = tokens
                    .next()
                    .filter(|source| !source.is_empty())
                    .ok_or_else(|| protocol_violation("truncated rename entry in git status"))?;
                let source = std::str::from_utf8(source)
                    .map_err(|_| protocol_violation("rename source path is not valid UTF-8"))?;
                entries.push(StatusEntry {
                    x,
                    y,
                    path,
                    orig_path: Some(source.to_string()),
                });
            }
        }
    }
    Ok(entries)
}

fn parse_porcelain_token(token: &[u8]) -> Result<PorcelainToken> {
    if token.len() < 4 {
        return Err(protocol_violation(format!(
            "porcelain entry too short: {token:?}"
        )));
    }
    let x = token[0];
    let y = token[1];
    if !PORCELAIN_X.contains(&x) || !PORCELAIN_Y.contains(&y) {
        return Err(protocol_violation(format!(
            "unexpected porcelain status code {}{}",
            x as char, y as char
        )));
    }
    if token[2] != b' ' {
        return Err(protocol_violation(
            "porcelain entry missing the code separator",
        ));
    }
    let path = std::str::from_utf8(&token[3..])
        .map_err(|_| protocol_violation("porcelain path is not valid UTF-8"))?
        .to_string();
    if matches!(x, b'R' | b'C') || matches!(y, b'R' | b'C') {
        Ok(PorcelainToken::Rename {
            x: x as char,
            y: y as char,
            path,
        })
    } else {
        Ok(PorcelainToken::Single(StatusEntry {
            x: x as char,
            y: y as char,
            path,
            orig_path: None,
        }))
    }
}

/// Strictly parses `git ls-tree -r -z` output: `<mode> <type> <oid>\t<path>\0`.
fn parse_ls_tree_z(bytes: &[u8]) -> Result<Vec<TreeEntry>> {
    let mut entries = Vec::new();
    for token in bytes.split(|byte| *byte == 0) {
        if token.is_empty() {
            continue;
        }
        let tab = token
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or_else(|| protocol_violation("ls-tree entry missing the tab separator"))?;
        let (meta, path) = token.split_at(tab);
        let path = std::str::from_utf8(&path[1..])
            .map_err(|_| protocol_violation("ls-tree path is not valid UTF-8"))?;
        let meta = std::str::from_utf8(meta)
            .map_err(|_| protocol_violation("ls-tree metadata is not valid UTF-8"))?;
        let mut parts = meta.split(' ');
        let mode = parts
            .next()
            .ok_or_else(|| protocol_violation("ls-tree entry missing the mode"))?;
        let object_type = parts
            .next()
            .ok_or_else(|| protocol_violation("ls-tree entry missing the object type"))?;
        let oid = parts
            .next()
            .ok_or_else(|| protocol_violation("ls-tree entry missing the object id"))?;
        if parts.next().is_some() {
            return Err(protocol_violation("ls-tree metadata has unexpected fields"));
        }
        if mode.len() != 6 || !mode.bytes().all(|byte| (b'0'..=b'7').contains(&byte)) {
            return Err(protocol_violation(format!(
                "ls-tree entry has invalid mode {mode:?}"
            )));
        }
        if !matches!(object_type, "blob" | "tree" | "commit") {
            return Err(protocol_violation(format!(
                "ls-tree entry has invalid object type {object_type:?}"
            )));
        }
        if !valid_oid(oid) {
            return Err(protocol_violation(format!(
                "ls-tree entry has invalid object id {oid:?}"
            )));
        }
        entries.push(TreeEntry {
            mode: mode.to_string(),
            object_type: object_type.to_string(),
            oid: oid.to_string(),
            path: path.to_string(),
        });
    }
    Ok(entries)
}

/// Parses `git worktree list --porcelain` into the listed worktree paths.
fn parse_worktree_list(bytes: &[u8]) -> Result<Vec<PathBuf>> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| protocol_violation("worktree list is not valid UTF-8"))?;
    Ok(text
        .lines()
        .filter_map(|line| line.strip_prefix("worktree "))
        .map(|path| PathBuf::from(path.trim_end()))
        .collect())
}

/// Dual-gate current-directory admission. Never creates a mesh worktree.
fn admit_current_directory_escape(
    request: &CurrentDirectoryRequest<'_>,
) -> Result<CurrentDirectoryAdmission> {
    if request.workspace_mode != WorkspaceMode::CurrentDirectory
        || request.effect_profile != EffectProfile::CurrentDirectory
    {
        return Err(WorktreeError::CurrentDirectoryRequestMismatch);
    }
    if !allow_current_directory(request.settings) {
        return Err(WorktreeError::CurrentDirectoryDisabled);
    }
    match request.approval {
        Some(evidence) if evidence.response_kind == InteractionResponseKind::Approve => {}
        Some(_) | None => return Err(WorktreeError::CurrentDirectoryApprovalRequired),
    }
    let cwd = validate_current_directory_path(request.path)?;
    Ok(CurrentDirectoryAdmission::best_effort(cwd))
}

fn validate_current_directory_path(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(WorktreeError::CurrentDirectoryNotADirectory(
            path.to_path_buf(),
        ));
    }
    let absolute = std::path::absolute(path)?;
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => current.push(component),
            Component::CurDir => {}
            Component::ParentDir => {
                current.pop();
            }
            Component::Normal(_) => {
                current.push(component);
                let metadata = fs::symlink_metadata(&current).map_err(|error| {
                    if error.kind() == std::io::ErrorKind::NotFound {
                        WorktreeError::CurrentDirectoryNotADirectory(current.clone())
                    } else {
                        WorktreeError::Io(error)
                    }
                })?;
                if metadata_is_reparse(&metadata) {
                    return Err(WorktreeError::CurrentDirectoryReparse(current));
                }
                if !metadata.is_dir() {
                    return Err(WorktreeError::CurrentDirectoryNotADirectory(current));
                }
            }
        }
    }
    let metadata = fs::symlink_metadata(&current).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            WorktreeError::CurrentDirectoryNotADirectory(current.clone())
        } else {
            WorktreeError::Io(error)
        }
    })?;
    if metadata_is_reparse(&metadata) {
        return Err(WorktreeError::CurrentDirectoryReparse(current));
    }
    if !metadata.is_dir() {
        return Err(WorktreeError::CurrentDirectoryNotADirectory(current));
    }
    Ok(current)
}

fn metadata_is_reparse(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::WriterHandle;
    use std::{
        process::Output,
        sync::{
            Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    const INSTALL_ID: &str = "install";

    fn git_binary() -> PathBuf {
        GitProgram::discover()
            .expect("git.exe must be available on PATH")
            .0
    }

    fn git_at(dir: &Path, args: &[&str]) -> Output {
        Command::new(git_binary())
            .args(args)
            .current_dir(dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("git must run")
    }

    fn git_ok(dir: &Path, args: &[&str]) {
        let output = git_at(dir, args);
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn make_repo(name: &str) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join(name);
        fs::create_dir_all(&repo).expect("repo dir");
        git_ok(temp.path(), &["init", "-q", &repo.to_string_lossy()]);
        git_ok(&repo, &["config", "user.name", "test"]);
        git_ok(&repo, &["config", "user.email", "test@example.invalid"]);
        git_ok(&repo, &["config", "commit.gpgsign", "false"]);
        (temp, repo)
    }

    fn commit_file(repo: &Path, relative: &str, content: &str) {
        let path = repo.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent dirs");
        }
        fs::write(&path, content).expect("file write");
        git_ok(repo, &["add", "--", relative]);
        git_ok(repo, &["commit", "-q", "-m", relative]);
    }

    fn head_oid(repo: &Path) -> String {
        let output = git_at(repo, &["rev-parse", "HEAD"]);
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .expect("utf8")
            .trim()
            .to_string()
    }

    fn tree_oid(repo: &Path) -> String {
        let output = git_at(repo, &["rev-parse", "HEAD^{tree}"]);
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .expect("utf8")
            .trim()
            .to_string()
    }

    fn manager(data_root: &Path) -> (WorktreeManager, WriterHandle) {
        let writer = WriterHandle::start_portable(data_root.to_path_buf(), INSTALL_ID, 1).unwrap();
        let manager =
            WorktreeManager::with_git(data_root, writer.clone(), GitProgram::discover().unwrap())
                .unwrap();
        (manager, writer)
    }

    /// Creates the durable task row that worktree registration references.
    /// The scheduler owns this step in production; tests exercise it directly
    /// because `worktrees.task_id` has a foreign key to `tasks`.
    fn ensure_task(writer: &WriterHandle, task_id: &str, now_us: i64) {
        writer
            .submit(
                "consumer",
                "delegate_task",
                format!("command-{task_id}"),
                format!("request-{task_id}").into_bytes(),
                task_id,
                None,
                now_us,
            )
            .unwrap();
    }

    fn durable_worktree_rows(data_root: &Path) -> Vec<(String, String, String, String)> {
        let connection = rusqlite::Connection::open(data_root.join("mesh.sqlite3")).unwrap();
        let mut statement = connection
            .prepare("SELECT worktree_id, task_id, path, state FROM worktrees ORDER BY worktree_id")
            .unwrap();
        let rows = statement
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap();
        rows.collect::<std::result::Result<Vec<_>, _>>().unwrap()
    }

    #[test]
    fn admission_accepts_clean_repo_and_pins_full_oid() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "one\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());

        let admission = manager.admit_repository(&repo, "HEAD").unwrap();
        assert_eq!(admission.working_root, repo.canonicalize().unwrap());
        assert_eq!(
            admission.common_dir,
            repo.join(".git").canonicalize().unwrap()
        );
        assert_eq!(admission.base_oid, head_oid(&repo));
        assert_eq!(admission.base_oid.len(), 40);
        assert!(
            admission
                .base_oid
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
    }

    #[test]
    fn admission_resolves_toplevel_from_subdirectory() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "one\n");
        let subdir = repo.join("sub").join("deep");
        fs::create_dir_all(&subdir).unwrap();
        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());

        let admission = manager.admit_repository(&subdir, "HEAD").unwrap();
        assert_eq!(admission.working_root, repo.canonicalize().unwrap());
        assert_eq!(admission.base_oid, head_oid(&repo));
    }

    #[test]
    fn admission_rejects_dirty_tracked_file() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "one\n");
        fs::write(repo.join("a.txt"), "modified\n").unwrap();
        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());

        let error = manager.admit_repository(&repo, "HEAD").unwrap_err();
        let WorktreeError::DirtyWorkspace(summary) = error else {
            panic!("expected DirtyWorkspace, got {error:?}");
        };
        assert_eq!(summary.unstaged, 1);
        assert_eq!(summary.staged, 0);
        assert_eq!(summary.untracked, 0);
        assert_eq!(summary.conflicted, 0);
        assert_eq!(summary.sample[0].path, "a.txt");
        assert_eq!(summary.sample[0].y, 'M');
    }

    #[test]
    fn admission_rejects_untracked_file() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "one\n");
        fs::write(repo.join("stray.bin"), [0u8, 1, 2]).unwrap();
        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());

        let error = manager.admit_repository(&repo, "HEAD").unwrap_err();
        let WorktreeError::DirtyWorkspace(summary) = error else {
            panic!("expected DirtyWorkspace, got {error:?}");
        };
        assert_eq!(summary.untracked, 1);
        assert_eq!(summary.sample[0].path, "stray.bin");
    }

    #[test]
    fn admission_rejects_unborn_repository() {
        let (_temp, repo) = make_repo("repo");
        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());

        let error = manager.admit_repository(&repo, "HEAD").unwrap_err();
        let WorktreeError::UnbornRepository(path) = error else {
            panic!("expected UnbornRepository, got {error:?}");
        };
        assert_eq!(path, repo.canonicalize().unwrap());
    }

    #[test]
    fn admission_rejects_missing_base_commit() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "one\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());

        let error = manager
            .admit_repository(&repo, "refs/heads/does-not-exist")
            .unwrap_err();
        let WorktreeError::MissingBaseCommit { requested } = error else {
            panic!("expected MissingBaseCommit, got {error:?}");
        };
        assert_eq!(requested, "refs/heads/does-not-exist");
    }

    #[test]
    fn admission_rejects_invalid_base_reference_syntax() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "one\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());

        for invalid in ["", "-junk"] {
            let error = manager.admit_repository(&repo, invalid).unwrap_err();
            let WorktreeError::InvalidBaseReference(got) = error else {
                panic!("expected InvalidBaseReference for {invalid:?}, got {error:?}");
            };
            assert_eq!(got, invalid);
        }
    }

    #[test]
    fn admission_rejects_non_git_path() {
        let empty = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());

        let error = manager.admit_repository(empty.path(), "HEAD").unwrap_err();
        let WorktreeError::NotAGitRepository(_) = error else {
            panic!("expected NotAGitRepository, got {error:?}");
        };
    }

    #[test]
    fn admission_rejects_bare_repository() {
        let temp = tempfile::tempdir().unwrap();
        let bare = temp.path().join("bare.git");
        fs::create_dir_all(&bare).unwrap();
        git_ok(
            temp.path(),
            &["init", "-q", "--bare", &bare.to_string_lossy()],
        );
        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());

        let error = manager.admit_repository(&bare, "HEAD").unwrap_err();
        let WorktreeError::BareRepository(path) = error else {
            panic!("expected BareRepository, got {error:?}");
        };
        assert_eq!(path, bare.canonicalize().unwrap());
    }

    #[test]
    fn admission_rejects_in_progress_conflicted_merge() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        git_ok(&repo, &["checkout", "-q", "-b", "side"]);
        commit_file(&repo, "a.txt", "side\n");
        git_ok(&repo, &["checkout", "-q", "master"]);
        commit_file(&repo, "a.txt", "master\n");
        let merge = git_at(&repo, &["merge", "side"]);
        assert!(!merge.status.success());

        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());
        let error = manager.admit_repository(&repo, "HEAD").unwrap_err();
        let WorktreeError::OperationInProgress {
            operation: GitOperation::Merge,
            ..
        } = error
        else {
            panic!("expected in-progress merge, got {error:?}");
        };
    }

    #[test]
    fn admission_rejects_in_progress_rebase() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        git_ok(&repo, &["checkout", "-q", "-b", "feature"]);
        commit_file(&repo, "a.txt", "feature\n");
        git_ok(&repo, &["checkout", "-q", "master"]);
        commit_file(&repo, "a.txt", "master\n");
        git_ok(&repo, &["checkout", "-q", "feature"]);
        let rebase = git_at(&repo, &["rebase", "master"]);
        assert!(!rebase.status.success());

        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());
        let error = manager.admit_repository(&repo, "HEAD").unwrap_err();
        let WorktreeError::OperationInProgress {
            operation: GitOperation::Rebase,
            ..
        } = error
        else {
            panic!("expected in-progress rebase, got {error:?}");
        };
        git_ok(&repo, &["rebase", "--abort"]);
    }

    #[test]
    fn prepare_pins_base_oid_across_branch_movement() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        let pinned = head_oid(&repo);
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        ensure_task(&writer, "task-1", 10);

        let prepared = manager
            .prepare_worktree("task-1", &repo, "HEAD", 10)
            .unwrap();
        assert_eq!(prepared.base_oid, pinned);
        assert_eq!(head_oid(&prepared.path), pinned);

        // Move the user's branch forward; the attempt worktree stays pinned
        // and the user's checkout is never mutated by the mesh.
        commit_file(&repo, "b.txt", "forward\n");
        assert_eq!(head_oid(&prepared.path), pinned);
        assert_ne!(head_oid(&repo), pinned);
        assert_eq!(head_oid(&prepared.path), prepared.base_oid);
    }

    #[test]
    fn prepare_creates_unique_detached_worktrees_for_distinct_attempts() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        ensure_task(&writer, "task-1", 10);
        ensure_task(&writer, "task-2", 10);

        let first = manager
            .prepare_worktree("task-1", &repo, "HEAD", 10)
            .unwrap();
        let second = manager
            .prepare_worktree("task-2", &repo, "HEAD", 11)
            .unwrap();
        assert_ne!(first.worktree_id, second.worktree_id);
        assert_ne!(first.path, second.path);
        assert!(first.path.starts_with(manager.worktrees_root()));
        assert!(second.path.starts_with(manager.worktrees_root()));
        for prepared in [&first, &second] {
            assert!(prepared.path.join(".git").is_file());
            let detach = git_at(&prepared.path, &["status", "--porcelain", "--branch"]);
            let text = String::from_utf8(detach.stdout).unwrap();
            assert!(
                text.starts_with("## HEAD (no branch)"),
                "expected detached HEAD, got {text:?}"
            );
        }
    }

    #[test]
    fn prepare_registers_durable_row_with_absolute_path() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        ensure_task(&writer, "task-1", 10);

        let prepared = manager
            .prepare_worktree("task-1", &repo, "HEAD", 10)
            .unwrap();
        let rows = durable_worktree_rows(data.path());
        assert_eq!(rows.len(), 1);
        let (worktree_id, task_id, path, state) = &rows[0];
        assert_eq!(worktree_id, &prepared.worktree_id);
        assert_eq!(task_id, "task-1");
        assert_eq!(path, &prepared.path.to_string_lossy());
        assert_eq!(state, "ACTIVE");
    }

    #[test]
    fn concurrent_prepares_are_serialized_per_repository() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        ensure_task(&writer, "task-0-0", 10);
        ensure_task(&writer, "task-0-1", 10);
        ensure_task(&writer, "task-1-0", 10);
        ensure_task(&writer, "task-1-1", 10);
        ensure_task(&writer, "task-2-0", 10);
        ensure_task(&writer, "task-2-1", 10);
        ensure_task(&writer, "task-3-0", 10);
        ensure_task(&writer, "task-3-1", 10);

        // The critical-section counter proves the per-repository
        // administrative lock serializes mesh-owned worktree operations.
        let in_section = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));
        let admission = manager.admit_repository(&repo, "HEAD").unwrap();
        let barrier = Arc::new(Barrier::new(4));
        let workers: Vec<_> = (0..4)
            .map(|index| {
                let manager = manager.clone();
                let admission = admission.clone();
                let repo = repo.clone();
                let in_section = Arc::clone(&in_section);
                let max_observed = Arc::clone(&max_observed);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    for attempt in 0..2 {
                        manager
                            .with_admin_lock(&admission.common_dir, || {
                                let current = in_section.fetch_add(1, Ordering::SeqCst) + 1;
                                max_observed.fetch_max(current, Ordering::SeqCst);
                                assert_eq!(current, 1, "admin lock must serialize");
                                thread::sleep(Duration::from_millis(5));
                                in_section.fetch_sub(1, Ordering::SeqCst);
                                Ok(())
                            })
                            .unwrap();
                        manager
                            .prepare_worktree(&format!("task-{index}-{attempt}"), &repo, "HEAD", 10)
                            .unwrap();
                    }
                })
            })
            .collect();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(max_observed.load(Ordering::SeqCst), 1);
        assert_eq!(durable_worktree_rows(data.path()).len(), 8);
    }

    #[test]
    fn admin_lock_is_keyed_by_common_directory_identity() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        let subdir = repo.join("nested");
        fs::create_dir_all(&subdir).unwrap();
        let (_temp2, other_repo) = make_repo("other");
        commit_file(&other_repo, "a.txt", "other\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());

        let from_root = manager.admit_repository(&repo, "HEAD").unwrap();
        let from_subdir = manager.admit_repository(&subdir, "HEAD").unwrap();
        let from_other = manager.admit_repository(&other_repo, "HEAD").unwrap();

        assert_eq!(from_root.common_dir, from_subdir.common_dir);
        assert_ne!(from_root.common_dir, from_other.common_dir);
        // The distinct repositories must not share a lock entry.
        assert!(!Arc::ptr_eq(
            &manager.admin_locks.acquire(&from_root.common_dir),
            &manager.admin_locks.acquire(&from_other.common_dir)
        ));
    }

    #[test]
    fn cleanup_refuses_non_owned_paths_and_ids() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        ensure_task(&writer, "task-1", 10);

        let prepared = manager
            .prepare_worktree("task-1", &repo, "HEAD", 10)
            .unwrap();

        // Unknown ids are refused.
        let error = manager.remove_worktree("wt-unknown").unwrap_err();
        let WorktreeError::WorktreeNotOwned(id) = error else {
            panic!("expected WorktreeNotOwned, got {error:?}");
        };
        assert_eq!(id, "wt-unknown");

        // A second manager (fresh ownership registry, same durable writer)
        // cannot remove the worktree either: ownership is scoped.
        let second =
            WorktreeManager::with_git(data.path(), writer.clone(), GitProgram::discover().unwrap())
                .unwrap();
        let error = second.remove_worktree(&prepared.worktree_id).unwrap_err();
        let WorktreeError::WorktreeNotOwned(_) = error else {
            panic!("expected WorktreeNotOwned from second manager, got {error:?}");
        };

        // An unrelated sibling directory inside the worktrees root survives.
        let sibling = manager.worktrees_root().join("unrelated-keep");
        fs::create_dir_all(&sibling).unwrap();
        manager.remove_worktree(&prepared.worktree_id).unwrap();
        assert!(sibling.is_dir());
        assert!(!prepared.path.is_dir());
    }

    #[test]
    fn cleanup_removes_owned_worktree_and_is_idempotent() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        ensure_task(&writer, "task-1", 10);

        let prepared = manager
            .prepare_worktree("task-1", &repo, "HEAD", 10)
            .unwrap();
        manager.remove_worktree(&prepared.worktree_id).unwrap();
        assert!(!prepared.path.exists());
        let listing = git_at(&repo, &["worktree", "list", "--porcelain"]);
        let text = String::from_utf8(listing.stdout).unwrap();
        assert!(
            !text.contains(prepared.path.to_string_lossy().as_ref()),
            "git still records the removed worktree: {text}"
        );
        // Idempotent second removal.
        manager.remove_worktree(&prepared.worktree_id).unwrap();
        // The durable row is retention state owned by storage GC, not by
        // cleanup: it must survive for post-ACK/retention accounting.
        assert_eq!(durable_worktree_rows(data.path()).len(), 1);
    }

    #[test]
    fn cleanup_detects_external_git_removal_without_repair() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        ensure_task(&writer, "task-1", 10);

        let prepared = manager
            .prepare_worktree("task-1", &repo, "HEAD", 10)
            .unwrap();
        // An external actor removes the worktree behind the mesh's back.
        git_ok(
            &repo,
            &[
                "worktree",
                "remove",
                "--force",
                &prepared.path.to_string_lossy(),
            ],
        );
        let error = manager.remove_worktree(&prepared.worktree_id).unwrap_err();
        let WorktreeError::ExternalModification(detail) = error else {
            panic!("expected ExternalModification, got {error:?}");
        };
        assert!(detail.contains(&prepared.worktree_id));
        assert!(!prepared.path.exists());
    }

    #[test]
    fn cleanup_detects_manual_directory_removal_without_repair() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        ensure_task(&writer, "task-1", 10);

        let prepared = manager
            .prepare_worktree("task-1", &repo, "HEAD", 10)
            .unwrap();
        fs::remove_dir_all(&prepared.path).unwrap();
        let error = manager.remove_worktree(&prepared.worktree_id).unwrap_err();
        let WorktreeError::ExternalModification(_) = error else {
            panic!("expected ExternalModification, got {error:?}");
        };
    }

    #[test]
    fn cleanup_detects_worktree_git_no_longer_records() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        ensure_task(&writer, "task-1", 10);

        let prepared = manager
            .prepare_worktree("task-1", &repo, "HEAD", 10)
            .unwrap();
        // Simulate external Git administration: git forgets the worktree but
        // the directory (and a stale .git marker) still exist.
        let git_file = prepared.path.join(".git");
        let git_file_content = fs::read_to_string(&git_file).unwrap();
        git_ok(
            &repo,
            &[
                "worktree",
                "remove",
                "--force",
                &prepared.path.to_string_lossy(),
            ],
        );
        fs::create_dir_all(&prepared.path).unwrap();
        fs::write(&git_file, git_file_content).unwrap();

        let error = manager.remove_worktree(&prepared.worktree_id).unwrap_err();
        let WorktreeError::ExternalModification(detail) = error else {
            panic!("expected ExternalModification, got {error:?}");
        };
        assert!(detail.contains("no longer records"));
        // No destructive repair: the restored directory is untouched.
        assert!(prepared.path.is_dir());
    }

    #[test]
    fn evidence_captures_modified_untracked_and_tree_metadata() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        commit_file(&repo, "sub/keep.txt", "keep\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        ensure_task(&writer, "task-1", 10);

        let prepared = manager
            .prepare_worktree("task-1", &repo, "HEAD", 10)
            .unwrap();
        let artifact = [0u8, 1, 2, 3, 4];
        fs::write(prepared.path.join("a.txt"), "changed\n").unwrap();
        fs::write(prepared.path.join("out.bin"), artifact).unwrap();

        let evidence = manager.capture_evidence(&prepared.worktree_id).unwrap();
        assert_eq!(evidence.worktree_id, prepared.worktree_id);
        assert_eq!(evidence.base_oid, prepared.base_oid);
        assert_eq!(evidence.head_oid, prepared.base_oid);
        assert_eq!(evidence.head_tree_oid, tree_oid(&repo));

        // Working-tree diff contains the tracked modification.
        let working = evidence.working_diff.expect("working diff expected");
        assert!(!working.truncated);
        let diff_text = String::from_utf8(working.bytes).unwrap();
        assert!(diff_text.contains("changed"));

        // No committed divergence from the pinned base.
        assert!(evidence.committed_diff.is_none());

        // Strict status parsing sees the modification and the artifact.
        let modified = evidence
            .status_entries
            .iter()
            .find(|entry| entry.path == "a.txt")
            .expect("modified entry");
        assert_eq!((modified.x, modified.y), (' ', 'M'));
        let untracked = evidence
            .status_entries
            .iter()
            .find(|entry| entry.path == "out.bin")
            .expect("untracked entry");
        assert_eq!(untracked.x, '?');

        // Artifact manifest carries the exact byte length.
        let artifact_entry = evidence
            .untracked_files
            .iter()
            .find(|file| file.path == "out.bin")
            .expect("artifact manifest entry");
        assert_eq!(artifact_entry.byte_length, artifact.len() as u64);
        assert!(!artifact_entry.is_directory);

        // Tree metadata lists every tracked path from the pinned base.
        assert_eq!(evidence.tree_entries.len(), 2);
        assert!(
            evidence
                .tree_entries
                .iter()
                .any(|entry| entry.path == "a.txt" && entry.object_type == "blob")
        );
    }

    #[test]
    fn evidence_for_clean_worktree_is_empty() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        ensure_task(&writer, "task-1", 10);

        let prepared = manager
            .prepare_worktree("task-1", &repo, "HEAD", 10)
            .unwrap();
        let evidence = manager.capture_evidence(&prepared.worktree_id).unwrap();
        assert!(evidence.status_entries.is_empty());
        assert!(evidence.untracked_files.is_empty());
        assert!(evidence.working_diff.is_none());
        assert!(evidence.committed_diff.is_none());
        assert_eq!(evidence.tree_entries.len(), 1);
    }

    #[test]
    fn prepare_reverifies_cleanliness_after_admission() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());

        let admission = manager.admit_repository(&repo, "HEAD").unwrap();
        fs::write(repo.join("late.txt"), "dirty after admission\n").unwrap();
        let error = manager
            .prepare_admitted("task-1", &admission, 10)
            .unwrap_err();
        let WorktreeError::DirtyWorkspace(summary) = error else {
            panic!("expected DirtyWorkspace, got {error:?}");
        };
        assert_eq!(summary.untracked, 1);
        assert_eq!(durable_worktree_rows(data.path()).len(), 0);
    }

    #[test]
    fn prepare_reverifies_repository_identity() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());

        let admission = manager.admit_repository(&repo, "HEAD").unwrap();
        fs::remove_dir_all(&repo).unwrap();
        let error = manager
            .prepare_admitted("task-1", &admission, 10)
            .unwrap_err();
        let WorktreeError::RepositoryChanged { .. } = error else {
            panic!("expected RepositoryChanged, got {error:?}");
        };
        assert_eq!(durable_worktree_rows(data.path()).len(), 0);
    }

    #[test]
    fn worktree_paths_with_spaces_and_unicode_work() {
        let (_temp, repo) = make_repo("répo with spaces");
        commit_file(&repo, "a.txt", "base\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        ensure_task(&writer, "task-1", 10);

        let prepared = manager
            .prepare_worktree("task-1", &repo, "HEAD", 10)
            .unwrap();
        assert_eq!(head_oid(&prepared.path), head_oid(&repo));
        let evidence = manager.capture_evidence(&prepared.worktree_id).unwrap();
        assert!(evidence.status_entries.is_empty());
        manager.remove_worktree(&prepared.worktree_id).unwrap();
    }

    #[test]
    fn porcelain_z_parser_matches_live_git_rename_layout() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "old.txt", "base\n");
        git_ok(&repo, &["mv", "old.txt", "new.txt"]);
        let output = git_at(&repo, &["status", "--porcelain=v1", "-z"]);
        assert!(output.status.success());
        // Freeze the observed wire layout: rename entries are
        // `R  <destination>\0<source>\0`, the reverse of the plain format.
        assert_eq!(output.stdout, b"R  new.txt\0old.txt\0");

        let entries = parse_porcelain_z(&output.stdout).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].x, 'R');
        assert_eq!(entries[0].path, "new.txt");
        assert_eq!(entries[0].orig_path.as_deref(), Some("old.txt"));
    }

    #[test]
    fn porcelain_z_parser_rejects_malformed_entries() {
        assert!(parse_porcelain_z(b"M  a.txt\0").is_ok());
        assert_eq!(parse_porcelain_z(b"M  a.txt").unwrap().len(), 1);
        assert!(matches!(
            parse_porcelain_z(b"ZZ a.txt\0"),
            Err(WorktreeError::ProtocolViolation(_))
        ));
        assert!(matches!(
            parse_porcelain_z(b"M"),
            Err(WorktreeError::ProtocolViolation(_))
        ));
        assert!(matches!(
            parse_porcelain_z(b"R  dst.txt\0"),
            Err(WorktreeError::ProtocolViolation(_))
        ));
        assert!(matches!(
            parse_porcelain_z(b"M\x00a.txt"),
            Err(WorktreeError::ProtocolViolation(_))
        ));
    }

    #[test]
    fn ls_tree_z_parser_accepts_and_rejects_strictly() {
        let valid = b"100644 blob 0123456789012345678901234567890123456789\ta.txt\0";
        let entries = parse_ls_tree_z(valid).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].mode, "100644");
        assert_eq!(entries[0].object_type, "blob");
        assert_eq!(entries[0].path, "a.txt");

        assert!(matches!(
            parse_ls_tree_z(b"100644 blob 0123456789\ta.txt\0"),
            Err(WorktreeError::ProtocolViolation(_))
        ));
        assert!(matches!(
            parse_ls_tree_z(b"12345 blob 0123456789012345678901234567890123456789\ta.txt\0"),
            Err(WorktreeError::ProtocolViolation(_))
        ));
        assert!(matches!(
            parse_ls_tree_z(b"100644 nope 0123456789012345678901234567890123456789\ta.txt\0"),
            Err(WorktreeError::ProtocolViolation(_))
        ));
        assert!(matches!(
            parse_ls_tree_z(
                b"100644 blob 0123456789012345678901234567890123456789\ta.txt\0extra\0"
            ),
            Err(WorktreeError::ProtocolViolation(_))
        ));
        assert!(matches!(
            parse_ls_tree_z(b"100644 blob 0123456789012345678901234567890123456789a.txt\0"),
            Err(WorktreeError::ProtocolViolation(_))
        ));
    }

    #[test]
    fn git_output_is_bounded_and_never_hangs() {
        let (_temp, repo) = make_repo("repo");
        commit_file(&repo, "a.txt", "base\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());

        let run = manager
            .run(&repo, &[s("rev-list"), s("--objects"), s("--all")], 128)
            .unwrap();
        assert!(run.success());
        assert!(run.stdout_truncated, "small cap must truncate");
        assert!(run.stdout.len() <= 128);
    }
}

#[cfg(test)]
mod current_directory_tests {
    use super::*;
    use crate::canonicalize;
    use crate::domain::{InteractionCapabilityClass, InteractionResponseKind};
    use crate::storage::{AttemptSpec, InteractionResponseEvidence};
    use crate::writer::WriterHandle;
    use serde_json::{Value, json};

    const INSTALL_ID: &str = "install";
    const OPERATION_DIGEST: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const POLICY_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const CONFIG_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn manager(data_root: &Path) -> (WorktreeManager, WriterHandle) {
        let writer = WriterHandle::start_portable(data_root.to_path_buf(), INSTALL_ID, 1).unwrap();
        let manager =
            WorktreeManager::with_git(data_root, writer.clone(), GitProgram::discover().unwrap())
                .unwrap();
        (manager, writer)
    }

    fn git_ok(dir: &Path, args: &[&str]) {
        let output = Command::new(GitProgram::discover().unwrap().0)
            .args(args)
            .current_dir(dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .expect("git must run");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn make_repo(name: &str) -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join(name);
        fs::create_dir_all(&repo).expect("repo dir");
        git_ok(temp.path(), &["init", "-q", &repo.to_string_lossy()]);
        git_ok(&repo, &["config", "user.name", "test"]);
        git_ok(&repo, &["config", "user.email", "test@example.invalid"]);
        git_ok(&repo, &["config", "commit.gpgsign", "false"]);
        (temp, repo)
    }

    fn commit_file(repo: &Path, relative: &str, content: &str) {
        let path = repo.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("parent dirs");
        }
        fs::write(&path, content).expect("file write");
        git_ok(repo, &["add", "--", relative]);
        git_ok(repo, &["commit", "-q", "-m", relative]);
    }

    fn frozen_settings() -> Value {
        let config: Value =
            serde_json::from_str(include_str!("../../../protocol/v1/golden/config.json")).unwrap();
        config["settings"].clone()
    }

    fn opt_in_settings() -> Value {
        let config: Value = serde_json::from_str(include_str!(
            "../../../protocol/v1/golden/config-allow-current-directory.json"
        ))
        .unwrap();
        config["settings"].clone()
    }

    fn ensure_task(writer: &WriterHandle, task_id: &str, now_us: i64) {
        writer
            .submit(
                "consumer",
                "delegate_task",
                format!("command-{task_id}"),
                format!("request-{task_id}").into_bytes(),
                task_id,
                None,
                now_us,
            )
            .unwrap();
    }

    fn durable_approve(
        writer: &WriterHandle,
        task_id: &str,
        now_us: i64,
    ) -> InteractionResponseEvidence {
        ensure_task(writer, task_id, now_us);
        let attempt = writer
            .begin_attempt(
                "consumer",
                format!("begin-{task_id}"),
                format!("begin-{task_id}").into_bytes(),
                task_id,
                0,
                AttemptSpec {
                    effect_profile: EffectProfile::CurrentDirectory.as_str().into(),
                    isolation_level: IsolationLevel::BestEffort.as_str().into(),
                    retry_class: "AMBIGUOUS_AFTER_DISPATCH".into(),
                    adapter_instance_id: "agent-1".into(),
                    config_digest: CONFIG_DIGEST.into(),
                    ..AttemptSpec::default()
                },
                now_us + 1,
            )
            .unwrap();
        let interaction = writer
            .open_interaction(
                format!("open-{task_id}"),
                task_id,
                attempt.attempt_id,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionCapabilityClass::Approval,
                1,
                1,
                now_us + 10_000,
                now_us + 2,
            )
            .unwrap();
        let response = json!({"kind":"approve"});
        let command = json!({
            "version":1,"kind":"command","action":"interaction_response",
            "command_key":format!("approve-{task_id}"),
            "task_id":task_id,
            "interaction_id":interaction.interaction_id,
            "generation":0,
            "operation_digest":OPERATION_DIGEST,
            "policy_digest":POLICY_DIGEST,
            "config_digest":CONFIG_DIGEST,
            "nonce":interaction.nonce,
            "response":response
        });
        writer
            .respond_interaction(
                "consumer",
                format!("approve-{task_id}"),
                canonicalize(&command).unwrap().into_bytes(),
                interaction.interaction_id.clone(),
                interaction.nonce,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionResponseKind::Approve,
                canonicalize(&response).unwrap().into_bytes(),
                now_us + 3,
            )
            .unwrap();
        writer
            .interaction_response(interaction.interaction_id)
            .unwrap()
    }

    fn durable_deny(
        writer: &WriterHandle,
        task_id: &str,
        now_us: i64,
    ) -> InteractionResponseEvidence {
        ensure_task(writer, task_id, now_us);
        let attempt = writer
            .begin_attempt(
                "consumer",
                format!("begin-{task_id}"),
                format!("begin-{task_id}").into_bytes(),
                task_id,
                0,
                AttemptSpec::default(),
                now_us + 1,
            )
            .unwrap();
        let interaction = writer
            .open_interaction(
                format!("open-{task_id}"),
                task_id,
                attempt.attempt_id,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionCapabilityClass::Approval,
                1,
                1,
                now_us + 10_000,
                now_us + 2,
            )
            .unwrap();
        let response = json!({"kind":"deny"});
        let command = json!({
            "version":1,"kind":"command","action":"interaction_response",
            "command_key":format!("deny-{task_id}"),
            "task_id":task_id,
            "interaction_id":interaction.interaction_id,
            "generation":0,
            "operation_digest":OPERATION_DIGEST,
            "policy_digest":POLICY_DIGEST,
            "config_digest":CONFIG_DIGEST,
            "nonce":interaction.nonce,
            "response":response
        });
        writer
            .respond_interaction(
                "consumer",
                format!("deny-{task_id}"),
                canonicalize(&command).unwrap().into_bytes(),
                interaction.interaction_id.clone(),
                interaction.nonce,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionResponseKind::Deny,
                canonicalize(&response).unwrap().into_bytes(),
                now_us + 3,
            )
            .unwrap();
        writer
            .interaction_response(interaction.interaction_id)
            .unwrap()
    }

    fn durable_text(
        writer: &WriterHandle,
        task_id: &str,
        now_us: i64,
    ) -> InteractionResponseEvidence {
        ensure_task(writer, task_id, now_us);
        let attempt = writer
            .begin_attempt(
                "consumer",
                format!("begin-{task_id}"),
                format!("begin-{task_id}").into_bytes(),
                task_id,
                0,
                AttemptSpec::default(),
                now_us + 1,
            )
            .unwrap();
        let interaction = writer
            .open_interaction(
                format!("open-{task_id}"),
                task_id,
                attempt.attempt_id,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionCapabilityClass::Approval,
                1,
                1,
                now_us + 10_000,
                now_us + 2,
            )
            .unwrap();
        let response = json!({"kind":"text","text":"ok"});
        let command = json!({
            "version":1,"kind":"command","action":"interaction_response",
            "command_key":format!("text-{task_id}"),
            "task_id":task_id,
            "interaction_id":interaction.interaction_id,
            "generation":0,
            "operation_digest":OPERATION_DIGEST,
            "policy_digest":POLICY_DIGEST,
            "config_digest":CONFIG_DIGEST,
            "nonce":interaction.nonce,
            "response":response
        });
        writer
            .respond_interaction(
                "consumer",
                format!("text-{task_id}"),
                canonicalize(&command).unwrap().into_bytes(),
                interaction.interaction_id.clone(),
                interaction.nonce,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionResponseKind::Text,
                canonicalize(&response).unwrap().into_bytes(),
                now_us + 3,
            )
            .unwrap();
        writer
            .interaction_response(interaction.interaction_id)
            .unwrap()
    }

    fn create_directory_reparse(link: &Path, target: &Path) -> std::io::Result<()> {
        #[cfg(windows)]
        {
            // `mklink /J` creates a junction without SeCreateSymbolicLinkPrivilege.
            // Pass each token separately so the Windows Command quoter cannot
            // swallow the built-in as one quoted string.
            let output = Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(link)
                .arg(target)
                .output()?;
            if output.status.success() {
                return Ok(());
            }
            let detail = String::from_utf8_lossy(&output.stderr);
            Err(std::io::Error::other(format!(
                "mklink /J failed ({:?}): {detail}",
                output.status.code()
            )))
        }
        #[cfg(not(windows))]
        {
            std::os::unix::fs::symlink(target, link)
        }
    }

    fn durable_worktree_count(data_root: &Path) -> usize {
        let connection = rusqlite::Connection::open(data_root.join("mesh.sqlite3")).unwrap();
        connection
            .query_row("SELECT COUNT(*) FROM worktrees", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn mesh_worktree_dirs(manager: &WorktreeManager) -> usize {
        fs::read_dir(manager.worktrees_root())
            .unwrap()
            .filter(|entry| entry.as_ref().is_ok_and(|value| value.path().is_dir()))
            .count()
    }

    #[test]
    fn default_config_rejects_current_directory_escape() {
        let cwd = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        let approval = durable_approve(&writer, "default-cfg", 10);
        let error = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: cwd.path(),
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &frozen_settings(),
                approval: Some(&approval),
            })
            .unwrap_err();
        assert!(matches!(error, WorktreeError::CurrentDirectoryDisabled));
        assert_eq!(durable_worktree_count(data.path()), 0);
        assert_eq!(mesh_worktree_dirs(&manager), 0);
    }

    #[test]
    fn opt_in_without_approval_rejects_current_directory_escape() {
        let cwd = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let (manager, _writer) = manager(data.path());
        let error = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: cwd.path(),
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &opt_in_settings(),
                approval: None,
            })
            .unwrap_err();
        assert!(matches!(
            error,
            WorktreeError::CurrentDirectoryApprovalRequired
        ));
        assert_eq!(durable_worktree_count(data.path()), 0);
    }

    #[test]
    fn approval_without_opt_in_rejects_current_directory_escape() {
        let cwd = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        let approval = durable_approve(&writer, "no-opt-in", 10);
        let error = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: cwd.path(),
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &frozen_settings(),
                approval: Some(&approval),
            })
            .unwrap_err();
        assert!(matches!(error, WorktreeError::CurrentDirectoryDisabled));
    }

    #[test]
    fn deny_is_not_current_directory_escape_consent() {
        let cwd = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        let deny = durable_deny(&writer, "deny-hatch", 10);
        let error = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: cwd.path(),
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &opt_in_settings(),
                approval: Some(&deny),
            })
            .unwrap_err();
        assert!(matches!(
            error,
            WorktreeError::CurrentDirectoryApprovalRequired
        ));
    }

    #[test]
    fn timeout_is_not_current_directory_escape_consent() {
        let cwd = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        ensure_task(&writer, "timeout-hatch", 10);
        let attempt = writer
            .begin_attempt(
                "consumer",
                "begin-timeout-hatch",
                b"begin-timeout-hatch".to_vec(),
                "timeout-hatch",
                0,
                AttemptSpec::default(),
                11,
            )
            .unwrap();
        let interaction = writer
            .open_interaction(
                "open-timeout-hatch",
                "timeout-hatch",
                attempt.attempt_id,
                0,
                OPERATION_DIGEST,
                POLICY_DIGEST,
                CONFIG_DIGEST,
                InteractionCapabilityClass::Approval,
                1,
                1,
                15,
                12,
            )
            .unwrap();
        assert!(
            writer
                .interaction_response(interaction.interaction_id)
                .is_err(),
            "timeout must leave no approve evidence"
        );
        let error = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: cwd.path(),
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &opt_in_settings(),
                approval: None,
            })
            .unwrap_err();
        assert!(matches!(
            error,
            WorktreeError::CurrentDirectoryApprovalRequired
        ));
    }

    #[test]
    fn text_is_not_current_directory_escape_consent() {
        let cwd = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        let text = durable_text(&writer, "text-hatch", 10);
        let error = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: cwd.path(),
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &opt_in_settings(),
                approval: Some(&text),
            })
            .unwrap_err();
        assert!(matches!(
            error,
            WorktreeError::CurrentDirectoryApprovalRequired
        ));
    }

    #[test]
    fn opt_in_and_approval_admits_current_directory_escape_best_effort() {
        let cwd = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        let approval = durable_approve(&writer, "both-gates", 10);
        let admitted = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: cwd.path(),
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &opt_in_settings(),
                approval: Some(&approval),
            })
            .unwrap();
        assert_eq!(admitted.isolation, IsolationLevel::BestEffort);
        assert_eq!(admitted.isolation(), IsolationLevel::BestEffort);
        assert_ne!(admitted.isolation, IsolationLevel::Enforced);
        assert_eq!(admitted.cwd, std::path::absolute(cwd.path()).unwrap());
        assert!(
            !admitted.cwd.starts_with(manager.worktrees_root()),
            "escape hatch must not create or use a mesh worktree"
        );
        assert_eq!(durable_worktree_count(data.path()), 0);
        assert_eq!(mesh_worktree_dirs(&manager), 0);
        let spec = admitted.attempt_spec("agent-1", "unknown", CONFIG_DIGEST);
        assert_eq!(spec.effect_profile, "CURRENT_DIRECTORY");
        assert_eq!(spec.isolation_level, "BEST_EFFORT");
        assert_ne!(spec.isolation_level, "ENFORCED");
        assert!(spec.worktree_id.is_none());
    }

    #[test]
    fn dirty_repo_uses_current_directory_escape_only_with_both_gates() {
        let (_temp, repo) = make_repo("dirty");
        commit_file(&repo, "a.txt", "one\n");
        fs::write(repo.join("a.txt"), "dirty\n").unwrap();
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());

        let isolated = manager.admit_repository(&repo, "HEAD").unwrap_err();
        assert!(matches!(isolated, WorktreeError::DirtyWorkspace(_)));

        let missing_opt_in = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: &repo,
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &frozen_settings(),
                approval: None,
            })
            .unwrap_err();
        assert!(matches!(
            missing_opt_in,
            WorktreeError::CurrentDirectoryDisabled
        ));

        let approval = durable_approve(&writer, "dirty-hatch", 10);
        let missing_approval_after_opt_in = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: &repo,
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &opt_in_settings(),
                approval: None,
            })
            .unwrap_err();
        assert!(matches!(
            missing_approval_after_opt_in,
            WorktreeError::CurrentDirectoryApprovalRequired
        ));

        let admitted = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: &repo,
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &opt_in_settings(),
                approval: Some(&approval),
            })
            .unwrap();
        assert_eq!(admitted.isolation, IsolationLevel::BestEffort);
        assert_eq!(durable_worktree_count(data.path()), 0);
        assert_eq!(mesh_worktree_dirs(&manager), 0);
    }

    #[test]
    fn isolated_worktree_admission_is_unchanged_when_escape_is_configured() {
        let (_temp, repo) = make_repo("clean");
        commit_file(&repo, "a.txt", "one\n");
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        ensure_task(&writer, "iso-clean", 10);
        let prepared = manager
            .prepare_worktree("iso-clean", &repo, "HEAD", 11)
            .unwrap();
        assert!(prepared.path.starts_with(manager.worktrees_root()));
        assert_eq!(durable_worktree_count(data.path()), 1);

        fs::write(repo.join("a.txt"), "dirty\n").unwrap();
        let approval = durable_approve(&writer, "iso-dirty", 20);
        let dirty = manager.admit_repository(&repo, "HEAD").unwrap_err();
        assert!(matches!(dirty, WorktreeError::DirtyWorkspace(_)));
        let mismatch = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: &repo,
                workspace_mode: WorkspaceMode::IsolatedWorktree,
                effect_profile: EffectProfile::IsolatedWorktree,
                settings: &opt_in_settings(),
                approval: Some(&approval),
            })
            .unwrap_err();
        assert!(matches!(
            mismatch,
            WorktreeError::CurrentDirectoryRequestMismatch
        ));
        let inferred = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: &repo,
                workspace_mode: WorkspaceMode::IsolatedWorktree,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &opt_in_settings(),
                approval: Some(&approval),
            })
            .unwrap_err();
        assert!(matches!(
            inferred,
            WorktreeError::CurrentDirectoryRequestMismatch
        ));
        assert_eq!(durable_worktree_count(data.path()), 1);
    }

    #[test]
    fn current_directory_escape_rejects_file_and_reparse_paths() {
        let data = tempfile::tempdir().unwrap();
        let (manager, writer) = manager(data.path());
        let approval = durable_approve(&writer, "path-hatch", 10);
        let file_root = tempfile::tempdir().unwrap();
        let file = file_root.path().join("not-a-dir.txt");
        fs::write(&file, "x").unwrap();
        let file_error = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: &file,
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &opt_in_settings(),
                approval: Some(&approval),
            })
            .unwrap_err();
        assert!(matches!(
            file_error,
            WorktreeError::CurrentDirectoryNotADirectory(_)
        ));

        let target = tempfile::tempdir().unwrap();
        let workdir = target.path().join("workdir");
        fs::create_dir(&workdir).unwrap();
        let link_root = tempfile::tempdir().unwrap();
        let link = link_root.path().join("junction");
        create_directory_reparse(&link, target.path())
            .expect("create junction or directory symlink");
        let leaf = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: &link,
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &opt_in_settings(),
                approval: Some(&approval),
            })
            .unwrap_err();
        assert!(matches!(leaf, WorktreeError::CurrentDirectoryReparse(_)));
        let via_parent = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: &link.join("workdir"),
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &opt_in_settings(),
                approval: Some(&approval),
            })
            .unwrap_err();
        assert!(
            matches!(via_parent, WorktreeError::CurrentDirectoryReparse(_)),
            "must reject a path that hops a parent junction, not follow it"
        );
        let real = manager
            .admit_current_directory(&CurrentDirectoryRequest {
                path: &workdir,
                workspace_mode: WorkspaceMode::CurrentDirectory,
                effect_profile: EffectProfile::CurrentDirectory,
                settings: &opt_in_settings(),
                approval: Some(&approval),
            })
            .unwrap();
        assert_eq!(real.isolation, IsolationLevel::BestEffort);
        assert_eq!(real.cwd, std::path::absolute(&workdir).unwrap());
    }
}
