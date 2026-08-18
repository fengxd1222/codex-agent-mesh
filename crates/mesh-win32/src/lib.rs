//! Audited Windows storage primitives for Codex Agent Mesh.
//!
//! This crate is intentionally narrow: callers receive relative-path APIs
//! rooted at a validated directory and never interact with raw Win32 handles.
//! The guarantees cover process crashes and reported I/O errors on local NTFS;
//! they do not claim directory-metadata durability across power loss.

#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(windows), forbid(unsafe_code))]

mod authenticode;
mod error;
mod frame;
mod handshake;
mod known_folder;
mod native_error;
mod secret;

#[cfg(windows)]
mod console;
#[cfg(windows)]
mod job;
#[cfg(windows)]
mod lock;
#[cfg(windows)]
mod pipe;
#[cfg(windows)]
mod process;
#[cfg(windows)]
mod task;
#[cfg(not(windows))]
mod unsupported;
#[cfg(windows)]
mod windows;

pub use authenticode::{
    AuthenticodePolicy, AuthenticodeVerification, MAX_AUTHENTICODE_FILE_BYTES, verify_authenticode,
};
#[cfg(windows)]
pub use console::enable_stdout_virtual_terminal;
pub use error::{StorageError, StorageErrorCode, StorageOperation};
pub use frame::{
    FRAME_HEADER_LENGTH, REQUEST_FRAME_LIMIT, RESPONSE_FRAME_LIMIT, decode_frame_length,
    decode_utf8, encode_frame, read_frame, write_frame,
};
pub use handshake::{
    AUTH_TAG_LENGTH, CLIENT_PROOF_DOMAIN, ClientAuth, ClientHello, EndpointKey,
    HandshakeTranscript, NONCE_LENGTH, Nonce, NonceReplayGuard, PROTOCOL_VERSION_V1,
    SERVER_PROOF_DOMAIN, ServerChallenge, ServerReady, WIRE_MAJOR_V1, WIRE_MINOR_V1, WireLimitsV1,
};
#[cfg(windows)]
pub use job::NonBreakawayJob;
#[cfg(windows)]
pub use known_folder::current_user_local_app_data;
pub use known_folder::{KnownFolderError, KnownFolderErrorCode};
#[cfg(windows)]
pub use lock::ExclusiveFileLock;
pub use native_error::{NativeError, NativeErrorCode, NativeOperation};
#[cfg(windows)]
pub use pipe::{
    PeerIdentityPolicy, PipeEndpoint, SecurePipeClient, SecurePipeConnection, SecurePipeReadHalf,
    SecurePipeServer, SecurePipeWriteHalf, derive_pipe_name, sha256_file,
};
#[cfg(windows)]
pub use process::{
    OwnedProcess, ProcessIdentity, ProcessSpawnSpec, ProcessWait, create_suspended_process,
    process_id_is_active, process_identity_is_live,
};
pub use secret::{
    MAX_PROTECTED_ENDPOINT_KEY_BYTES, ProtectedEndpointKey, protect_dashboard_secret,
    protect_endpoint_key, unprotect_dashboard_secret, unprotect_endpoint_key,
};
#[cfg(windows)]
pub use task::{
    ScheduledTaskController, ScheduledTaskSpec, ScheduledTaskState, ScheduledTaskStatus,
};
#[cfg(not(windows))]
pub use unsupported::ExclusiveFileLock;
#[cfg(not(windows))]
pub use unsupported::{
    ValidatedControlRoot, ValidatedDataRoot, current_user_local_app_data,
    open_or_create_product_control_root, protect_control_root, protect_data_root,
    validate_control_root, validate_data_root,
};
#[cfg(not(windows))]
pub fn enable_stdout_virtual_terminal() {}
#[cfg(windows)]
pub use windows::{
    MAX_CONTROL_FILE_BYTES, ValidatedControlRoot, ValidatedDataRoot,
    open_or_create_product_control_root, protect_control_root, protect_data_root,
    validate_control_root, validate_data_root,
};

#[cfg(not(windows))]
pub use unsupported::MAX_CONTROL_FILE_BYTES;

/// The exact security descriptor contract applied and accepted for a data root.
///
/// The directory owner is the current process user. Its DACL is protected from
/// inheritance and contains exactly three inheritable, full-control allow
/// entries: the current user, `LocalSystem`, and Builtin Administrators. No deny,
/// inherited, callback, or additional allow entry is accepted.
pub const DATA_ROOT_SECURITY_CONTRACT: DataRootSecurityContract = DataRootSecurityContract {
    owner: "current-user",
    allowed_full_control_principals: &["current-user", "SYSTEM", "Administrators"],
    protected_dacl: true,
    descendants_inherit: true,
};

/// A stable, inspectable description of [`DATA_ROOT_SECURITY_CONTRACT`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataRootSecurityContract {
    pub owner: &'static str,
    pub allowed_full_control_principals: &'static [&'static str],
    pub protected_dacl: bool,
    pub descendants_inherit: bool,
}

/// Presence of the only two record-derived installation tree locations.
///
/// Callers supply a validated lower-hex install identity, never either path.
/// Seeing both locations is returned as [`StorageErrorCode::PurgeTreeConflict`]
/// rather than represented here, so neither tree can be accidentally adopted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallPurgeTreePresence {
    Source,
    Tombstone,
    Gone,
}

/// Evidence returned after an exact same-volume, no-replace purge staging move.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PurgeStageReport {
    /// Whether both affected directory handles accepted an explicit flush.
    pub directory_sync_supported: bool,
}

/// Bounded evidence from the audit-first recursive purge boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PurgeTreeReport {
    /// Directories unlinked, including the tombstone root.
    pub directories: u64,
    /// Regular directory entries unlinked.
    pub files: u64,
    /// Sum of the regular entries' logical lengths.
    pub logical_file_bytes: u64,
    /// Entries whose NTFS link count was greater than one. Only the in-tree
    /// name is unlinked; another hard-link name is never traversed or removed.
    pub hard_link_entries: u64,
    /// Sparse regular entries accepted and unlinked without materialization.
    pub sparse_files: u64,
    /// Compressed regular entries accepted and unlinked without decompression.
    pub compressed_files: u64,
    /// Read-only entries removed with the explicit Win32 ignore-read-only
    /// disposition flag; their attributes are not rewritten first.
    pub read_only_entries: u64,
    /// Whether the final tombstone-parent directory flush was supported.
    pub directory_sync_supported: bool,
}

/// Exact immediate entry type returned for `slots/stable` finalization audits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlDirectoryEntryKind {
    RegularFile,
    Directory,
}

/// One unfiltered immediate child of the protected `slots/stable` directory.
///
/// Reparse points are reported (never followed) so the record store can reject
/// them as drift together with any unknown name. Non-reparse regular files
/// include their complete bounded bytes; directories and reparse points do not.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlDirectoryEntry {
    pub name: std::ffi::OsString,
    pub kind: ControlDirectoryEntryKind,
    pub reparse_point: bool,
    pub file_id: u64,
    pub contents: Option<Vec<u8>>,
}

/// Evidence that a record-absent product root contains no installation
/// identity or purge tombstone, while retaining only its lock structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CleanPurgeAbsenceReport {
    pub installs_directory_present: bool,
    pub purge_directory_present: bool,
}
