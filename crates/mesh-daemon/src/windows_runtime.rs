//! Production Windows entry-point orchestration.
//!
//! This module deliberately contains no setup or repair fallback. The plugin
//! cache may only trampoline into the retained image, the retained bridge may
//! only ask Task Scheduler to start the daemon, and the daemon publishes
//! readiness only after its durable store and authenticated listener exist.

#![allow(clippy::missing_errors_doc)]

use std::fmt;

#[cfg(any(windows, test))]
use std::io;

#[cfg(any(windows, test))]
const STARTUP_TIMEOUT_MS: u64 = 15_000;
#[cfg(any(windows, test))]
const HANDSHAKE_RESERVE_MS: u64 = 2_000;
#[cfg(any(windows, test))]
const STARTUP_POLL_MAX_MS: u64 = 25;

#[cfg(any(windows, test))]
trait CacheBootstrapOperations {
    type Child;

    fn spawn_exact_stable(&mut self) -> Result<Self::Child, WindowsRuntimeError>;
    fn wait_child(&mut self, child: Self::Child) -> Result<Option<i32>, WindowsRuntimeError>;
}

#[cfg(any(windows, test))]
fn bootstrap_cache<O: CacheBootstrapOperations>(
    operations: &mut O,
) -> Result<u8, WindowsRuntimeError> {
    let child = operations.spawn_exact_stable()?;
    let Some(code) = operations.wait_child(child)? else {
        return Err(invalid_child_exit());
    };
    u8::try_from(code).map_err(|_| invalid_child_exit())
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DaemonStartupMilestone {
    IdentityVerified,
    SingletonLocked,
    StorageRecovered,
    FirstPipeBound,
    RunningPublished,
}

#[cfg(any(windows, test))]
struct DaemonStartupOrder {
    next: usize,
}

#[cfg(any(windows, test))]
impl DaemonStartupOrder {
    const ORDER: [DaemonStartupMilestone; 5] = [
        DaemonStartupMilestone::IdentityVerified,
        DaemonStartupMilestone::SingletonLocked,
        DaemonStartupMilestone::StorageRecovered,
        DaemonStartupMilestone::FirstPipeBound,
        DaemonStartupMilestone::RunningPublished,
    ];

    const fn new() -> Self {
        Self { next: 0 }
    }

    fn advance(&mut self, milestone: DaemonStartupMilestone) -> Result<(), WindowsRuntimeError> {
        if Self::ORDER.get(self.next) != Some(&milestone) {
            return Err(startup_failed());
        }
        self.next += 1;
        Ok(())
    }
}

/// Stable, redaction-safe failure categories for the Windows entry modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsRuntimeErrorCode {
    AdmissionUnavailable,
    IdentityDrift,
    AuthenticationFailed,
    StartupTimeout,
    TaskUnavailable,
    TransportFailed,
    StorageFailed,
    RelayFailed,
    ChildExitInvalid,
    UnsupportedPlatform,
}

/// A bounded error which never embeds paths, native error text, secrets, or
/// protocol payloads.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WindowsRuntimeError {
    code: WindowsRuntimeErrorCode,
    message: &'static str,
}

impl WindowsRuntimeError {
    const fn new(code: WindowsRuntimeErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }

    #[must_use]
    pub const fn code(self) -> WindowsRuntimeErrorCode {
        self.code
    }

    #[must_use]
    pub const fn message(self) -> &'static str {
        self.message
    }

    /// Maps one internal runtime failure to the frozen public process-exit
    /// contract without exposing native details in `main`.
    #[must_use]
    pub const fn exit_code(self) -> u8 {
        match self.code {
            WindowsRuntimeErrorCode::AdmissionUnavailable
            | WindowsRuntimeErrorCode::IdentityDrift
            | WindowsRuntimeErrorCode::TaskUnavailable
            | WindowsRuntimeErrorCode::UnsupportedPlatform => crate::cli::EXIT_LIFECYCLE,
            WindowsRuntimeErrorCode::StartupTimeout => crate::cli::EXIT_TIMEOUT,
            WindowsRuntimeErrorCode::AuthenticationFailed
            | WindowsRuntimeErrorCode::TransportFailed
            | WindowsRuntimeErrorCode::StorageFailed
            | WindowsRuntimeErrorCode::RelayFailed
            | WindowsRuntimeErrorCode::ChildExitInvalid => crate::cli::EXIT_RUNTIME,
        }
    }
}

impl fmt::Debug for WindowsRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsRuntimeError")
            .field("code", &self.code)
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for WindowsRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for WindowsRuntimeError {}

#[cfg(any(windows, test))]
trait StartupOperations {
    type Session;

    fn now_ms(&self) -> u64;
    fn try_authenticated(&mut self) -> Result<Option<Self::Session>, WindowsRuntimeError>;
    fn try_acquire_startup_lock(&mut self) -> Result<bool, WindowsRuntimeError>;
    fn recheck_and_request_task_start(&mut self) -> Result<(), WindowsRuntimeError>;
    fn release_startup_lock(&mut self);
    fn next_poll_delay_ms(&mut self) -> u64;
    fn sleep_ms(&mut self, milliseconds: u64);
}

#[cfg(any(windows, test))]
struct StartupLockRelease<'a, O: StartupOperations> {
    operations: &'a mut O,
    held: bool,
}

#[cfg(any(windows, test))]
impl<'a, O: StartupOperations> StartupLockRelease<'a, O> {
    fn new(operations: &'a mut O, held: bool) -> Self {
        Self { operations, held }
    }

    fn operations(&mut self) -> &mut O {
        self.operations
    }
}

#[cfg(any(windows, test))]
impl<O: StartupOperations> Drop for StartupLockRelease<'_, O> {
    fn drop(&mut self) {
        if self.held {
            self.operations.release_startup_lock();
        }
    }
}

#[cfg(any(windows, test))]
fn connect_or_start<O: StartupOperations>(
    operations: &mut O,
    deadline_ms: u64,
) -> Result<O::Session, WindowsRuntimeError> {
    if can_attempt_handshake(operations.now_ms(), deadline_ms)
        && let Some(session) = operations.try_authenticated()?
    {
        return Ok(session);
    }

    let held = operations.try_acquire_startup_lock()?;
    let mut release = StartupLockRelease::new(operations, held);
    if held {
        if can_attempt_handshake(release.operations().now_ms(), deadline_ms)
            && let Some(session) = release.operations().try_authenticated()?
        {
            return Ok(session);
        }
        release.operations().recheck_and_request_task_start()?;
    }

    loop {
        let now_ms = release.operations().now_ms();
        if !can_attempt_handshake(now_ms, deadline_ms) {
            if now_ms < deadline_ms {
                release.operations().sleep_ms(deadline_ms - now_ms);
            }
            return Err(startup_timeout());
        }
        if let Some(session) = release.operations().try_authenticated()? {
            return Ok(session);
        }
        let now_ms = release.operations().now_ms();
        if now_ms >= deadline_ms {
            return Err(startup_timeout());
        }
        let delay = release
            .operations()
            .next_poll_delay_ms()
            .clamp(1, STARTUP_POLL_MAX_MS)
            .min(deadline_ms - now_ms);
        release.operations().sleep_ms(delay);
    }
}

#[cfg(any(windows, test))]
const fn can_attempt_handshake(now_ms: u64, deadline_ms: u64) -> bool {
    now_ms.saturating_add(HANDSHAKE_RESERVE_MS) <= deadline_ms
}

#[cfg(any(windows, test))]
const fn startup_timeout() -> WindowsRuntimeError {
    WindowsRuntimeError::new(
        WindowsRuntimeErrorCode::StartupTimeout,
        "authenticated daemon startup timed out",
    )
}

#[cfg(any(windows, test))]
#[derive(Debug)]
enum InputFrame {
    Eof,
    Payload(Vec<u8>),
}

#[cfg(any(windows, test))]
fn read_input_frame(
    input: &mut impl io::Read,
    maximum_payload_bytes: usize,
) -> Result<InputFrame, WindowsRuntimeError> {
    let mut header = [0_u8; 4];
    let mut offset = 0;
    while offset < header.len() {
        match input.read(&mut header[offset..]) {
            Ok(0) if offset == 0 => return Ok(InputFrame::Eof),
            Ok(0) => return Err(relay_failed()),
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(relay_failed()),
        }
    }
    let length = u32::from_le_bytes(header) as usize;
    if length == 0 || length > maximum_payload_bytes {
        return Err(relay_failed());
    }
    let mut payload = vec![0_u8; length];
    read_exact_or_fail(input, &mut payload)?;
    Ok(InputFrame::Payload(payload))
}

#[cfg(any(windows, test))]
fn write_output_frame(
    output: &mut impl io::Write,
    payload: &[u8],
    maximum_payload_bytes: usize,
) -> Result<(), WindowsRuntimeError> {
    if payload.is_empty() || payload.len() > maximum_payload_bytes {
        return Err(relay_failed());
    }
    let length = u32::try_from(payload.len()).map_err(|_| relay_failed())?;
    output
        .write_all(&length.to_le_bytes())
        .and_then(|()| output.write_all(payload))
        .and_then(|()| output.flush())
        .map_err(|_| relay_failed())
}

#[cfg(any(windows, test))]
fn read_exact_or_fail(
    input: &mut impl io::Read,
    mut destination: &mut [u8],
) -> Result<(), WindowsRuntimeError> {
    while !destination.is_empty() {
        match input.read(destination) {
            Ok(0) => return Err(relay_failed()),
            Ok(read) => destination = &mut destination[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(relay_failed()),
        }
    }
    Ok(())
}

#[cfg(any(windows, test))]
const fn relay_failed() -> WindowsRuntimeError {
    WindowsRuntimeError::new(
        WindowsRuntimeErrorCode::RelayFailed,
        "framed bridge relay failed",
    )
}

#[cfg(any(windows, test))]
const fn invalid_child_exit() -> WindowsRuntimeError {
    WindowsRuntimeError::new(
        WindowsRuntimeErrorCode::ChildExitInvalid,
        "stable bridge returned an invalid exit status",
    )
}

#[cfg(any(windows, test))]
const fn startup_failed() -> WindowsRuntimeError {
    WindowsRuntimeError::new(
        WindowsRuntimeErrorCode::StartupTimeout,
        "daemon startup could not complete",
    )
}

#[cfg(any(windows, test))]
fn runtime_lock_relative(product_relative_path: &str, file_name: &str) -> std::path::PathBuf {
    std::path::Path::new(product_relative_path)
        .join("run")
        .join(file_name)
}

#[cfg(any(windows, test))]
fn dashboard_diagnostic(address: std::net::SocketAddr) -> String {
    format!(
        "dashboard listening at http://{address}; one-time bootstrap URL is available through inspect_task"
    )
}

#[cfg(any(windows, test))]
fn optional_dashboard_start<T, A>(
    result: Result<(T, A), WindowsRuntimeError>,
    diagnostics: &mut impl io::Write,
) -> (Option<T>, Option<A>) {
    if let Ok((dashboard, access)) = result {
        (Some(dashboard), Some(access))
    } else {
        let _ = diagnostics
            .write_all(b"mesh-daemon: dashboard unavailable; authenticated MCP remains available\n")
            .and_then(|()| diagnostics.flush());
        (None, None)
    }
}

#[cfg(windows)]
mod platform {
    use std::{
        io::{self, Write},
        path::{Path, PathBuf},
        sync::{
            Arc,
            mpsc::{self, TryRecvError},
        },
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use mesh_win32::{
        EndpointKey, ExclusiveFileLock, NativeError, NativeErrorCode, PeerIdentityPolicy,
        PipeEndpoint, RESPONSE_FRAME_LIMIT, ScheduledTaskController, ScheduledTaskSpec,
        ScheduledTaskState, SecurePipeClient, SecurePipeConnection, SecurePipeServer, StorageError,
        open_or_create_product_control_root, sha256_file, unprotect_endpoint_key,
    };
    use rand::Rng;
    use sha2::{Digest, Sha256};

    use super::{
        CacheBootstrapOperations, DaemonStartupMilestone, DaemonStartupOrder, HANDSHAKE_RESERVE_MS,
        InputFrame, STARTUP_POLL_MAX_MS, STARTUP_TIMEOUT_MS, StartupOperations,
        WindowsRuntimeError, WindowsRuntimeErrorCode, bootstrap_cache, connect_or_start,
        dashboard_diagnostic, optional_dashboard_start, read_input_frame, relay_failed,
        runtime_lock_relative, startup_failed, startup_timeout, write_output_frame,
    };
    use crate::{
        daemon_runtime::{DaemonRuntime, DaemonRuntimeConfig, ShutdownSignal},
        dashboard::{DashboardSecret, DashboardState, SessionStore, bind_and_serve_loopback},
        install_record::{InstallRecord, InstallRecordStore, SignerStatus},
        install_store::{InstallStoreError, OrdinaryTrafficGuard, StableInstallRecordStore},
        protocol_client::{AuthenticatedClient, authenticate_client},
        protocol_handshake::{DaemonHealth, DaemonState, SessionError},
        reader::ReaderPool,
        router::{DashboardAccess, Router},
        settings::SettingsStore,
        storage::CURRENT_DATA_SCHEMA_VERSION,
        windows_install::WindowsSetupPlatform,
        writer::WriterHandle,
    };

    const STARTUP_LOCK_FILE: &str = "startup.lock";
    const DAEMON_LOCK_FILE: &str = "daemon.lock";
    const RUN_DIRECTORY: &str = "run";
    const CONNECT_PROBE_MS: u64 = 50;
    const CONFIG_READ_TIMEOUT: Duration = Duration::from_secs(5);
    const REMOVAL_POLL: Duration = Duration::from_millis(100);
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
    const REPLAY_CAPACITY: usize = 4_096;

    /// Cache-only trampoline. It holds the installation admission fence through
    /// exact retained-child creation, drops it immediately after `CreateProcess`,
    /// then waits and mirrors only a bounded 0..=255 process exit value.
    pub fn run_bridge_bootstrap() -> Result<u8, WindowsRuntimeError> {
        bootstrap_cache(&mut ProductionCacheBootstrap)
    }

    struct ProductionCacheBootstrap;

    impl CacheBootstrapOperations for ProductionCacheBootstrap {
        type Child = std::process::Child;

        fn spawn_exact_stable(&mut self) -> Result<Self::Child, WindowsRuntimeError> {
            let store = StableInstallRecordStore::open().map_err(map_store)?;
            let guard = store.acquire_ordinary_traffic_guard().map_err(map_store)?;
            let mut platform = platform_for(guard.record())?;
            // This audited method verifies the protected envelope but never
            // unprotects it and never derives or connects to the pipe.
            let child = platform.spawn_stable_bridge(&guard).map_err(map_control)?;
            drop(guard);
            Ok(child)
        }

        fn wait_child(
            &mut self,
            mut child: Self::Child,
        ) -> Result<Option<i32>, WindowsRuntimeError> {
            child
                .wait()
                .map(|status| status.code())
                .map_err(|_| storage_failed())
        }
    }

    /// Runs the exact retained bridge image and relays ordinary framed bytes
    /// only after mutual authentication reports `RUNNING` for this install.
    pub fn run_stable_bridge() -> Result<(), WindowsRuntimeError> {
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(STARTUP_TIMEOUT_MS))
            .ok_or_else(startup_failed)?;
        let store = StableInstallRecordStore::open().map_err(map_store)?;
        let initial_guard = acquire_active_guard_until(&store, deadline)?;
        let record = initial_guard.record().clone();
        let mut platform = platform_for(&record)?;
        platform
            .verify_current_is_stable(&record)
            .map_err(map_control)?;
        let root = open_or_create_product_control_root().map_err(map_storage)?;
        ensure_run_directory(&root, &record)?;
        let material = BridgeMaterial::load(&root, &record)?;
        initial_guard.revalidate_for_spawn().map_err(map_store)?;
        drop(initial_guard);

        let mut startup = RealStartup {
            origin: started,
            deadline,
            store: &store,
            record: &record,
            root: &root,
            material: &material,
            startup_lock: None,
        };
        let session = connect_or_start(&mut startup, STARTUP_TIMEOUT_MS)?;
        drop(startup);

        // Authentication is necessary but removal may have started while a
        // contender was polling. Re-admit the exact same ACTIVE bytes before
        // exposing the connection to stdio.
        let final_guard = acquire_active_guard_until(&store, deadline)?;
        if final_guard.record() != &record {
            return Err(identity_drift());
        }
        final_guard.revalidate_for_spawn().map_err(map_store)?;
        drop(final_guard);
        relay_authenticated(session)
    }

    /// Runs the scheduled stable daemon. Identity/secret/task checks precede
    /// the singleton lock; durable recovery precedes first-pipe ownership; and
    /// `RUNNING` is constructed only after the first listener is live.
    #[allow(clippy::too_many_lines)]
    pub fn run_daemon() -> Result<(), WindowsRuntimeError> {
        let mut order = DaemonStartupOrder::new();
        let store = StableInstallRecordStore::open().map_err(map_store)?;
        let initial_guard = store.acquire_ordinary_traffic_guard().map_err(map_store)?;
        let record = initial_guard.record().clone();
        let mut platform = platform_for(&record)?;
        let stable_image = platform
            .verify_current_is_stable(&record)
            .map_err(map_control)?;
        let root = open_or_create_product_control_root().map_err(map_storage)?;
        ensure_run_directory(&root, &record)?;
        let material = BridgeMaterial::load(&root, &record)?;
        verify_task(&record, &stable_image, material.runtime_digest)?;
        let BridgeMaterial {
            endpoint,
            peer_policy,
            endpoint_key,
            runtime_digest: _,
        } = material;
        order.advance(DaemonStartupMilestone::IdentityVerified)?;
        let daemon_lock_path = product_lock_path(&record, DAEMON_LOCK_FILE)?;
        let _daemon_lock = root
            .acquire_lifetime_lock(&daemon_lock_path)
            .map_err(map_native)?;
        order.advance(DaemonStartupMilestone::SingletonLocked)?;
        initial_guard.revalidate_for_spawn().map_err(map_store)?;
        drop(initial_guard);

        let data_root = data_root_path(&root, &record)?;
        let now_us = unix_time_us()?;
        let writer = WriterHandle::start_windows(
            data_root.clone(),
            record.install_id.as_str(),
            now_us,
            None,
        )
        .map_err(|_| storage_failed())?;
        let startup_result = (|| {
            let reader = ReaderPool::open(&data_root).map_err(|_| storage_failed())?;
            reader
                .empty_config(CONFIG_READ_TIMEOUT)
                .map_err(|_| identity_drift())?;
            writer
                .reconcile_nonterminal(record.consumer_id.as_str(), now_us)
                .map_err(|_| storage_failed())?;
            order.advance(DaemonStartupMilestone::StorageRecovered)?;

            // Removal is allowed to race durable recovery, but cannot cross
            // listener publication: final ACTIVE admission and exact identity
            // are checked again immediately before bind.
            let final_guard = store.acquire_ordinary_traffic_guard().map_err(map_store)?;
            if final_guard.record() != &record {
                return Err(identity_drift());
            }
            platform
                .verify_current_is_stable(final_guard.record())
                .map_err(map_control)?;
            let first_listener =
                SecurePipeServer::bind_first(&endpoint, peer_policy).map_err(map_native)?;
            order.advance(DaemonStartupMilestone::FirstPipeBound)?;
            final_guard.revalidate_for_spawn().map_err(map_store)?;

            let settings = SettingsStore::new(&data_root);
            let _ = crate::adapters::registry::seed_detected_adapters(&settings, now_us);
            let registry = crate::adapters::registry::AdapterRegistry::new(settings.clone());
            let (dashboard, dashboard_access) =
                start_optional_dashboard(&data_root, &record, reader.clone(), registry.clone());
            let dispatcher = crate::dispatcher::start(
                reader.clone(),
                writer.clone(),
                registry.clone(),
                record.consumer_id.as_str().to_owned(),
                data_root.clone(),
            );

            let generation = rand::rng().random_range(1..=MAX_SAFE_INTEGER);
            let started_at_ms = u64::try_from(now_us / 1_000).map_err(|_| storage_failed())?;
            let health = DaemonHealth::new(
                DaemonState::Running,
                record.install_id.as_str().to_owned(),
                record.consumer_id.as_str().to_owned(),
                env!("CARGO_PKG_VERSION").to_owned(),
                generation,
                u64::from(CURRENT_DATA_SCHEMA_VERSION),
                started_at_ms,
            )
            .map_err(map_session)?;
            let router = production_router(
                reader,
                &writer,
                &record,
                dashboard_access,
                registry,
                dispatcher.wake(),
            );
            let runtime = DaemonRuntime::new(
                endpoint_key,
                health,
                router,
                REPLAY_CAPACITY,
                DaemonRuntimeConfig::default(),
            )
            .map_err(|_| startup_failed())?;
            order.advance(DaemonStartupMilestone::RunningPublished)?;
            drop(final_guard);

            let shutdown = ShutdownSignal::new();
            let monitor_shutdown = shutdown.clone();
            let expected = record.clone();
            let monitor = thread::Builder::new()
                .name("mesh-install-state-monitor".into())
                .spawn(move || monitor_install_state(&expected, &monitor_shutdown))
                .map_err(|_| startup_failed())?;
            let serve_result = runtime
                .serve_secure_pipe(first_listener, &shutdown)
                .map_err(|_| transport_failed());
            shutdown.request();
            monitor.join().map_err(|_| startup_failed())?;
            if let Some(mut dashboard) = dashboard {
                dashboard.abort();
            }
            drop(dispatcher);
            serve_result.map(|_| ())
        })();
        let shutdown_result = writer.shutdown().map_err(|_| storage_failed());
        startup_result.and(shutdown_result)
    }

    struct ProductionDashboard {
        _runtime: tokio::runtime::Runtime,
        handle: tokio::task::JoinHandle<io::Result<()>>,
    }

    impl ProductionDashboard {
        fn start(
            data_root: &Path,
            record: &InstallRecord,
            reader: ReaderPool,
            registry: crate::adapters::registry::AdapterRegistry,
        ) -> Result<(Self, DashboardAccess), WindowsRuntimeError> {
            let _secret = DashboardSecret::load_or_create(data_root, record.install_id.as_str())
                .map_err(|_| storage_failed())?;
            let sessions = Arc::new(SessionStore::new());
            let state =
                DashboardState::new(reader, Arc::clone(&sessions), record.consumer_id.as_str())
                    .with_settings(SettingsStore::new(data_root), true)
                    .with_registry(registry);
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_io()
                .enable_time()
                .build()
                .map_err(|_| startup_failed())?;
            let (address, handle) = runtime
                .block_on(bind_and_serve_loopback(state))
                .map_err(|_| transport_failed())?;
            let access = DashboardAccess::new(address, sessions);
            write_dashboard_diagnostic(address);
            Ok((
                Self {
                    _runtime: runtime,
                    handle,
                },
                access,
            ))
        }

        fn abort(&mut self) {
            self.handle.abort();
        }
    }

    impl Drop for ProductionDashboard {
        fn drop(&mut self) {
            self.abort();
        }
    }

    fn start_optional_dashboard(
        data_root: &Path,
        record: &InstallRecord,
        reader: ReaderPool,
        registry: crate::adapters::registry::AdapterRegistry,
    ) -> (Option<ProductionDashboard>, Option<DashboardAccess>) {
        let result = ProductionDashboard::start(data_root, record, reader, registry);
        let mut stderr = io::stderr().lock();
        optional_dashboard_start(result, &mut stderr)
    }

    fn write_dashboard_diagnostic(address: std::net::SocketAddr) {
        let mut stderr = io::stderr().lock();
        let line = dashboard_diagnostic(address);
        let _ = stderr
            .write_all(b"mesh-daemon: ")
            .and_then(|()| stderr.write_all(line.as_bytes()))
            .and_then(|()| stderr.write_all(b"\n"))
            .and_then(|()| stderr.flush());
    }

    fn production_router(
        reader: ReaderPool,
        writer: &WriterHandle,
        record: &InstallRecord,
        dashboard: Option<DashboardAccess>,
        registry: crate::adapters::registry::AdapterRegistry,
        wake: crate::dispatcher::DispatchWake,
    ) -> Router {
        let router = Router::new(
            reader,
            writer.clone(),
            record.consumer_id.as_str().to_owned(),
        )
        .with_registry(registry)
        .with_dispatch_wake(wake);
        match dashboard {
            Some(dashboard) => router.with_dashboard(dashboard),
            None => router,
        }
    }

    struct BridgeMaterial {
        endpoint: PipeEndpoint,
        peer_policy: PeerIdentityPolicy,
        endpoint_key: EndpointKey,
        runtime_digest: [u8; 32],
    }

    impl BridgeMaterial {
        fn load(
            root: &mesh_win32::ValidatedControlRoot,
            record: &InstallRecord,
        ) -> Result<Self, WindowsRuntimeError> {
            let runtime = record.runtime.as_ref().ok_or_else(identity_drift)?;
            let runtime_digest = decode_lower_hex_32(runtime.sha256.as_str())?;
            let peer_policy = PeerIdentityPolicy::from_control_slot(
                root,
                Path::new(runtime.relative_path.as_str()),
                runtime_digest,
            )
            .map_err(map_native)?;
            let protected = record.protected_key.as_ref().ok_or_else(identity_drift)?;
            let envelope = root
                .read_endpoint_key_file(Path::new(protected.relative_path.as_str()))
                .map_err(map_storage)?;
            let observed: [u8; 32] = Sha256::digest(envelope.as_bytes()).into();
            if observed != decode_lower_hex_32(protected.sha256.as_str())? {
                return Err(identity_drift());
            }
            let endpoint_key = unprotect_endpoint_key(&envelope, record.install_id.as_str())
                .map_err(map_native)?;
            let endpoint =
                PipeEndpoint::for_current_user(record.install_id.as_str()).map_err(map_native)?;
            Ok(Self {
                endpoint,
                peer_policy,
                endpoint_key,
                runtime_digest,
            })
        }
    }

    struct RealStartup<'a> {
        origin: Instant,
        deadline: Instant,
        store: &'a StableInstallRecordStore,
        record: &'a InstallRecord,
        root: &'a mesh_win32::ValidatedControlRoot,
        material: &'a BridgeMaterial,
        startup_lock: Option<ExclusiveFileLock>,
    }

    impl StartupOperations for RealStartup<'_> {
        type Session = AuthenticatedClient<SecurePipeConnection>;

        fn now_ms(&self) -> u64 {
            u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
        }

        fn try_authenticated(&mut self) -> Result<Option<Self::Session>, WindowsRuntimeError> {
            if Instant::now()
                .checked_add(Duration::from_millis(HANDSHAKE_RESERVE_MS))
                .is_none_or(|reserved| reserved > self.deadline)
            {
                return Ok(None);
            }
            let connect_deadline = Instant::now()
                .checked_add(Duration::from_millis(CONNECT_PROBE_MS))
                .ok_or_else(startup_failed)?
                .min(self.deadline);
            let connection = match SecurePipeClient::connect(
                &self.material.endpoint,
                &self.material.peer_policy,
                connect_deadline,
            ) {
                Ok(connection) => connection,
                Err(error) if error.code() == NativeErrorCode::IoTimeout => return Ok(None),
                Err(error) => return Err(map_native(error)),
            };
            let authenticated = authenticate_client(
                connection,
                &self.material.endpoint_key,
                self.record.install_id.as_str().to_owned(),
                env!("CARGO_PKG_VERSION").to_owned(),
                u32::try_from(RESPONSE_FRAME_LIMIT).expect("response frame limit fits u32"),
            )
            .map_err(map_session)?;
            verify_health(authenticated.health(), self.record)?;
            Ok(Some(authenticated))
        }

        fn try_acquire_startup_lock(&mut self) -> Result<bool, WindowsRuntimeError> {
            let relative = product_lock_path(self.record, STARTUP_LOCK_FILE)?;
            match self.root.acquire_lifetime_lock(&relative) {
                Ok(lock) => {
                    self.startup_lock = Some(lock);
                    Ok(true)
                }
                Err(error) if error.code() == NativeErrorCode::SingletonConflict => Ok(false),
                Err(error) => Err(map_native(error)),
            }
        }

        fn recheck_and_request_task_start(&mut self) -> Result<(), WindowsRuntimeError> {
            if self.startup_lock.is_none() {
                return Err(startup_failed());
            }
            let guard = acquire_active_guard_until(self.store, self.deadline)?;
            if guard.record() != self.record {
                return Err(identity_drift());
            }
            let runtime = self.material.peer_policy.expected_image();
            let spec = verify_task(self.record, runtime, self.material.runtime_digest)?;
            let tasks = ScheduledTaskController::connect().map_err(map_native)?;
            let status = tasks.status(&spec).map_err(map_native)?;
            match status.state {
                ScheduledTaskState::Ready | ScheduledTaskState::Running => {}
                _ => return Err(task_unavailable()),
            }
            guard.revalidate_for_spawn().map_err(map_store)?;
            tasks.request_start(&spec).map_err(map_native)
        }

        fn release_startup_lock(&mut self) {
            drop(self.startup_lock.take());
        }

        fn next_poll_delay_ms(&mut self) -> u64 {
            rand::rng().random_range(1..=STARTUP_POLL_MAX_MS)
        }

        fn sleep_ms(&mut self, milliseconds: u64) {
            thread::sleep(Duration::from_millis(milliseconds));
        }
    }

    fn relay_authenticated(
        authenticated: AuthenticatedClient<SecurePipeConnection>,
    ) -> Result<(), WindowsRuntimeError> {
        let (pipe, _health, limits) = authenticated.into_parts();
        let request_limit =
            usize::try_from(limits.request_frame_bytes).map_err(|_| relay_failed())?;
        let response_limit =
            usize::try_from(limits.response_frame_bytes).map_err(|_| relay_failed())?;
        let write_timeout = Duration::from_millis(u64::from(limits.write_timeout_ms));
        let read_timeout = Duration::from_millis(
            u64::from(limits.max_wait_ms).saturating_add(u64::from(limits.write_timeout_ms)),
        );
        let (mut output_pipe, mut input_pipe) = pipe.into_duplex();
        let (finished_tx, finished_rx) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("mesh-bridge-stdin".into())
            .spawn(move || {
                let mut stdin = io::stdin();
                let result = loop {
                    match read_input_frame(&mut stdin, request_limit) {
                        Ok(InputFrame::Payload(payload)) => {
                            let Some(deadline) = Instant::now().checked_add(write_timeout) else {
                                break Err(relay_failed());
                            };
                            if input_pipe
                                .write_frame(&payload, request_limit, deadline)
                                .is_err()
                            {
                                break Err(relay_failed());
                            }
                        }
                        Ok(InputFrame::Eof) => break Ok(()),
                        Err(error) => break Err(error),
                    }
                };
                // Publish the exact stdin outcome before waking the sole read
                // half. Both halves share one native connection, so aborting
                // here cancels a pending output read instead of leaving this
                // helper alive until the maximum wait deadline.
                let _ = finished_tx.send(result);
                input_pipe.abort();
            })
            .map_err(|_| relay_failed())?;

        let mut stdout = io::stdout();
        loop {
            match finished_rx.try_recv() {
                Ok(result) => return result,
                Err(TryRecvError::Disconnected) => return Err(relay_failed()),
                Err(TryRecvError::Empty) => {}
            }
            let deadline = Instant::now()
                .checked_add(read_timeout)
                .ok_or_else(relay_failed)?;
            match output_pipe.read_frame(response_limit, deadline) {
                Ok(payload) => write_output_frame(&mut stdout, &payload, response_limit)?,
                // Native frame reads poison and abort the byte stream after
                // every error, including a deadline after a partial prefix or
                // body. Continuing would only delay the inevitable close and
                // could imply a resynchronization guarantee we do not have.
                Err(_) => {
                    return match finished_rx.try_recv() {
                        Ok(result) => result,
                        Err(TryRecvError::Disconnected | TryRecvError::Empty) => {
                            Err(relay_failed())
                        }
                    };
                }
            }
        }
    }

    fn acquire_active_guard_until(
        store: &StableInstallRecordStore,
        deadline: Instant,
    ) -> Result<OrdinaryTrafficGuard<'_>, WindowsRuntimeError> {
        loop {
            match store.acquire_ordinary_traffic_guard() {
                Ok(guard) => return Ok(guard),
                Err(InstallStoreError::AdmissionBusy) if Instant::now() < deadline => {
                    let jitter = rand::rng().random_range(1..=STARTUP_POLL_MAX_MS);
                    thread::sleep(Duration::from_millis(jitter));
                }
                Err(error) => return Err(map_store(error)),
            }
        }
    }

    fn verify_health(
        health: &DaemonHealth,
        record: &InstallRecord,
    ) -> Result<(), WindowsRuntimeError> {
        if health.state() != DaemonState::Running
            || health.install_id() != record.install_id.as_str()
            || health.consumer_id() != record.consumer_id.as_str()
            || health.daemon_version() != env!("CARGO_PKG_VERSION")
            || health.data_schema_version() != u64::from(CURRENT_DATA_SCHEMA_VERSION)
        {
            return Err(authentication_failed());
        }
        Ok(())
    }

    fn verify_task(
        record: &InstallRecord,
        stable_image: &Path,
        runtime_digest: [u8; 32],
    ) -> Result<ScheduledTaskSpec, WindowsRuntimeError> {
        if sha256_file(stable_image).map_err(map_native)? != runtime_digest {
            return Err(identity_drift());
        }
        let spec = ScheduledTaskSpec::new(record.install_id.as_str(), stable_image, runtime_digest)
            .map_err(map_native)?;
        let evidence = record.scheduled_task.as_ref().ok_or_else(identity_drift)?;
        if evidence.task_path.as_str() != spec.task_path()
            || decode_lower_hex_32(evidence.definition_sha256.as_str())?
                != *spec.expected_definition_digest()
        {
            return Err(identity_drift());
        }
        let tasks = ScheduledTaskController::connect().map_err(map_native)?;
        let status = tasks.status(&spec).map_err(map_native)?;
        if !matches!(
            status.state,
            ScheduledTaskState::Ready | ScheduledTaskState::Running
        ) || status.actual_definition_digest != Some(*spec.expected_definition_digest())
        {
            return Err(task_unavailable());
        }
        Ok(spec)
    }

    fn monitor_install_state(expected: &InstallRecord, shutdown: &ShutdownSignal) {
        while !shutdown.is_requested() {
            let active = StableInstallRecordStore::open()
                .and_then(|store| store.load())
                .is_ok_and(|record| record.as_ref() == Some(expected));
            if !active {
                shutdown.request();
                return;
            }
            thread::sleep(REMOVAL_POLL);
        }
    }

    fn platform_for(record: &InstallRecord) -> Result<WindowsSetupPlatform, WindowsRuntimeError> {
        let signer = record
            .runtime
            .as_ref()
            .ok_or_else(identity_drift)?
            .signer_status;
        match signer {
            SignerStatus::Signed => WindowsSetupPlatform::open_official_current_executable(),
            SignerStatus::UnsignedDevelopment => {
                WindowsSetupPlatform::open_unsigned_development_current_executable()
            }
        }
        .map_err(map_control)
    }

    fn product_lock_path(
        record: &InstallRecord,
        file_name: &str,
    ) -> Result<PathBuf, WindowsRuntimeError> {
        let product = record
            .product_relative_path
            .as_ref()
            .ok_or_else(identity_drift)?;
        Ok(runtime_lock_relative(product.as_str(), file_name))
    }

    fn ensure_run_directory(
        root: &mesh_win32::ValidatedControlRoot,
        record: &InstallRecord,
    ) -> Result<(), WindowsRuntimeError> {
        let product = record
            .product_relative_path
            .as_ref()
            .ok_or_else(identity_drift)?;
        root.create_relative_directories(&Path::new(product.as_str()).join(RUN_DIRECTORY))
            .map_err(map_storage)
    }

    fn data_root_path(
        root: &mesh_win32::ValidatedControlRoot,
        record: &InstallRecord,
    ) -> Result<PathBuf, WindowsRuntimeError> {
        let relative = record
            .data_relative_path
            .as_ref()
            .ok_or_else(identity_drift)?;
        Ok(root.path().join(relative.as_str()))
    }

    fn decode_lower_hex_32(value: &str) -> Result<[u8; 32], WindowsRuntimeError> {
        if value.len() != 64 {
            return Err(identity_drift());
        }
        let mut decoded = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            decoded[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(decoded)
    }

    fn nibble(value: u8) -> Result<u8, WindowsRuntimeError> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(identity_drift()),
        }
    }

    fn unix_time_us() -> Result<i64, WindowsRuntimeError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| storage_failed())?;
        i64::try_from(elapsed.as_micros()).map_err(|_| storage_failed())
    }

    fn map_store(error: InstallStoreError) -> WindowsRuntimeError {
        match error {
            InstallStoreError::OrdinaryTrafficUnavailable => admission_unavailable(),
            InstallStoreError::AdmissionBusy => WindowsRuntimeError::new(
                WindowsRuntimeErrorCode::AdmissionUnavailable,
                "installation admission is busy",
            ),
            InstallStoreError::InvalidRecord
            | InstallStoreError::Integrity
            | InstallStoreError::AdmissionChanged
            | InstallStoreError::CompareAndSwapConflict
            | InstallStoreError::PurgePrecondition
            | InstallStoreError::PurgeStageDrift => identity_drift(),
            InstallStoreError::Storage
            | InstallStoreError::Lock
            | InstallStoreError::AccessDenied => storage_failed(),
        }
    }

    fn map_control(error: crate::install_control::InstallControlError) -> WindowsRuntimeError {
        use crate::install_control::InstallControlError;
        match error {
            InstallControlError::Unavailable => admission_unavailable(),
            InstallControlError::Busy => WindowsRuntimeError::new(
                WindowsRuntimeErrorCode::AdmissionUnavailable,
                "installation admission is busy",
            ),
            InstallControlError::AccessDenied | InstallControlError::StorageUnavailable => {
                storage_failed()
            }
            _ => identity_drift(),
        }
    }

    fn map_native(error: NativeError) -> WindowsRuntimeError {
        match error.code() {
            NativeErrorCode::AuthenticationFailed => authentication_failed(),
            NativeErrorCode::IoTimeout => startup_timeout(),
            NativeErrorCode::SetupAbsent
            | NativeErrorCode::SetupDisabled
            | NativeErrorCode::SetupRemoving => admission_unavailable(),
            NativeErrorCode::SetupDrifted => identity_drift(),
            NativeErrorCode::ConnectionClosed
            | NativeErrorCode::FrameInvalid
            | NativeErrorCode::FrameTooLarge => transport_failed(),
            _ => storage_failed(),
        }
    }

    fn map_storage(_error: StorageError) -> WindowsRuntimeError {
        storage_failed()
    }

    fn map_session(error: SessionError) -> WindowsRuntimeError {
        use crate::ErrorCode;
        match error.code {
            ErrorCode::IpcAuthenticationFailed => authentication_failed(),
            ErrorCode::IpcIoTimeout => startup_timeout(),
            _ => transport_failed(),
        }
    }

    const fn admission_unavailable() -> WindowsRuntimeError {
        WindowsRuntimeError::new(
            WindowsRuntimeErrorCode::AdmissionUnavailable,
            "active installation is unavailable",
        )
    }

    const fn identity_drift() -> WindowsRuntimeError {
        WindowsRuntimeError::new(
            WindowsRuntimeErrorCode::IdentityDrift,
            "stable runtime identity verification failed",
        )
    }

    const fn authentication_failed() -> WindowsRuntimeError {
        WindowsRuntimeError::new(
            WindowsRuntimeErrorCode::AuthenticationFailed,
            "authenticated daemon readiness failed",
        )
    }

    const fn task_unavailable() -> WindowsRuntimeError {
        WindowsRuntimeError::new(
            WindowsRuntimeErrorCode::TaskUnavailable,
            "scheduled daemon task is unavailable",
        )
    }

    const fn transport_failed() -> WindowsRuntimeError {
        WindowsRuntimeError::new(
            WindowsRuntimeErrorCode::TransportFailed,
            "authenticated transport failed",
        )
    }

    const fn storage_failed() -> WindowsRuntimeError {
        WindowsRuntimeError::new(
            WindowsRuntimeErrorCode::StorageFailed,
            "runtime storage operation failed",
        )
    }
}

#[cfg(windows)]
pub use platform::{run_bridge_bootstrap, run_daemon, run_stable_bridge};

#[cfg(not(windows))]
pub fn run_bridge_bootstrap() -> Result<u8, WindowsRuntimeError> {
    Err(WindowsRuntimeError::new(
        WindowsRuntimeErrorCode::UnsupportedPlatform,
        "Windows runtime is unavailable on this platform",
    ))
}

#[cfg(not(windows))]
pub fn run_stable_bridge() -> Result<(), WindowsRuntimeError> {
    Err(WindowsRuntimeError::new(
        WindowsRuntimeErrorCode::UnsupportedPlatform,
        "Windows runtime is unavailable on this platform",
    ))
}

#[cfg(not(windows))]
pub fn run_daemon() -> Result<(), WindowsRuntimeError> {
    Err(WindowsRuntimeError::new(
        WindowsRuntimeErrorCode::UnsupportedPlatform,
        "Windows runtime is unavailable on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, io::Cursor};

    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FakeSession(u64);

    struct FakeStartup {
        now_ms: u64,
        connects: VecDeque<Option<FakeSession>>,
        lock_won: bool,
        lock_held: bool,
        start_calls: usize,
        sleeps: Vec<u64>,
    }

    struct FakeCache {
        calls: Vec<&'static str>,
        exit: Option<i32>,
    }

    impl CacheBootstrapOperations for FakeCache {
        type Child = ();

        fn spawn_exact_stable(&mut self) -> Result<Self::Child, WindowsRuntimeError> {
            self.calls.push("spawn_exact_stable");
            Ok(())
        }

        fn wait_child(&mut self, (): Self::Child) -> Result<Option<i32>, WindowsRuntimeError> {
            self.calls.push("wait_child");
            Ok(self.exit)
        }
    }

    #[test]
    fn cache_capability_surface_only_spawns_stable_then_waits() {
        let mut fake = FakeCache {
            calls: Vec::new(),
            exit: Some(17),
        };
        assert_eq!(bootstrap_cache(&mut fake).unwrap(), 17);
        assert_eq!(fake.calls, ["spawn_exact_stable", "wait_child"]);

        fake.calls.clear();
        fake.exit = Some(256);
        assert_eq!(
            bootstrap_cache(&mut fake).unwrap_err().code(),
            WindowsRuntimeErrorCode::ChildExitInvalid
        );
    }

    #[test]
    fn runtime_failures_use_the_frozen_process_exit_classes() {
        for code in [
            WindowsRuntimeErrorCode::AdmissionUnavailable,
            WindowsRuntimeErrorCode::IdentityDrift,
            WindowsRuntimeErrorCode::TaskUnavailable,
            WindowsRuntimeErrorCode::UnsupportedPlatform,
        ] {
            assert_eq!(
                WindowsRuntimeError::new(code, "test").exit_code(),
                crate::cli::EXIT_LIFECYCLE
            );
        }
        assert_eq!(
            WindowsRuntimeError::new(WindowsRuntimeErrorCode::StartupTimeout, "test").exit_code(),
            crate::cli::EXIT_TIMEOUT
        );
        for code in [
            WindowsRuntimeErrorCode::AuthenticationFailed,
            WindowsRuntimeErrorCode::TransportFailed,
            WindowsRuntimeErrorCode::StorageFailed,
            WindowsRuntimeErrorCode::RelayFailed,
            WindowsRuntimeErrorCode::ChildExitInvalid,
        ] {
            assert_eq!(
                WindowsRuntimeError::new(code, "test").exit_code(),
                crate::cli::EXIT_RUNTIME
            );
        }
    }

    #[test]
    fn dashboard_diagnostic_contains_only_the_token_free_base_url() {
        let notice = dashboard_diagnostic("127.0.0.1:43127".parse().unwrap());
        assert!(notice.contains("http://127.0.0.1:43127"));
        assert!(notice.contains("inspect_task"));
        assert!(!notice.contains("/bootstrap?token="));
    }

    #[test]
    fn dashboard_start_failure_disables_only_the_browser_capability() {
        let failure = WindowsRuntimeError::new(
            WindowsRuntimeErrorCode::StorageFailed,
            "injected dashboard failure with token=secret",
        );
        let mut diagnostics = Vec::new();
        let (dashboard, access) =
            optional_dashboard_start::<(), ()>(Err(failure), &mut diagnostics);

        assert!(dashboard.is_none());
        assert!(access.is_none());
        assert_eq!(
            String::from_utf8(diagnostics).unwrap(),
            "mesh-daemon: dashboard unavailable; authenticated MCP remains available\n"
        );
    }

    #[test]
    fn dashboard_start_success_preserves_both_capabilities_without_extra_diagnostic() {
        let mut diagnostics = Vec::new();
        let (dashboard, access) = optional_dashboard_start::<u8, u8>(Ok((7, 9)), &mut diagnostics);

        assert_eq!(dashboard, Some(7));
        assert_eq!(access, Some(9));
        assert!(diagnostics.is_empty());
    }

    #[test]
    fn daemon_readiness_order_rejects_early_publication() {
        let mut order = DaemonStartupOrder::new();
        assert_eq!(
            order
                .advance(DaemonStartupMilestone::RunningPublished)
                .unwrap_err()
                .code(),
            WindowsRuntimeErrorCode::StartupTimeout
        );

        let mut order = DaemonStartupOrder::new();
        for milestone in DaemonStartupOrder::ORDER {
            order.advance(milestone).unwrap();
        }
        assert_eq!(order.next, DaemonStartupOrder::ORDER.len());
    }

    #[test]
    fn runtime_locks_share_the_control_run_namespace() {
        let product = r"installs\0123456789abcdef0123456789abcdef";
        assert_eq!(
            runtime_lock_relative(product, "startup.lock"),
            std::path::Path::new(product)
                .join("run")
                .join("startup.lock")
        );
        assert_eq!(
            runtime_lock_relative(product, "daemon.lock"),
            std::path::Path::new(product)
                .join("run")
                .join("daemon.lock")
        );
    }

    impl StartupOperations for FakeStartup {
        type Session = FakeSession;

        fn now_ms(&self) -> u64 {
            self.now_ms
        }

        fn try_authenticated(&mut self) -> Result<Option<Self::Session>, WindowsRuntimeError> {
            self.now_ms = self.now_ms.saturating_add(25);
            Ok(self.connects.pop_front().flatten())
        }

        fn try_acquire_startup_lock(&mut self) -> Result<bool, WindowsRuntimeError> {
            self.lock_held = self.lock_won;
            Ok(self.lock_won)
        }

        fn recheck_and_request_task_start(&mut self) -> Result<(), WindowsRuntimeError> {
            assert!(self.lock_held);
            self.start_calls += 1;
            Ok(())
        }

        fn release_startup_lock(&mut self) {
            self.lock_held = false;
        }

        fn next_poll_delay_ms(&mut self) -> u64 {
            10
        }

        fn sleep_ms(&mut self, milliseconds: u64) {
            self.sleeps.push(milliseconds);
            self.now_ms = self.now_ms.saturating_add(milliseconds);
        }
    }

    #[test]
    fn startup_winner_rechecks_then_requests_task_exactly_once() {
        let mut fake = FakeStartup {
            now_ms: 0,
            connects: VecDeque::from([None, None, None, Some(FakeSession(7))]),
            lock_won: true,
            lock_held: false,
            start_calls: 0,
            sleeps: Vec::new(),
        };
        assert_eq!(
            connect_or_start(&mut fake, STARTUP_TIMEOUT_MS).unwrap(),
            FakeSession(7)
        );
        assert_eq!(fake.start_calls, 1);
        assert!(!fake.lock_held);
    }

    #[test]
    fn startup_loser_never_requests_task_and_observes_winner() {
        let mut fake = FakeStartup {
            now_ms: 0,
            connects: VecDeque::from([None, None, Some(FakeSession(9))]),
            lock_won: false,
            lock_held: false,
            start_calls: 0,
            sleeps: Vec::new(),
        };
        assert_eq!(
            connect_or_start(&mut fake, STARTUP_TIMEOUT_MS).unwrap(),
            FakeSession(9)
        );
        assert_eq!(fake.start_calls, 0);
    }

    #[test]
    fn startup_deadline_reserves_handshake_and_never_exceeds_fifteen_seconds() {
        let mut fake = FakeStartup {
            now_ms: 0,
            connects: VecDeque::new(),
            lock_won: true,
            lock_held: false,
            start_calls: 0,
            sleeps: Vec::new(),
        };
        let error = connect_or_start(&mut fake, STARTUP_TIMEOUT_MS).unwrap_err();
        assert_eq!(error.code(), WindowsRuntimeErrorCode::StartupTimeout);
        assert_eq!(fake.now_ms, STARTUP_TIMEOUT_MS);
        assert_eq!(fake.start_calls, 1);
        assert!(!fake.lock_held);
    }

    #[test]
    fn relay_preserves_payload_across_split_reads_and_coalesced_frames() {
        let first = br#"{\"jsonrpc\":\"2.0\",\"id\":1}"#;
        let second = br#"{\"jsonrpc\":\"2.0\",\"id\":2}"#;
        let mut bytes = Vec::new();
        write_output_frame(&mut bytes, first, 1024).unwrap();
        write_output_frame(&mut bytes, second, 1024).unwrap();
        let mut input = OneByteReader(Cursor::new(bytes));
        let InputFrame::Payload(observed_first) = read_input_frame(&mut input, 1024).unwrap()
        else {
            panic!("expected first payload");
        };
        let InputFrame::Payload(observed_second) = read_input_frame(&mut input, 1024).unwrap()
        else {
            panic!("expected second payload");
        };
        assert_eq!(observed_first, first);
        assert_eq!(observed_second, second);
        assert!(matches!(
            read_input_frame(&mut input, 1024).unwrap(),
            InputFrame::Eof
        ));
    }

    #[test]
    fn relay_treats_mid_frame_eof_and_zero_length_as_fail_closed() {
        let mut partial = Cursor::new([4_u8, 0, 0, 0, b'a']);
        assert_eq!(
            read_input_frame(&mut partial, 16).unwrap_err().code(),
            WindowsRuntimeErrorCode::RelayFailed
        );
        let mut zero = Cursor::new([0_u8; 4]);
        assert_eq!(
            read_input_frame(&mut zero, 16).unwrap_err().code(),
            WindowsRuntimeErrorCode::RelayFailed
        );
    }

    struct OneByteReader<R>(R);

    impl<R: io::Read> io::Read for OneByteReader<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let length = buffer.len().min(1);
            self.0.read(&mut buffer[..length])
        }
    }
}
