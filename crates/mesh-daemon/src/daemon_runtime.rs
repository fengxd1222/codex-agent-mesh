//! Bounded authenticated daemon server runtime.
//!
//! Startup/install verification owns construction of [`DaemonHealth`], the
//! endpoint key, and the first `FILE_FLAG_FIRST_PIPE_INSTANCE` listener. This
//! module owns only the final serving cut: it keeps one successor listener live
//! before consuming the current listener, authenticates every accepted peer,
//! and gives only [`PendingRequest`] capabilities to the durable router.

#![allow(clippy::missing_errors_doc)]

use std::{
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError, TryRecvError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use mesh_win32::{EndpointKey, NonceReplayGuard};

use crate::{
    ErrorCode,
    protocol_handshake::{
        AcceptedSession, DaemonHealth, DaemonState, PendingRequest, RpcMethod, RpcResponse,
        SessionError, SplittableFramedTransport,
    },
    router::{Router, RouterClock, RouterSleeper},
};

/// The named-pipe implementation allows 32 instances. One instance is always
/// reserved as the next listener, leaving at most 31 connected workers.
pub const MAX_CONNECTION_WORKERS: usize = 31;
pub const DEFAULT_CONNECTION_WORKERS: usize = 16;

const DEFAULT_ACCEPT_POLL: Duration = Duration::from_millis(100);
const DEFAULT_SHUTDOWN_GRACE: Duration = Duration::from_secs(40);
const MIN_ACCEPT_POLL: Duration = Duration::from_millis(1);
const MAX_ACCEPT_POLL: Duration = Duration::from_secs(1);
const MAX_SHUTDOWN_GRACE: Duration = Duration::from_mins(1);
const MIN_REPLAY_CAPACITY: usize = 32;
const MAX_REPLAY_CAPACITY: usize = 65_536;

/// Narrow request boundary used by the server and deterministic fakes.
///
/// Taking a non-cloneable [`PendingRequest`] prevents a server implementation
/// from rebuilding JSON-RPC IDs or bypassing the authenticated connection's
/// duplicate-ID and sixteen-in-flight admission checks.
pub trait SessionRouter: Send + Sync + 'static {
    fn route(&self, request: PendingRequest) -> Result<RpcResponse, SessionError>;
}

impl<C, S> SessionRouter for Router<C, S>
where
    C: RouterClock + Send + Sync + 'static,
    S: RouterSleeper + Send + Sync + 'static,
{
    fn route(&self, request: PendingRequest) -> Result<RpcResponse, SessionError> {
        Router::route(self, request)
    }
}

/// Explicit, cloneable daemon shutdown signal.
#[derive(Clone, Default)]
pub struct ShutdownSignal {
    requested: Arc<AtomicBool>,
    admission_fence: Arc<Mutex<()>>,
}

impl ShutdownSignal {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn request(&self) {
        let _fence = self
            .admission_fence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.requested.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }
}

impl fmt::Debug for ShutdownSignal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShutdownSignal")
            .field("requested", &self.is_requested())
            .finish()
    }
}

/// Bounded serving policy. Values outside the audited range are rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonRuntimeConfig {
    pub maximum_connections: usize,
    pub accept_poll_interval: Duration,
    pub shutdown_grace: Duration,
}

impl Default for DaemonRuntimeConfig {
    fn default() -> Self {
        Self {
            maximum_connections: DEFAULT_CONNECTION_WORKERS,
            accept_poll_interval: DEFAULT_ACCEPT_POLL,
            shutdown_grace: DEFAULT_SHUTDOWN_GRACE,
        }
    }
}

impl DaemonRuntimeConfig {
    fn validate(self) -> Result<Self, RuntimeError> {
        if !(1..=MAX_CONNECTION_WORKERS).contains(&self.maximum_connections)
            || !(MIN_ACCEPT_POLL..=MAX_ACCEPT_POLL).contains(&self.accept_poll_interval)
            || self.shutdown_grace > MAX_SHUTDOWN_GRACE
        {
            return Err(RuntimeError::invalid_configuration());
        }
        Ok(self)
    }
}

/// Stable runtime failure category. Native/transport details are never stored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeErrorCode {
    InvalidConfiguration,
    StartupNotReady,
    ListenerUnavailable,
}

/// Redaction-safe fatal server error.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RuntimeError {
    code: RuntimeErrorCode,
    message: &'static str,
}

impl RuntimeError {
    const fn invalid_configuration() -> Self {
        Self {
            code: RuntimeErrorCode::InvalidConfiguration,
            message: "daemon runtime configuration is invalid",
        }
    }

    const fn listener_unavailable() -> Self {
        Self {
            code: RuntimeErrorCode::ListenerUnavailable,
            message: "authenticated listener is unavailable",
        }
    }

    const fn startup_not_ready() -> Self {
        Self {
            code: RuntimeErrorCode::StartupNotReady,
            message: "daemon startup verification is incomplete",
        }
    }

    #[must_use]
    pub const fn code(self) -> RuntimeErrorCode {
        self.code
    }

    #[must_use]
    pub const fn message(self) -> &'static str {
        self.message
    }
}

impl fmt::Debug for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeError")
            .field("code", &self.code)
            .field("message", &self.message)
            .finish()
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for RuntimeError {}

/// Safe per-connection result suitable for aggregate telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectionReport {
    pub authenticated: bool,
    pub completed_requests: u64,
    pub terminal_error: Option<ErrorCode>,
    pub shutdown_observed: bool,
}

impl ConnectionReport {
    const fn failed_before_auth(error: SessionError) -> Self {
        Self {
            authenticated: false,
            completed_requests: 0,
            terminal_error: Some(error.code),
            shutdown_observed: false,
        }
    }
}

/// Aggregate server result. A nonzero detached count means shutdown returned
/// after its explicit grace period instead of blocking forever.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ServerReport {
    pub accepted_connections: u64,
    pub rejected_connections: u64,
    pub completed_connections: u64,
    pub failed_connections: u64,
    pub completed_requests: u64,
    pub detached_on_shutdown: u64,
}

struct SharedRuntime<R> {
    endpoint_key: EndpointKey,
    replay_guard: NonceReplayGuard,
    health: DaemonHealth,
    router: R,
}

/// Authenticated server state shared by the bounded connection workers.
pub struct DaemonRuntime<R> {
    shared: Arc<SharedRuntime<R>>,
    config: DaemonRuntimeConfig,
}

impl<R: SessionRouter> DaemonRuntime<R> {
    /// Builds one generation-scoped runtime after storage/config/install
    /// verification has published `RUNNING` health.
    pub fn new(
        endpoint_key: EndpointKey,
        health: DaemonHealth,
        router: R,
        replay_capacity: usize,
        config: DaemonRuntimeConfig,
    ) -> Result<Self, RuntimeError> {
        if health.state() != DaemonState::Running {
            return Err(RuntimeError::startup_not_ready());
        }
        if !(MIN_REPLAY_CAPACITY..=MAX_REPLAY_CAPACITY).contains(&replay_capacity) {
            return Err(RuntimeError::invalid_configuration());
        }
        Ok(Self {
            shared: Arc::new(SharedRuntime {
                endpoint_key,
                replay_guard: NonceReplayGuard::new(replay_capacity),
                health,
                router,
            }),
            config: config.validate()?,
        })
    }

    /// Drives one injected framed transport through hello, auth, health/task
    /// requests, and bound responses. This is also the unit-test seam.
    #[must_use]
    pub fn serve_transport<T>(&self, transport: T, shutdown: &ShutdownSignal) -> ConnectionReport
    where
        T: SplittableFramedTransport,
    {
        serve_transport(&self.shared, transport, shutdown)
    }

    fn serve_listener<L>(
        &self,
        first_listener: L,
        shutdown: &ShutdownSignal,
    ) -> Result<ServerReport, RuntimeError>
    where
        L: ConnectionListener,
        L::Transport: Send + 'static,
    {
        let mut listener = first_listener;
        let mut workers: Vec<JoinHandle<ConnectionReport>> = Vec::new();
        let mut report = ServerReport::default();

        while !shutdown.is_requested() {
            reap_finished_workers(&mut workers, &mut report);
            if workers.len() >= self.config.maximum_connections {
                thread::sleep(self.config.accept_poll_interval);
                continue;
            }

            // The successor must exist before `accept` consumes the current
            // instance. Therefore the original FIRST_PIPE_INSTANCE ownership is
            // continuously represented until intentional shutdown.
            let Ok(next_listener) = listener.bind_additional() else {
                shutdown.request();
                drop(listener);
                finish_workers(&mut workers, &mut report, self.config.shutdown_grace);
                return Err(RuntimeError::listener_unavailable());
            };
            let Some(accept_deadline) =
                Instant::now().checked_add(self.config.accept_poll_interval)
            else {
                shutdown.request();
                drop(listener);
                drop(next_listener);
                finish_workers(&mut workers, &mut report, self.config.shutdown_grace);
                return Err(RuntimeError::invalid_configuration());
            };
            let accepted = listener.accept(accept_deadline);
            listener = next_listener;

            match accepted {
                Ok(transport) => {
                    report.accepted_connections = report.accepted_connections.saturating_add(1);
                    let shared = Arc::clone(&self.shared);
                    let worker_shutdown = shutdown.clone();
                    let worker = thread::Builder::new()
                        .name("mesh-daemon-connection".into())
                        .spawn(move || serve_transport(&shared, transport, &worker_shutdown));
                    let Ok(worker) = worker else {
                        shutdown.request();
                        drop(listener);
                        finish_workers(&mut workers, &mut report, self.config.shutdown_grace);
                        return Err(RuntimeError::listener_unavailable());
                    };
                    workers.push(worker);
                }
                Err(AcceptFailure::Timeout) => {}
                Err(AcceptFailure::Rejected) => {
                    report.rejected_connections = report.rejected_connections.saturating_add(1);
                }
                Err(AcceptFailure::Fatal) => {
                    shutdown.request();
                    drop(listener);
                    finish_workers(&mut workers, &mut report, self.config.shutdown_grace);
                    return Err(RuntimeError::listener_unavailable());
                }
            }
        }

        drop(listener);
        finish_workers(&mut workers, &mut report, self.config.shutdown_grace);
        Ok(report)
    }

    /// Runs the production Windows pipe listener. `first_listener` must be the
    /// still-live value returned by `SecurePipeServer::bind_first`.
    #[cfg(windows)]
    pub fn serve_secure_pipe(
        &self,
        first_listener: mesh_win32::SecurePipeServer,
        shutdown: &ShutdownSignal,
    ) -> Result<ServerReport, RuntimeError> {
        self.serve_listener(first_listener, shutdown)
    }
}

// The orchestration stays linear so the admission, reader, route-worker, and
// writer shutdown order can be audited as one lifetime protocol.
#[allow(clippy::too_many_lines)]
fn serve_transport<T, R>(
    shared: &Arc<SharedRuntime<R>>,
    transport: T,
    shutdown: &ShutdownSignal,
) -> ConnectionReport
where
    T: SplittableFramedTransport,
    R: SessionRouter,
{
    let challenged = match AcceptedSession::new(
        transport,
        &shared.endpoint_key,
        &shared.replay_guard,
        shared.health.clone(),
    )
    .receive_hello()
    {
        Ok(challenged) => challenged,
        Err(error) => return ConnectionReport::failed_before_auth(error),
    };
    let session = match challenged.receive_auth() {
        Ok(session) => session,
        Err(error) => return ConnectionReport::failed_before_auth(error),
    };
    let limits = session.negotiated_limits();
    let maximum_in_flight = usize::try_from(limits.max_in_flight).unwrap_or(0);
    if maximum_in_flight == 0 || maximum_in_flight > 16 {
        return ConnectionReport {
            authenticated: true,
            completed_requests: 0,
            terminal_error: Some(ErrorCode::ValidationFailed),
            shutdown_observed: false,
        };
    }
    let read_timeout = Duration::from_millis(
        u64::from(limits.max_wait_ms).saturating_add(u64::from(limits.write_timeout_ms)),
    );
    let (mut reader, mut writer) = session.into_duplex();
    let (response_tx, response_rx) =
        mpsc::sync_channel::<Result<RpcResponse, SessionError>>(maximum_in_flight);
    let (control_tx, control_rx) = mpsc::channel();
    let terminal_slot = Arc::new(Mutex::new(None));
    let completed_requests = Arc::new(AtomicU64::new(0));
    let writer_terminal = Arc::clone(&terminal_slot);
    let writer_completed = Arc::clone(&completed_requests);
    let Ok(writer_thread) = thread::Builder::new()
        .name("mesh-daemon-writer".into())
        .spawn(move || {
            loop {
                match control_rx.try_recv() {
                    Ok(code) => {
                        set_terminal_error(&writer_terminal, code);
                        writer.abort_connection();
                        break;
                    }
                    Err(TryRecvError::Disconnected | TryRecvError::Empty) => {}
                }
                match response_rx.recv_timeout(Duration::from_millis(1)) {
                    Ok(Ok(response)) => {
                        if terminal_error(&writer_terminal).is_some() {
                            drop(response);
                            writer.abort_connection();
                            break;
                        }
                        match writer.write_response(response) {
                            Ok(()) => {
                                writer_completed.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(error) => {
                                set_terminal_error(&writer_terminal, error.code);
                                writer.abort_connection();
                                break;
                            }
                        }
                    }
                    Ok(Err(error)) => {
                        set_terminal_error(&writer_terminal, error.code);
                        writer.abort_connection();
                        break;
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {}
                }
            }
        })
    else {
        reader.abort_connection();
        return ConnectionReport {
            authenticated: true,
            completed_requests: 0,
            terminal_error: Some(ErrorCode::ProtocolMalformed),
            shutdown_observed: false,
        };
    };

    let mut route_workers = Vec::with_capacity(maximum_in_flight);
    let mut shutdown_observed = false;
    loop {
        reap_route_workers(&mut route_workers, &terminal_slot);
        if shutdown.is_requested() {
            shutdown_observed = true;
            break;
        }
        if terminal_error(&terminal_slot).is_some() {
            reader.abort_connection();
            break;
        }
        let Some(read_deadline) = Instant::now().checked_add(read_timeout) else {
            set_terminal_error(&terminal_slot, ErrorCode::ProtocolMalformed);
            let _ = control_tx.send(ErrorCode::ProtocolMalformed);
            reader.abort_connection();
            break;
        };
        let request = match reader.read_request_until(read_deadline) {
            Ok(request) => request,
            Err(error) => {
                if shutdown.is_requested() {
                    shutdown_observed = true;
                } else if terminal_error(&terminal_slot).is_none() {
                    set_terminal_error(&terminal_slot, error.code);
                    let _ = control_tx.send(error.code);
                }
                reader.abort_connection();
                break;
            }
        };

        // `request()` and this admission section use the same lock. Therefore
        // either this capability is fully assigned to a bounded worker before
        // the shutdown fence, or the request is dropped without router entry.
        let admission = shutdown
            .admission_fence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if shutdown.is_requested() {
            shutdown_observed = true;
            drop(request);
            drop(admission);
            break;
        }
        if terminal_error(&terminal_slot).is_some() {
            drop(request);
            drop(admission);
            reader.abort_connection();
            break;
        }
        if request.method() == RpcMethod::Health {
            let response = reader.health_response(request);
            if response_tx.send(response).is_err() {
                set_terminal_error(&terminal_slot, ErrorCode::ProtocolMalformed);
                reader.abort_connection();
                drop(admission);
                break;
            }
            drop(admission);
            continue;
        }

        let route_shared = Arc::clone(shared);
        let route_tx = response_tx.clone();
        if let Ok(worker) = thread::Builder::new()
            .name("mesh-daemon-route".into())
            .spawn(move || {
                let response = route_shared.router.route(request);
                let _ = route_tx.send(response);
            })
        {
            route_workers.push(worker);
        } else {
            set_terminal_error(&terminal_slot, ErrorCode::ProtocolMalformed);
            let _ = control_tx.send(ErrorCode::ProtocolMalformed);
            reader.abort_connection();
            drop(admission);
            break;
        }
        drop(admission);
    }

    drop(reader);
    drop(response_tx);
    for worker in route_workers {
        if worker.join().is_err() {
            set_terminal_error(&terminal_slot, ErrorCode::ProtocolMalformed);
            let _ = control_tx.send(ErrorCode::ProtocolMalformed);
        }
    }
    drop(control_tx);
    if writer_thread.join().is_err() {
        set_terminal_error(&terminal_slot, ErrorCode::ProtocolMalformed);
    }
    let terminal_error = terminal_error(&terminal_slot);
    ConnectionReport {
        authenticated: true,
        completed_requests: completed_requests.load(Ordering::Relaxed),
        terminal_error,
        shutdown_observed: shutdown_observed && terminal_error.is_none(),
    }
}

fn set_terminal_error(slot: &Mutex<Option<ErrorCode>>, code: ErrorCode) {
    let mut slot = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    slot.get_or_insert(code);
}

fn terminal_error(slot: &Mutex<Option<ErrorCode>>) -> Option<ErrorCode> {
    *slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn reap_route_workers(workers: &mut Vec<JoinHandle<()>>, terminal: &Mutex<Option<ErrorCode>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            if workers.swap_remove(index).join().is_err() {
                set_terminal_error(terminal, ErrorCode::ProtocolMalformed);
            }
        } else {
            index += 1;
        }
    }
}

fn reap_finished_workers(
    workers: &mut Vec<JoinHandle<ConnectionReport>>,
    report: &mut ServerReport,
) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            let result = worker.join();
            fold_worker(&result, report);
        } else {
            index += 1;
        }
    }
}

fn finish_workers(
    workers: &mut Vec<JoinHandle<ConnectionReport>>,
    report: &mut ServerReport,
    grace: Duration,
) {
    let deadline = Instant::now().checked_add(grace);
    loop {
        reap_finished_workers(workers, report);
        if workers.is_empty() {
            return;
        }
        if deadline.is_none_or(|deadline| Instant::now() >= deadline) {
            report.detached_on_shutdown = u64::try_from(workers.len()).unwrap_or(u64::MAX);
            workers.clear();
            return;
        }
        thread::sleep(Duration::from_millis(1));
    }
}

fn fold_worker(result: &thread::Result<ConnectionReport>, report: &mut ServerReport) {
    match result {
        Ok(connection) => {
            report.completed_connections = report.completed_connections.saturating_add(1);
            report.completed_requests = report
                .completed_requests
                .saturating_add(connection.completed_requests);
            if connection.terminal_error.is_some() {
                report.failed_connections = report.failed_connections.saturating_add(1);
            }
        }
        Err(_) => {
            report.failed_connections = report.failed_connections.saturating_add(1);
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcceptFailure {
    Timeout,
    Rejected,
    Fatal,
}

trait ConnectionListener: Send + Sized + 'static {
    type Transport: SplittableFramedTransport;

    fn bind_additional(&self) -> Result<Self, AcceptFailure>;
    fn accept(self, deadline: Instant) -> Result<Self::Transport, AcceptFailure>;
}

#[cfg(windows)]
impl ConnectionListener for mesh_win32::SecurePipeServer {
    type Transport = mesh_win32::SecurePipeConnection;

    fn bind_additional(&self) -> Result<Self, AcceptFailure> {
        mesh_win32::SecurePipeServer::bind_additional(self).map_err(|_| AcceptFailure::Fatal)
    }

    fn accept(self, deadline: Instant) -> Result<Self::Transport, AcceptFailure> {
        mesh_win32::SecurePipeServer::accept(self, deadline).map_err(|error| match error.code() {
            mesh_win32::NativeErrorCode::IoTimeout => AcceptFailure::Timeout,
            mesh_win32::NativeErrorCode::AuthenticationFailed
            | mesh_win32::NativeErrorCode::ConnectionClosed
            | mesh_win32::NativeErrorCode::AccessDenied
            | mesh_win32::NativeErrorCode::SetupDrifted
            | mesh_win32::NativeErrorCode::SetupAccessDenied => AcceptFailure::Rejected,
            _ => AcceptFailure::Fatal,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{
            Condvar, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use mesh_win32::{
        AUTH_TAG_LENGTH, ClientAuth, ClientHello, NONCE_LENGTH, Nonce, PROTOCOL_VERSION_V1,
        ServerChallenge, WIRE_MAJOR_V1, WIRE_MINOR_V1, WireLimitsV1,
    };
    use serde_json::{Value, json};

    use super::*;
    use crate::protocol_handshake::{
        FramedReadHalf, FramedTransport, FramedWriteHalf, RpcEffectClass, RpcErrorSpec,
        RpcLifecycle, RpcRetryClass,
    };

    const KEY_BYTES: [u8; AUTH_TAG_LENGTH] = [7; AUTH_TAG_LENGTH];

    struct FakeRouter {
        calls: AtomicUsize,
        shutdown: ShutdownSignal,
    }

    impl SessionRouter for FakeRouter {
        fn route(&self, request: PendingRequest) -> Result<RpcResponse, SessionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.shutdown.request();
            request.success(&json!({
                "kind": "list_agents_result",
                "agents": [],
                "config_version": 1
            }))
        }
    }

    struct RejectingRouter {
        calls: AtomicUsize,
    }

    impl SessionRouter for RejectingRouter {
        fn route(&self, request: PendingRequest) -> Result<RpcResponse, SessionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            request.error(&RpcErrorSpec::new(
                -32_000,
                ErrorCode::ValidationFailed,
                RpcRetryClass::DeterministicFailure,
                RpcEffectClass::NoEffect,
                RpcLifecycle::BeforeProcessCreation,
                "fake_router".into(),
                "request rejected".into(),
                "fake".into(),
            ))
        }
    }

    struct CountingRouter {
        calls: Arc<AtomicUsize>,
    }

    struct GatedRouter {
        calls: Arc<AtomicUsize>,
        gate: Arc<(Mutex<bool>, Condvar)>,
    }

    impl SessionRouter for GatedRouter {
        fn route(&self, request: PendingRequest) -> Result<RpcResponse, SessionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if request.method() == RpcMethod::WaitTask || request.method() == RpcMethod::ListAgents
            {
                let (lock, wake) = &*self.gate;
                let mut released = lock.lock().expect("route gate");
                while !*released {
                    released = wake.wait(released).expect("route gate wait");
                }
            }
            match request.method() {
                RpcMethod::WaitTask => request.success(&json!({
                    "kind":"wait_task_result",
                    "task_id":"task-001",
                    "requested_after_seq":0,
                    "events":[],
                    "next_seq":0,
                    "oldest_available_seq":1,
                    "last_committed_seq":1,
                    "terminal_result":null
                })),
                RpcMethod::CancelTask => request.success(&json!({
                    "kind":"cancel_task_result",
                    "task":{
                        "version":1,
                        "kind":"task_snapshot",
                        "task_id":"task-001",
                        "state":"CANCEL_REQUESTED",
                        "generation":1
                    }
                })),
                RpcMethod::ListAgents => request.success(&json!({
                    "kind":"list_agents_result",
                    "agents":[],
                    "config_version":1
                })),
                _ => unreachable!("test router method"),
            }
        }
    }

    impl SessionRouter for CountingRouter {
        fn route(&self, request: PendingRequest) -> Result<RpcResponse, SessionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            request.success(&json!({
                "kind": "list_agents_result",
                "agents": [],
                "config_version": 1
            }))
        }
    }

    struct HandshakeTransport {
        stage: usize,
        disconnect_at_stage: Option<usize>,
        client: ClientHello,
        writes: Arc<Mutex<Vec<Value>>>,
        requests: VecDeque<Value>,
        key_bytes: [u8; AUTH_TAG_LENGTH],
        request_gate: Option<Arc<(Mutex<bool>, Condvar)>>,
    }

    impl HandshakeTransport {
        fn new(request: Value, writes: Arc<Mutex<Vec<Value>>>) -> Self {
            Self::new_with_nonce(request, writes, [1; NONCE_LENGTH])
        }

        fn new_with_nonce(
            request: Value,
            writes: Arc<Mutex<Vec<Value>>>,
            client_nonce: [u8; NONCE_LENGTH],
        ) -> Self {
            let client = ClientHello::new(
                WIRE_MAJOR_V1,
                WIRE_MINOR_V1,
                WIRE_MINOR_V1,
                PROTOCOL_VERSION_V1,
                "install-001".into(),
                "mcp-bridge-native".into(),
                "0.1.0".into(),
                Nonce::from_bytes(client_nonce),
                8_388_608,
            )
            .expect("client hello");
            Self {
                stage: 0,
                disconnect_at_stage: None,
                client,
                writes,
                requests: VecDeque::from([request]),
                key_bytes: KEY_BYTES,
                request_gate: None,
            }
        }

        fn disconnecting_at(stage: usize, writes: Arc<Mutex<Vec<Value>>>) -> Self {
            Self {
                disconnect_at_stage: Some(stage),
                ..Self::new(
                    json!({"jsonrpc":"2.0","id":"unused","method":"mesh.health","params":{}}),
                    writes,
                )
            }
        }

        fn new_many(
            requests: impl IntoIterator<Item = Value>,
            writes: Arc<Mutex<Vec<Value>>>,
        ) -> Self {
            let mut requests = requests.into_iter();
            let first = requests.next().expect("at least one request");
            let mut transport = Self::new(first, writes);
            transport.requests.extend(requests);
            transport
        }

        fn gated(
            request: Value,
            writes: Arc<Mutex<Vec<Value>>>,
            request_gate: Arc<(Mutex<bool>, Condvar)>,
        ) -> Self {
            Self {
                request_gate: Some(request_gate),
                ..Self::new(request, writes)
            }
        }

        fn challenge(&self) -> ServerChallenge {
            let writes = self.writes.lock().expect("writes");
            let value = &writes[0]["result"];
            ServerChallenge::new(
                &self.client,
                u32_value(value, "selected_major"),
                u32_value(value, "selected_minor"),
                u32_value(value, "protocol_version"),
                value["install_id"].as_str().expect("install id").into(),
                value["daemon_version"]
                    .as_str()
                    .expect("daemon version")
                    .into(),
                value["daemon_generation"]
                    .as_u64()
                    .expect("daemon generation"),
                Nonce::from_bytes(hex32(value["server_nonce"].as_str().expect("server nonce"))),
                WireLimitsV1::protocol_v1_0(),
            )
            .expect("challenge")
        }
    }

    impl FramedTransport for HandshakeTransport {
        fn peer_pid(&self) -> u32 {
            42
        }

        fn read_payload(
            &mut self,
            _maximum_payload_bytes: usize,
            _deadline: Instant,
        ) -> Result<Vec<u8>, crate::protocol_handshake::TransportError> {
            if self.disconnect_at_stage == Some(self.stage) {
                self.stage += 1;
                return Err(crate::protocol_handshake::TransportError::ConnectionClosed);
            }
            let value = match self.stage {
                0 => json!({
                    "jsonrpc":"2.0",
                    "id":"handshake-1",
                    "method":"mesh.handshake",
                    "params":{
                        "phase":"hello",
                        "wire_major":1,
                        "min_minor":0,
                        "max_minor":0,
                        "protocol_versions":[1],
                        "install_id":"install-001",
                        "client_kind":"mcp-bridge-native",
                        "client_version":"0.1.0",
                        "client_nonce": hex_lower(self.client.client_nonce.as_bytes()),
                        "max_response_frame":8_388_608
                    }
                }),
                1 => {
                    let challenge = self.challenge();
                    let key = EndpointKey::from_bytes(self.key_bytes);
                    let auth = ClientAuth::signed(&key, &self.client, &challenge).expect("auth");
                    json!({
                        "jsonrpc":"2.0",
                        "id":"handshake-2",
                        "method":"mesh.handshake",
                        "params":{
                            "phase":"auth",
                            "client_nonce":hex_lower(auth.client_nonce.as_bytes()),
                            "server_nonce":hex_lower(auth.server_nonce.as_bytes()),
                            "client_proof":hex_lower(&auth.client_proof)
                        }
                    })
                }
                2 => {
                    if let Some((lock, wake)) = self.request_gate.as_deref() {
                        let mut released = lock.lock().expect("request gate");
                        while !*released {
                            released = wake.wait(released).expect("request gate wait");
                        }
                    }
                    self.requests
                        .pop_front()
                        .ok_or(crate::protocol_handshake::TransportError::Timeout)?
                }
                _ => return Err(crate::protocol_handshake::TransportError::ConnectionClosed),
            };
            self.stage += 1;
            serde_json::to_vec(&value).map_err(|_| crate::protocol_handshake::TransportError::Io)
        }

        fn write_payload(
            &mut self,
            payload: &[u8],
            _maximum_payload_bytes: usize,
            _deadline: Instant,
        ) -> Result<(), crate::protocol_handshake::TransportError> {
            let value = serde_json::from_slice(payload)
                .map_err(|_| crate::protocol_handshake::TransportError::Io)?;
            self.writes.lock().expect("writes").push(value);
            Ok(())
        }
    }

    struct HandshakeReadHalf {
        requests: VecDeque<Value>,
        request_gate: Option<Arc<(Mutex<bool>, Condvar)>>,
    }

    impl FramedReadHalf for HandshakeReadHalf {
        fn read_payload(
            &mut self,
            _maximum_payload_bytes: usize,
            _deadline: Instant,
        ) -> Result<Vec<u8>, crate::protocol_handshake::TransportError> {
            if self.requests.is_empty() {
                thread::sleep(Duration::from_millis(100));
                return Err(crate::protocol_handshake::TransportError::Timeout);
            }
            if let Some((lock, wake)) = self.request_gate.as_deref() {
                let mut released = lock.lock().expect("request gate");
                while !*released {
                    released = wake.wait(released).expect("request gate wait");
                }
            }
            serde_json::to_vec(&self.requests.pop_front().expect("request checked above"))
                .map_err(|_| crate::protocol_handshake::TransportError::Io)
        }

        fn abort_connection(&self) {
            if let Some((lock, wake)) = self.request_gate.as_deref() {
                *lock.lock().expect("request gate") = true;
                wake.notify_all();
            }
        }
    }

    struct HandshakeWriteHalf {
        writes: Arc<Mutex<Vec<Value>>>,
    }

    impl FramedWriteHalf for HandshakeWriteHalf {
        fn write_payload(
            &mut self,
            payload: &[u8],
            _maximum_payload_bytes: usize,
            _deadline: Instant,
        ) -> Result<(), crate::protocol_handshake::TransportError> {
            let value = serde_json::from_slice(payload)
                .map_err(|_| crate::protocol_handshake::TransportError::Io)?;
            self.writes.lock().expect("writes").push(value);
            Ok(())
        }
    }

    impl SplittableFramedTransport for HandshakeTransport {
        type Reader = HandshakeReadHalf;
        type Writer = HandshakeWriteHalf;

        fn into_framed_halves(self) -> (Self::Reader, Self::Writer) {
            (
                HandshakeReadHalf {
                    requests: self.requests,
                    request_gate: self.request_gate,
                },
                HandshakeWriteHalf {
                    writes: self.writes,
                },
            )
        }
    }

    fn health() -> DaemonHealth {
        DaemonHealth::new(
            crate::protocol_handshake::DaemonState::Running,
            "install-001".into(),
            "consumer-001".into(),
            "0.1.0".into(),
            7,
            4,
            1_000,
        )
        .expect("health")
    }

    #[test]
    fn full_authenticated_session_routes_only_after_ready_and_stops_cleanly() {
        let shutdown = ShutdownSignal::new();
        let writes = Arc::new(Mutex::new(Vec::new()));
        let router = FakeRouter {
            calls: AtomicUsize::new(0),
            shutdown: shutdown.clone(),
        };
        let runtime = DaemonRuntime::new(
            EndpointKey::from_bytes(KEY_BYTES),
            health(),
            router,
            32,
            DaemonRuntimeConfig::default(),
        )
        .expect("runtime");
        let connection = runtime.serve_transport(
            HandshakeTransport::new(
                json!({"jsonrpc":"2.0","id":9,"method":"mesh.list_agents","params":{}}),
                Arc::clone(&writes),
            ),
            &shutdown,
        );

        assert!(connection.authenticated);
        assert_eq!(connection.completed_requests, 1);
        assert!(connection.shutdown_observed);
        assert_eq!(runtime.shared.router.calls.load(Ordering::SeqCst), 1);
        let writes = writes.lock().expect("writes");
        assert_eq!(writes.len(), 3);
        assert_eq!(writes[0]["result"]["kind"], "handshake_challenge");
        assert_eq!(writes[1]["result"]["kind"], "handshake_ready");
        assert_eq!(writes[2]["id"], 9);
        assert_eq!(writes[2]["result"]["kind"], "list_agents_result");
    }

    #[test]
    fn health_is_internal_and_authentication_failure_never_reaches_router() {
        let shutdown = ShutdownSignal::new();
        let router = RejectingRouter {
            calls: AtomicUsize::new(0),
        };
        let runtime = DaemonRuntime::new(
            EndpointKey::from_bytes([8; AUTH_TAG_LENGTH]),
            health(),
            router,
            32,
            DaemonRuntimeConfig::default(),
        )
        .expect("runtime");
        let writes = Arc::new(Mutex::new(Vec::new()));
        let failed = runtime.serve_transport(
            HandshakeTransport::new(
                json!({"jsonrpc":"2.0","id":3,"method":"mesh.health","params":{}}),
                writes,
            ),
            &shutdown,
        );
        assert!(!failed.authenticated);
        assert_eq!(failed.completed_requests, 0);
        assert_eq!(runtime.shared.router.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn health_bypasses_router_and_router_errors_stay_structured() {
        let shutdown = ShutdownSignal::new();
        let health_writes = Arc::new(Mutex::new(Vec::new()));
        let health_runtime = DaemonRuntime::new(
            EndpointKey::from_bytes(KEY_BYTES),
            health(),
            RejectingRouter {
                calls: AtomicUsize::new(0),
            },
            32,
            DaemonRuntimeConfig::default(),
        )
        .expect("runtime");
        let health_report = health_runtime.serve_transport(
            HandshakeTransport::new(
                json!({"jsonrpc":"2.0","id":3,"method":"mesh.health","params":{}}),
                Arc::clone(&health_writes),
            ),
            &shutdown,
        );
        assert!(health_report.authenticated);
        assert_eq!(health_report.completed_requests, 1);
        assert_eq!(health_runtime.shared.router.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            health_writes.lock().expect("writes")[2]["result"]["kind"],
            "health_result"
        );

        let error_writes = Arc::new(Mutex::new(Vec::new()));
        let error_runtime = DaemonRuntime::new(
            EndpointKey::from_bytes(KEY_BYTES),
            health(),
            RejectingRouter {
                calls: AtomicUsize::new(0),
            },
            32,
            DaemonRuntimeConfig::default(),
        )
        .expect("runtime");
        let error_report = error_runtime.serve_transport(
            HandshakeTransport::new(
                json!({"jsonrpc":"2.0","id":4,"method":"mesh.list_agents","params":{}}),
                Arc::clone(&error_writes),
            ),
            &shutdown,
        );
        assert_eq!(error_report.completed_requests, 1);
        let writes = error_writes.lock().expect("writes");
        assert_eq!(writes[2]["id"], 4);
        assert_eq!(
            writes[2]["error"]["data"]["error"]["code"],
            "VALIDATION_FAILED"
        );
        assert_eq!(writes[2]["error"]["data"]["diagnostic_ref"], "fake");
    }

    #[test]
    fn shutdown_fences_a_request_that_finishes_reading_after_the_signal() {
        let shutdown = ShutdownSignal::new();
        let writes = Arc::new(Mutex::new(Vec::new()));
        let request_gate = Arc::new((Mutex::new(false), Condvar::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let runtime = DaemonRuntime::new(
            EndpointKey::from_bytes(KEY_BYTES),
            health(),
            CountingRouter {
                calls: Arc::clone(&calls),
            },
            32,
            DaemonRuntimeConfig::default(),
        )
        .expect("runtime");
        let thread_shutdown = shutdown.clone();
        let transport = HandshakeTransport::gated(
            json!({"jsonrpc":"2.0","id":5,"method":"mesh.list_agents","params":{}}),
            Arc::clone(&writes),
            Arc::clone(&request_gate),
        );
        let worker = thread::spawn(move || runtime.serve_transport(transport, &thread_shutdown));

        let deadline = Instant::now() + Duration::from_secs(1);
        while writes.lock().expect("writes").len() < 2 && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(writes.lock().expect("writes").len(), 2);
        shutdown.request();
        let (lock, wake) = &*request_gate;
        *lock.lock().expect("request gate") = true;
        wake.notify_all();

        let report = worker.join().expect("worker");
        assert!(report.authenticated);
        assert!(report.shutdown_observed);
        assert_eq!(report.completed_requests, 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(writes.lock().expect("writes").len(), 2);
    }

    #[test]
    fn blocked_wait_does_not_block_later_cancel_and_ids_are_out_of_order() {
        let shutdown = ShutdownSignal::new();
        let writes = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let runtime = DaemonRuntime::new(
            EndpointKey::from_bytes(KEY_BYTES),
            health(),
            GatedRouter {
                calls: Arc::clone(&calls),
                gate: Arc::clone(&gate),
            },
            32,
            DaemonRuntimeConfig::default(),
        )
        .expect("runtime");
        let transport = HandshakeTransport::new_many(
            [
                json!({"jsonrpc":"2.0","id":7,"method":"mesh.wait_task","params":{"task_id":"task-001","after_seq":0,"limit":200,"wait_ms":30000}}),
                json!({"jsonrpc":"2.0","id":9,"method":"mesh.cancel_task","params":{"version":1,"kind":"command","action":"cancel","command_key":"cmd-cancel-001","task_id":"task-001"}}),
            ],
            Arc::clone(&writes),
        );
        let thread_shutdown = shutdown.clone();
        let worker = thread::spawn(move || runtime.serve_transport(transport, &thread_shutdown));

        wait_until(Duration::from_secs(1), || {
            calls.load(Ordering::SeqCst) == 2 && writes.lock().expect("writes").len() >= 3
        });
        assert_eq!(writes.lock().expect("writes")[2]["id"], 9);

        let (lock, wake) = &*gate;
        *lock.lock().expect("route gate") = true;
        wake.notify_all();
        wait_until(Duration::from_secs(1), || {
            writes.lock().expect("writes").len() >= 4
        });
        shutdown.request();
        let report = worker.join().expect("connection worker");
        let writes = writes.lock().expect("writes");
        assert_eq!(writes[3]["id"], 7);
        assert_eq!(report.completed_requests, 2);
        assert!(report.shutdown_observed);
        assert_eq!(report.terminal_error, None);
    }

    #[test]
    fn duplicate_in_flight_id_fails_connection_and_releases_worker_capability() {
        let shutdown = ShutdownSignal::new();
        let writes = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let runtime = DaemonRuntime::new(
            EndpointKey::from_bytes(KEY_BYTES),
            health(),
            GatedRouter {
                calls: Arc::clone(&calls),
                gate: Arc::clone(&gate),
            },
            32,
            DaemonRuntimeConfig::default(),
        )
        .expect("runtime");
        let request = json!({"jsonrpc":"2.0","id":7,"method":"mesh.list_agents","params":{}});
        let transport =
            HandshakeTransport::new_many([request.clone(), request], Arc::clone(&writes));
        let worker = thread::spawn(move || runtime.serve_transport(transport, &shutdown));
        wait_until(Duration::from_secs(1), || calls.load(Ordering::SeqCst) == 1);
        let (lock, wake) = &*gate;
        *lock.lock().expect("route gate") = true;
        wake.notify_all();
        let report = worker.join().expect("connection worker");
        assert_eq!(report.terminal_error, Some(ErrorCode::ValidationFailed));
        assert!(report.completed_requests <= 1);
        assert_eq!(
            writes.lock().expect("writes").len(),
            2 + usize::try_from(report.completed_requests).expect("small count")
        );
    }

    #[test]
    fn seventeenth_request_is_not_routed_or_queued() {
        let shutdown = ShutdownSignal::new();
        let writes = Arc::new(Mutex::new(Vec::new()));
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let runtime = DaemonRuntime::new(
            EndpointKey::from_bytes(KEY_BYTES),
            health(),
            GatedRouter {
                calls: Arc::clone(&calls),
                gate: Arc::clone(&gate),
            },
            32,
            DaemonRuntimeConfig::default(),
        )
        .expect("runtime");
        let requests = (0_u64..17)
            .map(|id| json!({"jsonrpc":"2.0","id":id,"method":"mesh.list_agents","params":{}}));
        let transport = HandshakeTransport::new_many(requests, Arc::clone(&writes));
        let worker = thread::spawn(move || runtime.serve_transport(transport, &shutdown));
        wait_until(Duration::from_secs(1), || {
            calls.load(Ordering::SeqCst) == 16
        });
        let (lock, wake) = &*gate;
        *lock.lock().expect("route gate") = true;
        wake.notify_all();
        let report = worker.join().expect("connection worker");
        assert_eq!(calls.load(Ordering::SeqCst), 16);
        assert_eq!(report.terminal_error, Some(ErrorCode::ValidationFailed));
        assert!(report.completed_requests <= 16);
        assert_eq!(
            writes.lock().expect("writes").len(),
            2 + usize::try_from(report.completed_requests).expect("small count")
        );
    }

    fn wait_until(timeout: Duration, predicate: impl Fn() -> bool) {
        let deadline = Instant::now() + timeout;
        while !predicate() && Instant::now() < deadline {
            thread::yield_now();
        }
        assert!(predicate(), "condition timed out");
    }

    struct BlockingTransport {
        released: Arc<(Mutex<bool>, Condvar)>,
    }

    impl FramedTransport for BlockingTransport {
        fn peer_pid(&self) -> u32 {
            1
        }

        fn read_payload(
            &mut self,
            _maximum_payload_bytes: usize,
            _deadline: Instant,
        ) -> Result<Vec<u8>, crate::protocol_handshake::TransportError> {
            let (lock, wake) = &*self.released;
            let mut released = lock.lock().expect("release lock");
            while !*released {
                released = wake.wait(released).expect("release wait");
            }
            Err(crate::protocol_handshake::TransportError::ConnectionClosed)
        }

        fn write_payload(
            &mut self,
            _payload: &[u8],
            _maximum_payload_bytes: usize,
            _deadline: Instant,
        ) -> Result<(), crate::protocol_handshake::TransportError> {
            Ok(())
        }
    }

    struct BlockingWriteHalf;

    impl FramedWriteHalf for BlockingWriteHalf {
        fn write_payload(
            &mut self,
            _payload: &[u8],
            _maximum_payload_bytes: usize,
            _deadline: Instant,
        ) -> Result<(), crate::protocol_handshake::TransportError> {
            Ok(())
        }
    }

    impl SplittableFramedTransport for BlockingTransport {
        type Reader = BlockingTransport;
        type Writer = BlockingWriteHalf;

        fn into_framed_halves(self) -> (Self::Reader, Self::Writer) {
            (self, BlockingWriteHalf)
        }
    }

    impl FramedReadHalf for BlockingTransport {
        fn read_payload(
            &mut self,
            maximum_payload_bytes: usize,
            deadline: Instant,
        ) -> Result<Vec<u8>, crate::protocol_handshake::TransportError> {
            FramedTransport::read_payload(self, maximum_payload_bytes, deadline)
        }

        fn abort_connection(&self) {
            let (lock, wake) = &*self.released;
            *lock.lock().expect("release lock") = true;
            wake.notify_all();
        }
    }

    struct FakeListenerState {
        queued: Mutex<VecDeque<BlockingTransport>>,
        live_listeners: AtomicUsize,
        minimum_live_at_accept: AtomicUsize,
        accepts: AtomicUsize,
    }

    struct FakeListener {
        state: Arc<FakeListenerState>,
    }

    impl FakeListener {
        fn first(state: Arc<FakeListenerState>) -> Self {
            state.live_listeners.fetch_add(1, Ordering::SeqCst);
            Self { state }
        }
    }

    impl Drop for FakeListener {
        fn drop(&mut self) {
            self.state.live_listeners.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl ConnectionListener for FakeListener {
        type Transport = BlockingTransport;

        fn bind_additional(&self) -> Result<Self, AcceptFailure> {
            self.state.live_listeners.fetch_add(1, Ordering::SeqCst);
            Ok(Self {
                state: Arc::clone(&self.state),
            })
        }

        fn accept(self, _deadline: Instant) -> Result<Self::Transport, AcceptFailure> {
            let live = self.state.live_listeners.load(Ordering::SeqCst);
            self.state
                .minimum_live_at_accept
                .fetch_min(live, Ordering::SeqCst);
            self.state.accepts.fetch_add(1, Ordering::SeqCst);
            self.state
                .queued
                .lock()
                .expect("queue")
                .pop_front()
                .ok_or(AcceptFailure::Timeout)
        }
    }

    struct HandshakeListenerState {
        queued: Mutex<VecDeque<HandshakeTransport>>,
        live_listeners: AtomicUsize,
        minimum_live_at_accept: AtomicUsize,
    }

    struct HandshakeListener {
        state: Arc<HandshakeListenerState>,
    }

    impl HandshakeListener {
        fn first(state: Arc<HandshakeListenerState>) -> Self {
            state.live_listeners.fetch_add(1, Ordering::SeqCst);
            Self { state }
        }
    }

    impl Drop for HandshakeListener {
        fn drop(&mut self) {
            self.state.live_listeners.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl ConnectionListener for HandshakeListener {
        type Transport = HandshakeTransport;

        fn bind_additional(&self) -> Result<Self, AcceptFailure> {
            self.state.live_listeners.fetch_add(1, Ordering::SeqCst);
            Ok(Self {
                state: Arc::clone(&self.state),
            })
        }

        fn accept(self, _deadline: Instant) -> Result<Self::Transport, AcceptFailure> {
            self.state.minimum_live_at_accept.fetch_min(
                self.state.live_listeners.load(Ordering::SeqCst),
                Ordering::SeqCst,
            );
            self.state
                .queued
                .lock()
                .expect("handshake listener queue")
                .pop_front()
                .ok_or(AcceptFailure::Timeout)
        }
    }

    #[test]
    fn listener_keeps_successor_live_and_never_accepts_beyond_worker_bound() {
        let released = Arc::new((Mutex::new(false), Condvar::new()));
        let state = Arc::new(FakeListenerState {
            queued: Mutex::new(
                (0..3)
                    .map(|_| BlockingTransport {
                        released: Arc::clone(&released),
                    })
                    .collect(),
            ),
            live_listeners: AtomicUsize::new(0),
            minimum_live_at_accept: AtomicUsize::new(usize::MAX),
            accepts: AtomicUsize::new(0),
        });
        let shutdown = ShutdownSignal::new();
        let runtime = DaemonRuntime::new(
            EndpointKey::from_bytes(KEY_BYTES),
            health(),
            RejectingRouter {
                calls: AtomicUsize::new(0),
            },
            32,
            DaemonRuntimeConfig {
                maximum_connections: 2,
                accept_poll_interval: Duration::from_millis(1),
                shutdown_grace: Duration::from_secs(1),
            },
        )
        .expect("runtime");
        let first = FakeListener::first(Arc::clone(&state));
        let thread_shutdown = shutdown.clone();
        let server = thread::spawn(move || runtime.serve_listener(first, &thread_shutdown));

        let deadline = Instant::now() + Duration::from_secs(1);
        while state.accepts.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(state.accepts.load(Ordering::SeqCst), 2);
        thread::sleep(Duration::from_millis(10));
        assert_eq!(state.accepts.load(Ordering::SeqCst), 2);
        assert!(state.minimum_live_at_accept.load(Ordering::SeqCst) >= 2);

        shutdown.request();
        let (lock, wake) = &*released;
        *lock.lock().expect("release lock") = true;
        wake.notify_all();
        let report = server.join().expect("server thread").expect("server");
        assert_eq!(report.accepted_connections, 2);
        assert_eq!(report.completed_connections, 2);
        assert_eq!(report.detached_on_shutdown, 0);
        assert_eq!(state.live_listeners.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn listener_survives_client_disconnect_during_each_handshake_phase() {
        for disconnect_stage in [0, 1] {
            let interrupted_writes = Arc::new(Mutex::new(Vec::new()));
            let healthy_writes = Arc::new(Mutex::new(Vec::new()));
            let state = Arc::new(HandshakeListenerState {
                queued: Mutex::new(VecDeque::from([
                    HandshakeTransport::disconnecting_at(
                        disconnect_stage,
                        Arc::clone(&interrupted_writes),
                    ),
                    HandshakeTransport::new_with_nonce(
                        json!({
                            "jsonrpc":"2.0",
                            "id":"health-after-disconnect",
                            "method":"mesh.health",
                            "params":{}
                        }),
                        Arc::clone(&healthy_writes),
                        [2; NONCE_LENGTH],
                    ),
                ])),
                live_listeners: AtomicUsize::new(0),
                minimum_live_at_accept: AtomicUsize::new(usize::MAX),
            });
            let router_calls = Arc::new(AtomicUsize::new(0));
            let shutdown = ShutdownSignal::new();
            let runtime = DaemonRuntime::new(
                EndpointKey::from_bytes(KEY_BYTES),
                health(),
                CountingRouter {
                    calls: Arc::clone(&router_calls),
                },
                32,
                DaemonRuntimeConfig {
                    maximum_connections: 2,
                    accept_poll_interval: Duration::from_millis(1),
                    shutdown_grace: Duration::from_secs(1),
                },
            )
            .expect("runtime");
            let first = HandshakeListener::first(Arc::clone(&state));
            let thread_shutdown = shutdown.clone();
            let server = thread::spawn(move || runtime.serve_listener(first, &thread_shutdown));

            wait_until(Duration::from_secs(1), || {
                healthy_writes.lock().expect("healthy writes").len() == 3
            });
            assert!(
                !server.is_finished(),
                "a handshake disconnect must not terminate the daemon listener"
            );
            assert!(state.minimum_live_at_accept.load(Ordering::SeqCst) >= 2);
            assert_eq!(router_calls.load(Ordering::SeqCst), 0);

            let healthy = healthy_writes.lock().expect("healthy writes");
            assert_eq!(healthy[0]["result"]["kind"], "handshake_challenge");
            assert_eq!(healthy[1]["result"]["kind"], "handshake_ready");
            assert_eq!(healthy[2]["id"], "health-after-disconnect");
            assert_eq!(healthy[2]["result"]["kind"], "health_result");
            drop(healthy);
            assert_eq!(
                interrupted_writes.lock().expect("interrupted writes").len(),
                disconnect_stage,
                "hello disconnect emits nothing; auth disconnect emits only the challenge"
            );

            shutdown.request();
            let report = server.join().expect("server thread").expect("server");
            assert_eq!(report.accepted_connections, 2);
            assert_eq!(report.completed_connections, 2);
            assert_eq!(report.completed_requests, 1);
            assert_eq!(report.detached_on_shutdown, 0);
            assert_eq!(state.live_listeners.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn invalid_bounds_are_rejected_without_secret_or_native_detail() {
        let error = DaemonRuntime::new(
            EndpointKey::from_bytes(KEY_BYTES),
            health(),
            RejectingRouter {
                calls: AtomicUsize::new(0),
            },
            31,
            DaemonRuntimeConfig::default(),
        )
        .err()
        .expect("invalid replay capacity");
        assert_eq!(error.code(), RuntimeErrorCode::InvalidConfiguration);
        assert_eq!(error.to_string(), "daemon runtime configuration is invalid");
        assert!(!format!("{error:?}").contains('7'));

        let ready_health = DaemonHealth::new(
            crate::protocol_handshake::DaemonState::Ready,
            "install-001".into(),
            "consumer-001".into(),
            "0.1.0".into(),
            7,
            4,
            1_000,
        )
        .expect("ready health");
        let error = DaemonRuntime::new(
            EndpointKey::from_bytes(KEY_BYTES),
            ready_health,
            RejectingRouter {
                calls: AtomicUsize::new(0),
            },
            32,
            DaemonRuntimeConfig::default(),
        )
        .err()
        .expect("READY cannot serve RPC");
        assert_eq!(error.code(), RuntimeErrorCode::StartupNotReady);
        assert_eq!(
            error.to_string(),
            "daemon startup verification is incomplete"
        );
    }

    fn u32_value(value: &Value, field: &str) -> u32 {
        u32::try_from(value[field].as_u64().expect("u32 field")).expect("u32")
    }

    fn hex32(source: &str) -> [u8; NONCE_LENGTH] {
        let mut output = [0_u8; NONCE_LENGTH];
        for (index, pair) in source.as_bytes().chunks_exact(2).enumerate() {
            output[index] =
                u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex");
        }
        output
    }

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }
}
