//! Daemon-side authenticated wire session.
//!
//! Proofs, nonces, transcript ordering, and negotiated-limit validation are
//! intentionally owned by `mesh-win32`. This module only converts the strict
//! schema JSON and enforces the consuming server-session state machine.

use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use mesh_win32::{
    AUTH_TAG_LENGTH, ClientAuth, ClientHello, EndpointKey, NONCE_LENGTH, Nonce, NonceReplayGuard,
    PROTOCOL_VERSION_V1, ServerChallenge, ServerReady, WIRE_MAJOR_V1, WIRE_MINOR_V1, WireLimitsV1,
};
use serde_json::{Map, Value, json};

use crate::{
    ErrorCode, PROTOCOL_VERSION, ProtocolError, decode_wire_v1,
    protocol_frame::{decode_strict_payload, decode_wire_payload, encode_wire_payload},
};

const HANDSHAKE_HELLO_ID: &str = "handshake-1";
const HANDSHAKE_AUTH_ID: &str = "handshake-2";
const REQUEST_FRAME_LIMIT: u32 = 1_048_576;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const WAIT_TRANSPORT_MARGIN_MS: u64 = 5_000;

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// A redaction-safe error produced by the authenticated session boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionError {
    pub code: ErrorCode,
    pub message: &'static str,
}

impl SessionError {
    const fn authentication() -> Self {
        Self {
            code: ErrorCode::IpcAuthenticationFailed,
            message: "pipe authentication failed",
        }
    }

    const fn invalid_request(message: &'static str) -> Self {
        Self {
            code: ErrorCode::ValidationFailed,
            message,
        }
    }

    const fn version_unsupported() -> Self {
        Self {
            code: ErrorCode::VersionUnsupported,
            message: "protocol version is unsupported",
        }
    }

    const fn transport(error: TransportError) -> Self {
        match error {
            TransportError::FrameInvalid => Self {
                code: ErrorCode::IpcFrameInvalid,
                message: "pipe frame is invalid",
            },
            TransportError::FrameTooLarge => Self {
                code: ErrorCode::IpcFrameTooLarge,
                message: "pipe frame is too large",
            },
            TransportError::Timeout => Self {
                code: ErrorCode::IpcIoTimeout,
                message: "pipe I/O timed out",
            },
            // A closed stream is a truncated frame at this boundary. Generic OS
            // failures use PROTOCOL_MALFORMED because the public v1 taxonomy has
            // no IPC_IO_ERROR code; neither is mislabeled as a retryable timeout.
            TransportError::ConnectionClosed => Self {
                code: ErrorCode::IpcFrameInvalid,
                message: "pipe connection closed during a frame",
            },
            TransportError::Io => Self {
                code: ErrorCode::ProtocolMalformed,
                message: "pipe transport failed",
            },
        }
    }
}

impl From<ProtocolError> for SessionError {
    fn from(error: ProtocolError) -> Self {
        Self {
            code: error.code,
            message: error.message,
        }
    }
}

/// Opaque transport failure. Native error details never cross this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportError {
    FrameInvalid,
    FrameTooLarge,
    Timeout,
    ConnectionClosed,
    Io,
}

#[cfg(windows)]
impl From<mesh_win32::NativeError> for TransportError {
    fn from(error: mesh_win32::NativeError) -> Self {
        match error.code() {
            mesh_win32::NativeErrorCode::FrameInvalid => Self::FrameInvalid,
            mesh_win32::NativeErrorCode::FrameTooLarge => Self::FrameTooLarge,
            mesh_win32::NativeErrorCode::IoTimeout => Self::Timeout,
            mesh_win32::NativeErrorCode::ConnectionClosed => Self::ConnectionClosed,
            _ => Self::Io,
        }
    }
}

/// An injectable payload-framed transport.
///
/// Implementations must consume/produce the four-byte frame prefix themselves.
/// Session code sees only bounded JSON payload bytes.
pub trait FramedTransport {
    fn peer_pid(&self) -> u32;

    /// Reads one already de-framed payload within the supplied bound/deadline.
    ///
    /// # Errors
    ///
    /// Returns an opaque timeout, closure, framing, or native I/O failure.
    fn read_payload(
        &mut self,
        maximum_payload_bytes: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, TransportError>;

    /// Writes one payload, adding its transport frame within the supplied bound.
    ///
    /// # Errors
    ///
    /// Returns an opaque timeout, closure, framing, or native I/O failure.
    fn write_payload(
        &mut self,
        payload: &[u8],
        maximum_payload_bytes: usize,
        deadline: Instant,
    ) -> Result<(), TransportError>;
}

/// The sole post-authentication reader of a framed byte stream.
pub trait FramedReadHalf: Send + 'static {
    /// # Errors
    ///
    /// Returns an opaque timeout, closure, framing, or native I/O failure.
    fn read_payload(
        &mut self,
        maximum_payload_bytes: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, TransportError>;

    /// Wake a pending read and fail the connection closed.
    fn abort_connection(&self) {}
}

/// The sole post-authentication writer of a framed byte stream.
pub trait FramedWriteHalf: Send + 'static {
    /// # Errors
    ///
    /// Returns an opaque timeout, closure, framing, or native I/O failure.
    fn write_payload(
        &mut self,
        payload: &[u8],
        maximum_payload_bytes: usize,
        deadline: Instant,
    ) -> Result<(), TransportError>;

    /// Wake the peer half and fail the connection closed.
    fn abort_connection(&self) {}
}

/// A consuming, server/client-neutral duplex split available only after the
/// sequential handshake has surrendered the original transport.
pub trait SplittableFramedTransport: FramedTransport + Sized {
    type Reader: FramedReadHalf;
    type Writer: FramedWriteHalf;

    fn into_framed_halves(self) -> (Self::Reader, Self::Writer);
}

#[cfg(windows)]
impl FramedTransport for mesh_win32::SecurePipeConnection {
    fn peer_pid(&self) -> u32 {
        Self::peer_pid(self)
    }

    fn read_payload(
        &mut self,
        maximum_payload_bytes: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, TransportError> {
        self.read_frame(maximum_payload_bytes, deadline)
            .map_err(TransportError::from)
    }

    fn write_payload(
        &mut self,
        payload: &[u8],
        maximum_payload_bytes: usize,
        deadline: Instant,
    ) -> Result<(), TransportError> {
        self.write_frame(payload, maximum_payload_bytes, deadline)
            .map_err(TransportError::from)
    }
}

#[cfg(windows)]
impl FramedReadHalf for mesh_win32::SecurePipeReadHalf {
    fn read_payload(
        &mut self,
        maximum_payload_bytes: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, TransportError> {
        self.read_frame(maximum_payload_bytes, deadline)
            .map_err(TransportError::from)
    }

    fn abort_connection(&self) {
        self.abort();
    }
}

#[cfg(windows)]
impl FramedWriteHalf for mesh_win32::SecurePipeWriteHalf {
    fn write_payload(
        &mut self,
        payload: &[u8],
        maximum_payload_bytes: usize,
        deadline: Instant,
    ) -> Result<(), TransportError> {
        self.write_frame(payload, maximum_payload_bytes, deadline)
            .map_err(TransportError::from)
    }

    fn abort_connection(&self) {
        self.abort();
    }
}

#[cfg(windows)]
impl SplittableFramedTransport for mesh_win32::SecurePipeConnection {
    type Reader = mesh_win32::SecurePipeReadHalf;
    type Writer = mesh_win32::SecurePipeWriteHalf;

    fn into_framed_halves(self) -> (Self::Reader, Self::Writer) {
        self.into_duplex()
    }
}

/// Typed daemon identity supplied by verified startup state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DaemonHealth {
    state: DaemonState,
    install_id: String,
    consumer_id: String,
    daemon_version: String,
    daemon_generation: u64,
    data_schema_version: u64,
    started_at_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DaemonState {
    Ready,
    Running,
}

impl DaemonState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "READY",
            Self::Running => "RUNNING",
        }
    }
}

impl DaemonHealth {
    /// Creates identity only when every value satisfies the authoritative wire schema.
    ///
    /// # Errors
    ///
    /// Rejects malformed IDs, versions, schema versions, and unsafe integers.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: DaemonState,
        install_id: String,
        consumer_id: String,
        daemon_version: String,
        daemon_generation: u64,
        data_schema_version: u64,
        started_at_ms: u64,
    ) -> Result<Self, SessionError> {
        let health = Self {
            state,
            install_id,
            consumer_id,
            daemon_version,
            daemon_generation,
            data_schema_version,
            started_at_ms,
        };
        // Validate the exact health object through a complete admitted envelope.
        let probe = json!({
            "jsonrpc": "2.0",
            "id": 0,
            "result": {
                "kind": "health_result",
                "health": health.to_value(),
                "negotiated_limits": wire_limits_to_value(WireLimitsV1::protocol_v1_0())
            }
        });
        encode_wire_payload(&probe, 8_388_608)?;
        Ok(health)
    }

    #[must_use]
    pub fn install_id(&self) -> &str {
        &self.install_id
    }

    #[must_use]
    pub fn consumer_id(&self) -> &str {
        &self.consumer_id
    }

    #[must_use]
    pub fn daemon_version(&self) -> &str {
        &self.daemon_version
    }

    #[must_use]
    pub const fn state(&self) -> DaemonState {
        self.state
    }

    #[must_use]
    pub const fn daemon_generation(&self) -> u64 {
        self.daemon_generation
    }

    #[must_use]
    pub const fn data_schema_version(&self) -> u64 {
        self.data_schema_version
    }

    #[must_use]
    pub const fn started_at_ms(&self) -> u64 {
        self.started_at_ms
    }

    fn to_value(&self) -> Value {
        json!({
            "kind": "daemon_health",
            "daemon_state": self.state.as_str(),
            "install_id": self.install_id,
            "consumer_id": self.consumer_id,
            "daemon_version": self.daemon_version,
            "daemon_generation": self.daemon_generation,
            "wire_major": WIRE_MAJOR_V1,
            "wire_minor": WIRE_MINOR_V1,
            "protocol_version": PROTOCOL_VERSION_V1,
            "data_schema_version": self.data_schema_version,
            "started_at_ms": self.started_at_ms
        })
    }
}

/// A newly accepted pipe. It has no ordinary request API.
pub struct AcceptedSession<'a, T> {
    transport: T,
    endpoint_key: &'a EndpointKey,
    replay_guard: &'a NonceReplayGuard,
    health: DaemonHealth,
    handshake_deadline: Instant,
}

impl<'a, T: FramedTransport> AcceptedSession<'a, T> {
    #[must_use]
    pub fn new(
        transport: T,
        endpoint_key: &'a EndpointKey,
        replay_guard: &'a NonceReplayGuard,
        health: DaemonHealth,
    ) -> Self {
        Self {
            transport,
            endpoint_key,
            replay_guard,
            health,
            handshake_deadline: handshake_deadline(),
        }
    }

    /// Reads the hello, records its nonce, and emits a schema-valid challenge.
    ///
    /// # Errors
    ///
    /// Any malformed, replayed, mismatched, or non-hello request fails closed.
    pub fn receive_hello(self) -> Result<ChallengedSession<'a, T>, SessionError> {
        self.receive_hello_inner(None)
    }

    fn receive_hello_inner(
        mut self,
        deterministic_nonce: Option<Nonce>,
    ) -> Result<ChallengedSession<'a, T>, SessionError> {
        let deadline = self.handshake_deadline;
        let payload = self
            .transport
            .read_payload(REQUEST_FRAME_LIMIT as usize, deadline)
            .map_err(SessionError::transport)?;
        let object = decode_hello_payload(&payload)?;
        let request = HandshakeRequest::parse(&object, HandshakePhase::Hello)?;
        if request.id != RpcId::Text(HANDSHAKE_HELLO_ID.to_owned()) {
            return Err(SessionError::invalid_request(
                "unexpected handshake request id",
            ));
        }
        let client = client_hello_from_params(&request.params)?;
        if client.install_id != self.health.install_id {
            return Err(SessionError::authentication());
        }
        self.replay_guard
            .check_and_record(client.client_nonce)
            .map_err(|_| SessionError::authentication())?;

        let mut limits = WireLimitsV1::protocol_v1_0();
        limits.response_frame_bytes = limits.response_frame_bytes.min(client.max_response_frame);
        let server_nonce = match deterministic_nonce {
            Some(nonce) => nonce,
            None => Nonce::generate().map_err(|_| SessionError::authentication())?,
        };
        let challenge = ServerChallenge::new(
            &client,
            WIRE_MAJOR_V1,
            WIRE_MINOR_V1,
            PROTOCOL_VERSION_V1,
            self.health.install_id.clone(),
            self.health.daemon_version.clone(),
            self.health.daemon_generation,
            server_nonce,
            limits,
        )
        .map_err(|_| SessionError::authentication())?;
        let response = success_value(&request.id, &challenge_to_value(&challenge));
        write_validated(
            &mut self.transport,
            &response,
            challenge.limits.response_frame_bytes,
            deadline,
        )?;
        Ok(ChallengedSession {
            transport: self.transport,
            endpoint_key: self.endpoint_key,
            health: self.health,
            client,
            challenge,
            handshake_deadline: deadline,
        })
    }
}

/// A challenged pipe. It can only consume the matching auth phase.
pub struct ChallengedSession<'a, T> {
    transport: T,
    endpoint_key: &'a EndpointKey,
    health: DaemonHealth,
    client: ClientHello,
    challenge: ServerChallenge,
    handshake_deadline: Instant,
}

impl<T: FramedTransport> ChallengedSession<'_, T> {
    /// Verifies client proof, emits ready/server proof, and unlocks RPC access.
    ///
    /// # Errors
    ///
    /// Any malformed or unbound proof fails closed without health/task output.
    pub fn receive_auth(mut self) -> Result<AuthenticatedSession<T>, SessionError> {
        let deadline = self.handshake_deadline;
        let payload = self
            .transport
            .read_payload(REQUEST_FRAME_LIMIT as usize, deadline)
            .map_err(SessionError::transport)?;
        let object = decode_wire_payload(&payload, REQUEST_FRAME_LIMIT)?;
        let request = HandshakeRequest::parse(&object, HandshakePhase::Auth)?;
        if request.id != RpcId::Text(HANDSHAKE_AUTH_ID.to_owned()) {
            return Err(SessionError::invalid_request(
                "unexpected handshake request id",
            ));
        }
        let auth = client_auth_from_params(&request.params)?;
        auth.verify(self.endpoint_key, &self.client, &self.challenge)
            .map_err(|_| SessionError::authentication())?;
        let ready = ServerReady::signed(self.endpoint_key, &self.client, &self.challenge, &auth)
            .map_err(|_| SessionError::authentication())?;
        let response = success_value(
            &request.id,
            &json!({
                "kind": "handshake_ready",
                "health": self.health.to_value(),
                "server_proof": lower_hex(&ready.server_proof)
            }),
        );
        write_validated(
            &mut self.transport,
            &response,
            self.challenge.limits.response_frame_bytes,
            deadline,
        )?;
        let peer_pid = self.transport.peer_pid();
        Ok(AuthenticatedSession {
            transport: self.transport,
            health: self.health,
            peer_pid,
            limits: self.challenge.limits,
            connection_state: Arc::new(Mutex::new(ConnectionState::new())),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OutstandingRequest {
    id: RpcId,
    method: RpcMethod,
    deadline: Instant,
}

#[derive(Debug)]
struct ConnectionState {
    connection_id: u64,
    next_token: u64,
    by_token: HashMap<u64, OutstandingRequest>,
    ids: HashSet<RpcId>,
}

impl ConnectionState {
    fn new() -> Self {
        Self {
            connection_id: NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
            next_token: 1,
            by_token: HashMap::new(),
            ids: HashSet::new(),
        }
    }
}

struct OutstandingCapability {
    state: Arc<Mutex<ConnectionState>>,
    connection_id: u64,
    token: u64,
    id: RpcId,
    method: RpcMethod,
    deadline: Instant,
}

impl OutstandingCapability {
    fn is_registered_for(&self, state: &Arc<Mutex<ConnectionState>>) -> bool {
        if !Arc::ptr_eq(&self.state, state) {
            return false;
        }
        state.lock().is_ok_and(|state| {
            state.connection_id == self.connection_id
                && state.by_token.get(&self.token)
                    == Some(&OutstandingRequest {
                        id: self.id.clone(),
                        method: self.method,
                        deadline: self.deadline,
                    })
        })
    }

    fn release(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state.connection_id != self.connection_id {
            return;
        }
        if let Some(request) = state.by_token.remove(&self.token) {
            state.ids.remove(&request.id);
        }
    }
}

impl Drop for OutstandingCapability {
    fn drop(&mut self) {
        self.release();
    }
}

fn register_outstanding(
    state: &Arc<Mutex<ConnectionState>>,
    id: &RpcId,
    method: RpcMethod,
    deadline: Instant,
    maximum: u32,
) -> Result<OutstandingCapability, SessionError> {
    let mut locked = state
        .lock()
        .map_err(|_| SessionError::invalid_request("connection state is unavailable"))?;
    let maximum = usize::try_from(maximum)
        .map_err(|_| SessionError::invalid_request("in-flight limit is invalid"))?;
    if locked.by_token.len() >= maximum {
        return Err(SessionError::invalid_request(
            "too many in-flight RPC requests",
        ));
    }
    if locked.ids.contains(id) {
        return Err(SessionError::invalid_request("duplicate in-flight RPC id"));
    }
    let token = locked.next_token;
    locked.next_token = locked
        .next_token
        .checked_add(1)
        .ok_or_else(|| SessionError::invalid_request("RPC capability space is exhausted"))?;
    let connection_id = locked.connection_id;
    let request = OutstandingRequest {
        id: id.clone(),
        method,
        deadline,
    };
    locked.ids.insert(id.clone());
    locked.by_token.insert(token, request);
    drop(locked);
    Ok(OutstandingCapability {
        state: Arc::clone(state),
        connection_id,
        token,
        id: id.clone(),
        method,
        deadline,
    })
}

/// One authenticated connection. This is the only state exposing task requests.
pub struct AuthenticatedSession<T> {
    transport: T,
    health: DaemonHealth,
    peer_pid: u32,
    limits: WireLimitsV1,
    connection_state: Arc<Mutex<ConnectionState>>,
}

impl<T: FramedTransport> AuthenticatedSession<T> {
    #[must_use]
    pub const fn peer_pid(&self) -> u32 {
        self.peer_pid
    }

    #[must_use]
    pub const fn negotiated_limits(&self) -> WireLimitsV1 {
        self.limits
    }

    #[must_use]
    pub const fn health(&self) -> &DaemonHealth {
        &self.health
    }

    /// Reads one schema-valid health/task request within the negotiated bound.
    ///
    /// # Errors
    ///
    /// Responses, unknown methods, and any post-auth handshake are rejected.
    pub fn read_request(&mut self) -> Result<PendingRequest, SessionError> {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(u64::from(
                self.limits.mutation_timeout_ms,
            )))
            .unwrap_or_else(Instant::now);
        let payload = self
            .transport
            .read_payload(self.limits.request_frame_bytes as usize, deadline)
            .map_err(SessionError::transport)?;
        let received_at = Instant::now();
        let object = decode_wire_payload(&payload, self.limits.request_frame_bytes)?;
        let request = RpcRequest::parse(&object)?;
        let request_deadline = request.deadline_from(received_at)?;
        let capability = register_outstanding(
            &self.connection_state,
            &request.id,
            request.method,
            request_deadline,
            self.limits.max_in_flight,
        )?;
        Ok(PendingRequest {
            request,
            deadline: request_deadline,
            capability: Some(capability),
        })
    }

    /// Writes one response previously bound to a request ID and deadline.
    ///
    /// # Errors
    ///
    /// The response is revalidated against the authoritative schema and bound.
    /// Its effective write deadline is the earlier of the request's absolute
    /// method deadline and the negotiated per-write timeout, so dispatch and
    /// response delivery share one method budget.
    /// The capability is consumed, so replay does not compile:
    ///
    /// ```compile_fail
    /// use mesh_daemon::protocol_handshake::{
    ///     AuthenticatedSession, FramedTransport, RpcResponse,
    /// };
    /// fn replay<T: FramedTransport>(
    ///     session: &mut AuthenticatedSession<T>,
    ///     response: RpcResponse,
    /// ) {
    ///     session.write_response(response).unwrap();
    ///     session.write_response(response).unwrap();
    /// }
    /// ```
    pub fn write_response(&mut self, response: RpcResponse) -> Result<(), SessionError> {
        self.write_response_at(response, Instant::now())
    }

    fn write_response_at(
        &mut self,
        mut response: RpcResponse,
        now: Instant,
    ) -> Result<(), SessionError> {
        let capability = response
            .capability
            .as_ref()
            .ok_or_else(|| SessionError::invalid_request("response capability was consumed"))?;
        if !capability.is_registered_for(&self.connection_state) {
            return Err(SessionError::invalid_request(
                "response does not belong to this connection",
            ));
        }
        let deadline = bounded_write_deadline(
            capability.deadline,
            now,
            Duration::from_millis(u64::from(self.limits.write_timeout_ms)),
        )?;
        let result = write_validated(
            &mut self.transport,
            &response.value,
            self.limits.response_frame_bytes,
            deadline,
        );
        // Success, validation failure, and transport failure all consume the
        // one-shot capability. A failed write leaves the connection result
        // uncertain, but cannot leak an outstanding-ID slot or replay bytes.
        response.capability.take();
        result
    }

    /// Constructs the exact authenticated health response for a health request.
    ///
    /// # Errors
    ///
    /// Rejects use with any task request.
    pub fn health_response(&self, request: PendingRequest) -> Result<RpcResponse, SessionError> {
        if request.method() != RpcMethod::Health {
            return Err(SessionError::invalid_request("request is not mesh.health"));
        }
        request.success(&json!({
            "kind": "health_result",
            "health": self.health.to_value(),
            "negotiated_limits": wire_limits_to_value(self.limits)
        }))
    }
}

/// Post-authentication session half that exclusively owns frame reads.
pub struct AuthenticatedReader<R> {
    transport: R,
    health: DaemonHealth,
    limits: WireLimitsV1,
    connection_state: Arc<Mutex<ConnectionState>>,
}

impl<R: FramedReadHalf> AuthenticatedReader<R> {
    /// Read one request using an absolute transport deadline. A timeout is
    /// terminal because a byte-mode transport may already have consumed part
    /// of the prefix or payload.
    ///
    /// # Errors
    ///
    /// Rejects transport, framing, schema, duplicate-ID, or in-flight-limit
    /// failures without admitting a router capability.
    pub fn read_request_until(
        &mut self,
        transport_deadline: Instant,
    ) -> Result<PendingRequest, SessionError> {
        let payload = self
            .transport
            .read_payload(self.limits.request_frame_bytes as usize, transport_deadline)
            .map_err(SessionError::transport)?;
        let received_at = Instant::now();
        let object = decode_wire_payload(&payload, self.limits.request_frame_bytes)?;
        let request = RpcRequest::parse(&object)?;
        let request_deadline = request.deadline_from(received_at)?;
        let capability = register_outstanding(
            &self.connection_state,
            &request.id,
            request.method,
            request_deadline,
            self.limits.max_in_flight,
        )?;
        Ok(PendingRequest {
            request,
            deadline: request_deadline,
            capability: Some(capability),
        })
    }

    /// # Errors
    ///
    /// Rejects non-health capabilities or a response that fails v1 encoding.
    pub fn health_response(&self, request: PendingRequest) -> Result<RpcResponse, SessionError> {
        if request.method() != RpcMethod::Health {
            return Err(SessionError::invalid_request("request is not mesh.health"));
        }
        request.success(&json!({
            "kind": "health_result",
            "health": self.health.to_value(),
            "negotiated_limits": wire_limits_to_value(self.limits)
        }))
    }

    pub fn abort_connection(&self) {
        self.transport.abort_connection();
    }
}

/// Post-authentication session half that exclusively owns frame writes.
pub struct AuthenticatedWriter<W> {
    transport: W,
    limits: WireLimitsV1,
    connection_state: Arc<Mutex<ConnectionState>>,
}

impl<W: FramedWriteHalf> AuthenticatedWriter<W> {
    /// # Errors
    ///
    /// Rejects cross-connection/consumed capabilities, expired deadlines,
    /// response encoding failures, and transport write failures.
    pub fn write_response(&mut self, mut response: RpcResponse) -> Result<(), SessionError> {
        let capability = response
            .capability
            .as_ref()
            .ok_or_else(|| SessionError::invalid_request("response capability was consumed"))?;
        if !capability.is_registered_for(&self.connection_state) {
            return Err(SessionError::invalid_request(
                "response does not belong to this connection",
            ));
        }
        let now = Instant::now();
        let deadline = bounded_write_deadline(
            capability.deadline,
            now,
            Duration::from_millis(u64::from(self.limits.write_timeout_ms)),
        )?;
        let payload = encode_wire_payload(&response.value, self.limits.response_frame_bytes)?;
        let result = self
            .transport
            .write_payload(
                &payload,
                self.limits.response_frame_bytes as usize,
                deadline,
            )
            .map_err(SessionError::transport);
        response.capability.take();
        result
    }

    pub fn abort_connection(&self) {
        self.transport.abort_connection();
    }
}

impl<T: SplittableFramedTransport> AuthenticatedSession<T> {
    /// Consume the authenticated typestate into its exclusive reader/writer
    /// owners while retaining one connection-bound capability registry.
    pub fn into_duplex(
        self,
    ) -> (
        AuthenticatedReader<T::Reader>,
        AuthenticatedWriter<T::Writer>,
    ) {
        let (reader, writer) = self.transport.into_framed_halves();
        (
            AuthenticatedReader {
                transport: reader,
                health: self.health,
                limits: self.limits,
                connection_state: Arc::clone(&self.connection_state),
            },
            AuthenticatedWriter {
                transport: writer,
                limits: self.limits,
                connection_state: self.connection_state,
            },
        )
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum RpcId {
    Number(u64),
    Text(String),
}

impl RpcId {
    fn parse(value: &Value) -> Result<Self, SessionError> {
        if let Some(number) = value.as_u64().filter(|number| *number <= MAX_SAFE_INTEGER) {
            return Ok(Self::Number(number));
        }
        if let Some(text) = value.as_str() {
            return Ok(Self::Text(text.to_owned()));
        }
        Err(SessionError::invalid_request("invalid RPC id"))
    }

    fn to_value(&self) -> Value {
        match self {
            Self::Number(number) => Value::from(*number),
            Self::Text(text) => Value::from(text.clone()),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcMethod {
    Health,
    ListAgents,
    DelegateTask,
    InspectTask,
    WaitTask,
    SendTaskInput,
    CancelTask,
    ReviewTask,
    ImprovementCase,
}

impl RpcMethod {
    fn parse(method: &str) -> Result<Self, SessionError> {
        match method {
            "mesh.health" => Ok(Self::Health),
            "mesh.list_agents" => Ok(Self::ListAgents),
            "mesh.delegate_task" => Ok(Self::DelegateTask),
            "mesh.inspect_task" => Ok(Self::InspectTask),
            "mesh.wait_task" => Ok(Self::WaitTask),
            "mesh.send_task_input" => Ok(Self::SendTaskInput),
            "mesh.cancel_task" => Ok(Self::CancelTask),
            "mesh.review_task" => Ok(Self::ReviewTask),
            "mesh.improvement_case" => Ok(Self::ImprovementCase),
            "mesh.handshake" => Err(SessionError::invalid_request(
                "handshake is unavailable after authentication",
            )),
            _ => Err(SessionError::invalid_request("RPC method is not admitted")),
        }
    }

    const fn expected_result_kind(self) -> &'static str {
        match self {
            Self::Health => "health_result",
            Self::ListAgents => "list_agents_result",
            Self::DelegateTask => "delegate_task_result",
            Self::InspectTask => "inspect_task_result",
            Self::WaitTask => "wait_task_result",
            Self::SendTaskInput => "send_task_input_result",
            Self::CancelTask => "cancel_task_result",
            Self::ReviewTask => "review_task_result",
            Self::ImprovementCase => "improvement_case_result",
        }
    }

    fn timeout(self, params: &Map<String, Value>) -> Result<Duration, SessionError> {
        let limits = WireLimitsV1::protocol_v1_0();
        let milliseconds = match self {
            Self::Health => u64::from(limits.health_timeout_ms),
            Self::ListAgents | Self::InspectTask => u64::from(limits.query_timeout_ms),
            Self::ImprovementCase => match required(params, "action")?.as_str() {
                Some("inspect") => u64::from(limits.query_timeout_ms),
                Some("improvement_propose" | "improvement_rollback") => {
                    u64::from(limits.mutation_timeout_ms)
                }
                _ => {
                    return Err(SessionError::invalid_request(
                        "improvement action is not admitted",
                    ));
                }
            },
            Self::WaitTask => required(params, "wait_ms")?
                .as_u64()
                .and_then(|wait| wait.checked_add(WAIT_TRANSPORT_MARGIN_MS))
                .filter(|total| {
                    *total <= u64::from(limits.max_wait_ms).saturating_add(WAIT_TRANSPORT_MARGIN_MS)
                })
                .ok_or_else(|| SessionError::invalid_request("wait deadline is invalid"))?,
            Self::DelegateTask | Self::SendTaskInput | Self::CancelTask | Self::ReviewTask => {
                u64::from(limits.mutation_timeout_ms)
            }
        };
        Ok(Duration::from_millis(milliseconds))
    }
}

#[derive(Eq, PartialEq)]
pub struct RpcRequest {
    id: RpcId,
    method: RpcMethod,
    params: Map<String, Value>,
}

impl RpcRequest {
    fn parse(object: &Map<String, Value>) -> Result<Self, SessionError> {
        let id = RpcId::parse(required(object, "id")?)?;
        let method = required(object, "method")?
            .as_str()
            .ok_or_else(|| SessionError::invalid_request("RPC method must be text"))?;
        let method = RpcMethod::parse(method)?;
        let params = required(object, "params")?
            .as_object()
            .cloned()
            .ok_or_else(|| SessionError::invalid_request("RPC params must be an object"))?;
        Ok(Self { id, method, params })
    }

    fn deadline_from(&self, start: Instant) -> Result<Instant, SessionError> {
        start
            .checked_add(self.method.timeout(&self.params)?)
            .ok_or_else(|| SessionError::invalid_request("request deadline overflows"))
    }

    #[must_use]
    pub const fn id(&self) -> &RpcId {
        &self.id
    }

    #[must_use]
    pub const fn method(&self) -> RpcMethod {
        self.method
    }

    #[must_use]
    pub const fn params(&self) -> &Map<String, Value> {
        &self.params
    }
}

/// A connection-bound, one-shot request capability.
///
/// Dropping it abandons the request and releases its in-flight ID. Converting it
/// into a response transfers that cleanup responsibility to the response.
pub struct PendingRequest {
    request: RpcRequest,
    deadline: Instant,
    capability: Option<OutstandingCapability>,
}

impl PendingRequest {
    #[must_use]
    pub const fn id(&self) -> &RpcId {
        &self.request.id
    }

    #[must_use]
    pub const fn method(&self) -> RpcMethod {
        self.request.method
    }

    #[must_use]
    pub const fn params(&self) -> &Map<String, Value> {
        &self.request.params
    }

    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Consumes this capability and constructs the one result kind admitted for
    /// its request method.
    ///
    /// # Errors
    ///
    /// Returns a stable validation error when the result kind does not match the
    /// request method or the complete response fails the v1 schema.
    pub fn success(mut self, result: &Value) -> Result<RpcResponse, SessionError> {
        if result.get("kind").and_then(Value::as_str)
            != Some(self.request.method.expected_result_kind())
        {
            return Err(SessionError::invalid_request(
                "RPC result kind does not match request method",
            ));
        }
        let value = success_value(&self.request.id, result);
        encode_wire_payload(&value, 8_388_608)?;
        Ok(RpcResponse {
            value,
            capability: self.capability.take(),
        })
    }

    /// Consumes this capability and constructs one schema-valid structured
    /// error preserving the exact request ID.
    ///
    /// # Errors
    ///
    /// Returns a stable validation error when any typed error field falls
    /// outside the authoritative v1 schema.
    pub fn error(mut self, error: &RpcErrorSpec) -> Result<RpcResponse, SessionError> {
        let value = json!({
            "jsonrpc": "2.0",
            "id": self.request.id.to_value(),
            "error": {
                "code": error.rpc_code,
                "message": error.message,
                "data": {
                    "error": {
                        "version": 1,
                        "kind": "error",
                        "code": error.code.as_str(),
                        "retry_class": error.retry_class.as_str(),
                        "effect_class": error.effect_class.as_str(),
                        "lifecycle": error.lifecycle.as_str(),
                        "evidence": error.evidence,
                        "message": error.message
                    },
                    "diagnostic_ref": error.diagnostic_ref
                }
            }
        });
        encode_wire_payload(&value, 8_388_608)?;
        Ok(RpcResponse {
            value,
            capability: self.capability.take(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcRetryClass {
    SafePreDispatch,
    SafeProvenNoEffect,
    DeterministicFailure,
    AmbiguousAfterDispatch,
}

impl RpcRetryClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SafePreDispatch => "SAFE_PRE_DISPATCH",
            Self::SafeProvenNoEffect => "SAFE_PROVEN_NO_EFFECT",
            Self::DeterministicFailure => "DETERMINISTIC_FAILURE",
            Self::AmbiguousAfterDispatch => "AMBIGUOUS_AFTER_DISPATCH",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcEffectClass {
    NoEffect,
    PossibleEffect,
    UnknownEffect,
}

impl RpcEffectClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::NoEffect => "NO_EFFECT",
            Self::PossibleEffect => "POSSIBLE_EFFECT",
            Self::UnknownEffect => "UNKNOWN_EFFECT",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcLifecycle {
    BeforeProcessCreation,
    ProcessDeadNoEffectProof,
    AfterProcessCreation,
    Unknown,
}

impl RpcLifecycle {
    const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeProcessCreation => "BEFORE_PROCESS_CREATION",
            Self::ProcessDeadNoEffectProof => "PROCESS_DEAD_NO_EFFECT_PROOF",
            Self::AfterProcessCreation => "AFTER_PROCESS_CREATION",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Typed, redaction-safe fields admitted by the v1 JSON-RPC error envelope.
pub struct RpcErrorSpec {
    rpc_code: i32,
    code: ErrorCode,
    retry_class: RpcRetryClass,
    effect_class: RpcEffectClass,
    lifecycle: RpcLifecycle,
    evidence: String,
    message: String,
    diagnostic_ref: String,
}

impl RpcErrorSpec {
    #[cfg(test)]
    #[must_use]
    pub(crate) fn code(&self) -> ErrorCode {
        self.code
    }

    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        rpc_code: i32,
        code: ErrorCode,
        retry_class: RpcRetryClass,
        effect_class: RpcEffectClass,
        lifecycle: RpcLifecycle,
        evidence: String,
        message: String,
        diagnostic_ref: String,
    ) -> Self {
        Self {
            rpc_code,
            code,
            retry_class,
            effect_class,
            lifecycle,
            evidence,
            message,
            diagnostic_ref,
        }
    }
}

/// A schema-valid, connection-bound response. It is deliberately not `Clone`.
pub struct RpcResponse {
    value: Value,
    capability: Option<OutstandingCapability>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HandshakePhase {
    Hello,
    Auth,
}

struct HandshakeRequest {
    id: RpcId,
    params: Map<String, Value>,
}

impl HandshakeRequest {
    fn parse(
        object: &Map<String, Value>,
        expected_phase: HandshakePhase,
    ) -> Result<Self, SessionError> {
        if required(object, "method")? != "mesh.handshake" {
            return Err(SessionError::invalid_request(
                "only mesh.handshake is admitted",
            ));
        }
        let id = RpcId::parse(required(object, "id")?)?;
        let params = required(object, "params")?
            .as_object()
            .cloned()
            .ok_or_else(|| SessionError::invalid_request("handshake params must be an object"))?;
        let expected = match expected_phase {
            HandshakePhase::Hello => "hello",
            HandshakePhase::Auth => "auth",
        };
        if required(&params, "phase")? != expected {
            return Err(SessionError::invalid_request("unexpected handshake phase"));
        }
        Ok(Self { id, params })
    }
}

fn decode_hello_payload(payload: &[u8]) -> Result<Map<String, Value>, SessionError> {
    let value = decode_strict_payload(payload, REQUEST_FRAME_LIMIT)?;
    if hello_is_valid_except_for_unsupported_versions(&value) {
        return Err(SessionError::version_unsupported());
    }
    decode_wire_v1(value).map_err(SessionError::from)
}

/// Recognizes only a complete, otherwise schema-valid hello whose offered
/// protocol list has no v1 overlap. Replacing only that list and running the
/// authoritative schema prevents malformed or unknown-field hellos from being
/// mislabeled as a clean version negotiation failure.
fn hello_is_valid_except_for_unsupported_versions(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    if object.get("jsonrpc") != Some(&Value::from("2.0"))
        || object.get("method") != Some(&Value::from("mesh.handshake"))
    {
        return false;
    }
    let Some(params) = object.get("params").and_then(Value::as_object) else {
        return false;
    };
    if params.get("phase") != Some(&Value::from("hello")) {
        return false;
    }
    let Some(versions) = params.get("protocol_versions").and_then(Value::as_array) else {
        return false;
    };
    if versions.is_empty() {
        return false;
    }
    let mut unique = HashSet::with_capacity(versions.len());
    for version in versions {
        let Some(version) = version.as_u64() else {
            return false;
        };
        if u32::try_from(version).is_err() {
            return false;
        }
        if !unique.insert(version) {
            return false;
        }
    }
    if unique.contains(&PROTOCOL_VERSION) {
        return false;
    }

    let mut normalized = value.clone();
    normalized["params"]["protocol_versions"] = json!([PROTOCOL_VERSION]);
    decode_wire_v1(normalized).is_ok()
}

fn client_hello_from_params(params: &Map<String, Value>) -> Result<ClientHello, SessionError> {
    let versions = required(params, "protocol_versions")?
        .as_array()
        .ok_or_else(|| SessionError::invalid_request("protocol_versions must be an array"))?;
    if versions.as_slice() != [Value::from(PROTOCOL_VERSION_V1)] {
        return Err(SessionError::version_unsupported());
    }
    ClientHello::new(
        u32_field(params, "wire_major")?,
        u32_field(params, "min_minor")?,
        u32_field(params, "max_minor")?,
        PROTOCOL_VERSION_V1,
        string_field(params, "install_id")?,
        string_field(params, "client_kind")?,
        string_field(params, "client_version")?,
        nonce_field(params, "client_nonce")?,
        u32_field(params, "max_response_frame")?,
    )
    .map_err(|_| SessionError::authentication())
}

fn client_auth_from_params(params: &Map<String, Value>) -> Result<ClientAuth, SessionError> {
    Ok(ClientAuth {
        client_nonce: nonce_field(params, "client_nonce")?,
        server_nonce: nonce_field(params, "server_nonce")?,
        client_proof: tag_field(params, "client_proof")?,
    })
}

fn challenge_to_value(challenge: &ServerChallenge) -> Value {
    json!({
        "kind": "handshake_challenge",
        "selected_major": challenge.selected_major,
        "selected_minor": challenge.selected_minor,
        "protocol_version": challenge.protocol_version,
        "install_id": challenge.install_id,
        "daemon_version": challenge.daemon_version,
        "daemon_generation": challenge.daemon_generation,
        "server_nonce": challenge.server_nonce.to_lower_hex(),
        "negotiated_limits": wire_limits_to_value(challenge.limits)
    })
}

/// Converts all thirteen native v1 limit fields to their exact schema names.
#[must_use]
pub fn wire_limits_to_value(limits: WireLimitsV1) -> Value {
    json!({
        "request_frame_bytes": limits.request_frame_bytes,
        "response_frame_bytes": limits.response_frame_bytes,
        "max_in_flight": limits.max_in_flight,
        "max_events_per_page": limits.max_events_per_page,
        "handshake_timeout_ms": limits.handshake_timeout_ms,
        "health_timeout_ms": limits.health_timeout_ms,
        "startup_timeout_ms": limits.startup_timeout_ms,
        "query_timeout_ms": limits.query_timeout_ms,
        "mutation_timeout_ms": limits.mutation_timeout_ms,
        "max_wait_ms": limits.max_wait_ms,
        "write_timeout_ms": limits.write_timeout_ms,
        "stderr_budget_bytes": limits.stderr_budget_bytes,
        "stderr_line_bytes": limits.stderr_line_bytes
    })
}

/// Strictly converts all thirteen schema limit fields through native validation.
///
/// # Errors
///
/// Rejects missing, unknown, non-u32, non-v1, and above-client-offer values.
pub fn wire_limits_from_value(
    value: &Value,
    client_max_response_frame: u32,
) -> Result<WireLimitsV1, SessionError> {
    const FIELD_COUNT: usize = 13;
    let values = value
        .as_object()
        .ok_or_else(|| SessionError::invalid_request("negotiated limits must be an object"))?;
    if values.len() != FIELD_COUNT {
        return Err(SessionError::invalid_request(
            "negotiated limits contain unknown or missing fields",
        ));
    }
    let limits = WireLimitsV1 {
        request_frame_bytes: u32_field(values, "request_frame_bytes")?,
        response_frame_bytes: u32_field(values, "response_frame_bytes")?,
        max_in_flight: u32_field(values, "max_in_flight")?,
        max_events_per_page: u32_field(values, "max_events_per_page")?,
        handshake_timeout_ms: u32_field(values, "handshake_timeout_ms")?,
        health_timeout_ms: u32_field(values, "health_timeout_ms")?,
        startup_timeout_ms: u32_field(values, "startup_timeout_ms")?,
        query_timeout_ms: u32_field(values, "query_timeout_ms")?,
        mutation_timeout_ms: u32_field(values, "mutation_timeout_ms")?,
        max_wait_ms: u32_field(values, "max_wait_ms")?,
        write_timeout_ms: u32_field(values, "write_timeout_ms")?,
        stderr_budget_bytes: u32_field(values, "stderr_budget_bytes")?,
        stderr_line_bytes: u32_field(values, "stderr_line_bytes")?,
    };
    // Do not duplicate the frozen negotiation rules here: construct a complete
    // native challenge and let mesh-win32 accept or reject the limit tuple.
    let client = ClientHello::new(
        WIRE_MAJOR_V1,
        WIRE_MINOR_V1,
        WIRE_MINOR_V1,
        PROTOCOL_VERSION_V1,
        "validation-install".to_owned(),
        "mcp-bridge-native".to_owned(),
        "validation".to_owned(),
        Nonce::from_bytes([0x11; NONCE_LENGTH]),
        client_max_response_frame,
    )
    .map_err(|_| SessionError::invalid_request("client response limit is invalid"))?;
    let challenge = ServerChallenge::new(
        &client,
        WIRE_MAJOR_V1,
        WIRE_MINOR_V1,
        PROTOCOL_VERSION_V1,
        client.install_id.clone(),
        "validation".to_owned(),
        0,
        Nonce::from_bytes([0x22; NONCE_LENGTH]),
        limits,
    )
    .map_err(|_| SessionError::invalid_request("negotiated limits are invalid"))?;
    Ok(challenge.limits)
}

fn required<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value, SessionError> {
    object
        .get(name)
        .ok_or_else(|| SessionError::invalid_request("required wire field is missing"))
}

fn u32_field(object: &Map<String, Value>, name: &str) -> Result<u32, SessionError> {
    required(object, name)?
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| SessionError::invalid_request("wire integer is outside u32"))
}

fn string_field(object: &Map<String, Value>, name: &str) -> Result<String, SessionError> {
    required(object, name)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| SessionError::invalid_request("wire field must be text"))
}

fn nonce_field(object: &Map<String, Value>, name: &str) -> Result<Nonce, SessionError> {
    Ok(Nonce::from_bytes(fixed_lower_hex::<NONCE_LENGTH>(
        required(object, name)?,
    )?))
}

fn tag_field(
    object: &Map<String, Value>,
    name: &str,
) -> Result<[u8; AUTH_TAG_LENGTH], SessionError> {
    fixed_lower_hex::<AUTH_TAG_LENGTH>(required(object, name)?)
}

fn fixed_lower_hex<const N: usize>(value: &Value) -> Result<[u8; N], SessionError> {
    let text = value
        .as_str()
        .ok_or_else(|| SessionError::invalid_request("authentication field must be text"))?;
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SessionError::authentication());
    }
    let mut output = [0_u8; N];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    Ok(output)
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn success_value(id: &RpcId, result: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id.to_value(), "result": result})
}

fn write_validated<T: FramedTransport>(
    transport: &mut T,
    value: &Value,
    maximum_payload_bytes: u32,
    deadline: Instant,
) -> Result<(), SessionError> {
    let payload = encode_wire_payload(value, maximum_payload_bytes)?;
    transport
        .write_payload(&payload, maximum_payload_bytes as usize, deadline)
        .map_err(SessionError::transport)
}

fn bounded_write_deadline(
    request_deadline: Instant,
    now: Instant,
    write_timeout: Duration,
) -> Result<Instant, SessionError> {
    if now >= request_deadline {
        return Err(SessionError::transport(TransportError::Timeout));
    }
    let transport_deadline = now.checked_add(write_timeout).unwrap_or(request_deadline);
    Ok(request_deadline.min(transport_deadline))
}

fn handshake_deadline() -> Instant {
    Instant::now()
        .checked_add(Duration::from_millis(u64::from(
            WireLimitsV1::protocol_v1_0().handshake_timeout_ms,
        )))
        .unwrap_or_else(Instant::now)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use super::*;

    type CapturedWrites = Arc<Mutex<Vec<Vec<u8>>>>;
    type CapturedDeadlines = Arc<Mutex<Vec<Instant>>>;

    #[derive(Clone)]
    struct FakeTransport {
        peer_pid: u32,
        reads: Arc<Mutex<VecDeque<Vec<Vec<u8>>>>>,
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        deadlines: CapturedDeadlines,
    }

    impl FakeTransport {
        fn new(payloads: impl IntoIterator<Item = Vec<Vec<u8>>>) -> Self {
            Self {
                peer_pid: 4242,
                reads: Arc::new(Mutex::new(payloads.into_iter().collect())),
                writes: Arc::new(Mutex::new(Vec::new())),
                deadlines: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl FramedTransport for FakeTransport {
        fn peer_pid(&self) -> u32 {
            self.peer_pid
        }

        fn read_payload(
            &mut self,
            maximum_payload_bytes: usize,
            deadline: Instant,
        ) -> Result<Vec<u8>, TransportError> {
            self.deadlines
                .lock()
                .map_err(|_| TransportError::Io)?
                .push(deadline);
            let chunks = self
                .reads
                .lock()
                .map_err(|_| TransportError::Io)?
                .pop_front()
                .ok_or(TransportError::ConnectionClosed)?;
            let length = chunks.iter().try_fold(0_usize, |total, chunk| {
                total
                    .checked_add(chunk.len())
                    .ok_or(TransportError::FrameTooLarge)
            })?;
            if length == 0 {
                return Err(TransportError::FrameInvalid);
            }
            if length > maximum_payload_bytes {
                return Err(TransportError::FrameTooLarge);
            }
            let mut payload = Vec::with_capacity(length);
            for chunk in chunks {
                payload.extend_from_slice(&chunk);
            }
            Ok(payload)
        }

        fn write_payload(
            &mut self,
            payload: &[u8],
            maximum_payload_bytes: usize,
            deadline: Instant,
        ) -> Result<(), TransportError> {
            self.deadlines
                .lock()
                .map_err(|_| TransportError::Io)?
                .push(deadline);
            if payload.is_empty() || payload.len() > maximum_payload_bytes {
                return Err(if payload.is_empty() {
                    TransportError::FrameInvalid
                } else {
                    TransportError::FrameTooLarge
                });
            }
            self.writes
                .lock()
                .map_err(|_| TransportError::Io)?
                .push(payload.to_vec());
            Ok(())
        }
    }

    fn golden(name: &str) -> Value {
        let source = match name {
            "hello" => include_str!("../../../protocol/v1/golden/wire-handshake-hello.json"),
            "challenge" => {
                include_str!("../../../protocol/v1/golden/wire-handshake-challenge.json")
            }
            "auth" => include_str!("../../../protocol/v1/golden/wire-handshake-auth.json"),
            "ready" => include_str!("../../../protocol/v1/golden/wire-handshake-ready.json"),
            "health" => include_str!("../../../protocol/v1/golden/wire-health-request.json"),
            "health-response" => {
                include_str!("../../../protocol/v1/golden/wire-health-response.json")
            }
            _ => panic!("unknown golden"),
        };
        serde_json::from_str(source).expect("golden JSON")
    }

    fn wire_golden(file_stem: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("protocol/v1/golden")
            .join(format!("{file_stem}.json"));
        serde_json::from_str(&std::fs::read_to_string(path).expect("wire golden"))
            .expect("wire golden JSON")
    }

    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("JSON bytes")
    }

    fn vector_nonce(byte: u8) -> Nonce {
        Nonce::from_bytes([byte; NONCE_LENGTH])
    }

    fn endpoint_key() -> EndpointKey {
        EndpointKey::from_bytes(std::array::from_fn(|index| {
            u8::try_from(index).expect("key index")
        }))
    }

    fn health() -> DaemonHealth {
        DaemonHealth::new(
            DaemonState::Ready,
            "install-001".to_owned(),
            "consumer-001".to_owned(),
            "0.1.0".to_owned(),
            7,
            1,
            1000,
        )
        .expect("health")
    }

    fn authenticate(
        extra_payloads: impl IntoIterator<Item = Vec<Vec<u8>>>,
    ) -> (
        AuthenticatedSession<FakeTransport>,
        CapturedWrites,
        CapturedDeadlines,
    ) {
        let mut payloads = vec![vec![bytes(&golden("hello"))], vec![bytes(&golden("auth"))]];
        payloads.extend(extra_payloads);
        let transport = FakeTransport::new(payloads);
        let writes = Arc::clone(&transport.writes);
        let deadlines = Arc::clone(&transport.deadlines);
        let key = Box::leak(Box::new(endpoint_key()));
        let guard = Box::leak(Box::new(NonceReplayGuard::new(8)));
        let challenged = AcceptedSession::new(transport, key, guard, health())
            .receive_hello_inner(Some(vector_nonce(0x22)))
            .expect("hello");
        let authenticated = challenged.receive_auth().expect("auth");
        (authenticated, writes, deadlines)
    }

    #[test]
    fn shared_four_phase_goldens_round_trip_through_win32_authority() {
        let (session, writes, deadlines) = authenticate([]);
        assert_eq!(session.peer_pid(), 4242);
        let writes = writes.lock().expect("writes");
        assert_eq!(writes.len(), 2);
        let challenge: Value = serde_json::from_slice(&writes[0]).expect("challenge JSON");
        let ready: Value = serde_json::from_slice(&writes[1]).expect("ready JSON");
        assert_eq!(challenge, golden("challenge"));
        assert_eq!(ready, golden("ready"));
        let deadlines = deadlines.lock().expect("deadlines");
        assert_eq!(deadlines.len(), 4);
        assert!(deadlines.iter().all(|deadline| *deadline == deadlines[0]));
    }

    #[test]
    fn all_thirteen_limits_round_trip_exactly() {
        let mut expected = WireLimitsV1::protocol_v1_0();
        expected.response_frame_bytes = 4096;
        let encoded = wire_limits_to_value(expected);
        assert_eq!(
            wire_limits_from_value(&encoded, 4096).expect("decode limits"),
            expected
        );
        assert_eq!(encoded.as_object().expect("object").len(), 13);

        let mut wrong = encoded.clone();
        wrong["max_in_flight"] = Value::from(17);
        assert!(wire_limits_from_value(&wrong, 4096).is_err());
        wrong = encoded;
        wrong["unknown"] = Value::from(1);
        assert!(wire_limits_from_value(&wrong, 4096).is_err());
    }

    #[test]
    fn rejects_wrong_id_install_version_phase_unknown_and_duplicate_field_before_proof() {
        let cases = [
            ("id", json!(9)),
            ("install_id", json!("different-install")),
            ("wire_major", json!(2)),
            ("phase", json!("auth")),
            ("unknown", json!(true)),
            ("max_response_frame", json!(4095)),
            ("client_nonce", json!("AA".repeat(32))),
        ];
        for (field, replacement) in cases {
            let mut hello = golden("hello");
            if field == "id" {
                hello[field] = replacement;
            } else {
                hello["params"][field] = replacement;
            }
            let transport = FakeTransport::new([vec![bytes(&hello)]]);
            let key = endpoint_key();
            let guard = NonceReplayGuard::new(8);
            assert!(
                AcceptedSession::new(transport, &key, &guard, health())
                    .receive_hello_inner(Some(vector_nonce(0x22)))
                    .is_err(),
                "{field}"
            );
        }

        let duplicate = br#"{"jsonrpc":"2.0","id":"handshake-1","method":"mesh.handshake","method":"mesh.health","params":{}}"#.to_vec();
        let transport = FakeTransport::new([vec![duplicate]]);
        let key = endpoint_key();
        let guard = NonceReplayGuard::new(8);
        assert!(
            AcceptedSession::new(transport, &key, &guard, health())
                .receive_hello_inner(Some(vector_nonce(0x22)))
                .is_err()
        );
    }

    #[test]
    fn hello_nonce_replay_fails_closed() {
        let key = endpoint_key();
        let guard = NonceReplayGuard::new(8);
        let first = FakeTransport::new([vec![bytes(&golden("hello"))]]);
        AcceptedSession::new(first, &key, &guard, health())
            .receive_hello_inner(Some(vector_nonce(0x22)))
            .expect("first hello");
        let replay = FakeTransport::new([vec![bytes(&golden("hello"))]]);
        assert_eq!(
            AcceptedSession::new(replay, &key, &guard, health())
                .receive_hello_inner(Some(vector_nonce(0x22)))
                .err()
                .expect("replay error")
                .code,
            ErrorCode::IpcAuthenticationFailed
        );
    }

    #[test]
    fn unsupported_hello_versions_are_distinct_from_malformed_hello() {
        let mut unsupported = golden("hello");
        unsupported["params"]["protocol_versions"] = json!([2]);
        let transport = FakeTransport::new([vec![bytes(&unsupported)]]);
        let key = endpoint_key();
        let guard = NonceReplayGuard::new(8);
        assert_eq!(
            AcceptedSession::new(transport, &key, &guard, health())
                .receive_hello_inner(Some(vector_nonce(0x22)))
                .err()
                .expect("unsupported version")
                .code,
            ErrorCode::VersionUnsupported
        );

        unsupported["params"]["unknown"] = json!(true);
        let transport = FakeTransport::new([vec![bytes(&unsupported)]]);
        let guard = NonceReplayGuard::new(8);
        assert_eq!(
            AcceptedSession::new(transport, &key, &guard, health())
                .receive_hello_inner(Some(vector_nonce(0x22)))
                .err()
                .expect("malformed version offer")
                .code,
            ErrorCode::ValidationFailed
        );
    }

    #[test]
    fn health_and_task_requests_are_unavailable_before_auth() {
        for value in [
            golden("health"),
            json!({"jsonrpc":"2.0","id":4,"method":"mesh.list_agents","params":{}}),
        ] {
            let transport = FakeTransport::new([vec![bytes(&value)]]);
            let key = endpoint_key();
            let guard = NonceReplayGuard::new(8);
            assert!(
                AcceptedSession::new(transport, &key, &guard, health())
                    .receive_hello_inner(Some(vector_nonce(0x22)))
                    .is_err()
            );
        }
    }

    #[test]
    fn wrong_nonce_or_tag_never_emits_ready() {
        for field in ["client_nonce", "server_nonce", "client_proof"] {
            let mut auth = golden("auth");
            auth["params"][field] = Value::from("33".repeat(32));
            let transport = FakeTransport::new([vec![bytes(&golden("hello"))], vec![bytes(&auth)]]);
            let writes = Arc::clone(&transport.writes);
            let key = endpoint_key();
            let guard = NonceReplayGuard::new(8);
            let challenged = AcceptedSession::new(transport, &key, &guard, health())
                .receive_hello_inner(Some(vector_nonce(0x22)))
                .expect("challenge");
            assert!(challenged.receive_auth().is_err(), "{field}");
            assert_eq!(writes.lock().expect("writes").len(), 1, "{field}");
        }
    }

    #[test]
    fn auth_rejects_wrong_id_phase_unknown_and_non_lower_hex_tag() {
        let cases = [
            ("id", json!(8)),
            ("phase", json!("hello")),
            ("unknown", json!(true)),
            ("client_proof", json!("AA".repeat(32))),
        ];
        for (field, replacement) in cases {
            let mut auth = golden("auth");
            if field == "id" {
                auth[field] = replacement;
            } else {
                auth["params"][field] = replacement;
            }
            let transport = FakeTransport::new([vec![bytes(&golden("hello"))], vec![bytes(&auth)]]);
            let writes = Arc::clone(&transport.writes);
            let key = endpoint_key();
            let guard = NonceReplayGuard::new(8);
            let challenged = AcceptedSession::new(transport, &key, &guard, health())
                .receive_hello_inner(Some(vector_nonce(0x22)))
                .expect("challenge");
            assert!(challenged.receive_auth().is_err(), "{field}");
            assert_eq!(writes.lock().expect("writes").len(), 1, "{field}");
        }
    }

    #[test]
    fn authenticated_session_admits_exactly_health_and_eight_task_methods() {
        let cases = [
            ("health", RpcMethod::Health),
            ("list_agents", RpcMethod::ListAgents),
            ("delegate_task", RpcMethod::DelegateTask),
            ("inspect_task", RpcMethod::InspectTask),
            ("wait_task", RpcMethod::WaitTask),
            ("send_task_input", RpcMethod::SendTaskInput),
            ("cancel_task", RpcMethod::CancelTask),
            ("review_task", RpcMethod::ReviewTask),
            ("improvement_case", RpcMethod::ImprovementCase),
        ];
        let payloads: Vec<_> = cases
            .iter()
            .map(|(name, _)| {
                let value = if *name == "health" {
                    golden("health")
                } else {
                    let path = format!(
                        "protocol/v1/golden/wire-{}-request.json",
                        name.replace('_', "-")
                    );
                    let source = std::fs::read_to_string(
                        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                            .join("../..")
                            .join(path),
                    )
                    .expect("request golden");
                    serde_json::from_str(&source).expect("request JSON")
                };
                vec![bytes(&value)]
            })
            .collect();
        let (mut session, _, _) = authenticate(payloads);
        for (_, expected) in cases {
            assert_eq!(
                session.read_request().expect("admitted request").method(),
                expected
            );
        }
    }

    #[test]
    fn post_auth_rehandshake_is_rejected_and_health_id_is_preserved() {
        let health_request =
            json!({"jsonrpc":"2.0","id":"health-custom","method":"mesh.health","params":{}});
        let (mut session, writes, _) =
            authenticate([vec![bytes(&health_request)], vec![bytes(&golden("hello"))]]);
        let request = session.read_request().expect("health request");
        assert_eq!(request.id(), &RpcId::Text("health-custom".to_owned()));
        let response = session.health_response(request).expect("health response");
        session.write_response(response).expect("write response");
        let last: Value =
            serde_json::from_slice(writes.lock().expect("writes").last().expect("response"))
                .expect("response JSON");
        assert_eq!(last["id"], "health-custom");
        assert_eq!(last["result"]["kind"], "health_result");

        assert!(session.read_request().is_err());
    }

    #[test]
    fn pending_capability_rejects_cross_connection_response_and_releases_id() {
        let request = json!({"jsonrpc":"2.0","id":"shared-id","method":"mesh.health","params":{}});
        let (mut first, _, _) = authenticate([vec![bytes(&request)], vec![bytes(&request)]]);
        let (mut second, _, _) = authenticate([]);

        let pending = first.read_request().expect("first request");
        let response = first.health_response(pending).expect("response");
        assert_eq!(
            second
                .write_response(response)
                .expect_err("cross-connection response")
                .code,
            ErrorCode::ValidationFailed
        );

        let reused = first
            .read_request()
            .expect("ID released after rejected write");
        assert_eq!(reused.id(), &RpcId::Text("shared-id".to_owned()));
    }

    #[test]
    fn duplicate_ids_and_seventeenth_pending_request_are_rejected() {
        let duplicate = json!({"jsonrpc":"2.0","id":7,"method":"mesh.health","params":{}});
        let (mut duplicate_session, _, _) = authenticate([
            vec![bytes(&duplicate)],
            vec![bytes(&duplicate)],
            vec![bytes(&duplicate)],
        ]);
        let first = duplicate_session.read_request().expect("first ID");
        assert_eq!(
            duplicate_session
                .read_request()
                .err()
                .expect("duplicate outstanding ID")
                .code,
            ErrorCode::ValidationFailed
        );
        drop(first);
        assert!(duplicate_session.read_request().is_ok());

        let payloads = (0_u64..17).map(|id| {
            vec![bytes(
                &json!({"jsonrpc":"2.0","id":id,"method":"mesh.health","params":{}}),
            )]
        });
        let (mut session, _, _) = authenticate(payloads);
        let mut pending = Vec::new();
        for _ in 0..16 {
            pending.push(session.read_request().expect("within max_in_flight"));
        }
        assert_eq!(
            session
                .read_request()
                .err()
                .expect("seventeenth outstanding request")
                .code,
            ErrorCode::ValidationFailed
        );
        drop(pending);
    }

    #[test]
    fn success_result_kind_is_bound_to_the_request_method() {
        let methods = [
            "health",
            "list-agents",
            "delegate-task",
            "inspect-task",
            "wait-task",
            "send-task-input",
            "cancel-task",
            "review-task",
            "improvement-case",
        ];
        let health_result = wire_golden("wire-health-response")["result"].clone();
        let list_result = wire_golden("wire-list-agents-response")["result"].clone();
        for method in methods {
            let request = wire_golden(&format!("wire-{method}-request"));
            let wrong_result = if method == "health" {
                &list_result
            } else {
                &health_result
            };
            let (mut session, _, _) = authenticate([vec![bytes(&request)]]);
            let pending = session.read_request().expect("pending request");
            assert_eq!(
                pending
                    .success(wrong_result)
                    .err()
                    .expect("wrong result kind")
                    .code,
                ErrorCode::ValidationFailed,
                "{method}"
            );
            assert!(
                session
                    .connection_state
                    .lock()
                    .expect("connection state")
                    .by_token
                    .is_empty(),
                "{method}"
            );
        }
    }

    #[test]
    fn structured_error_is_bound_to_request_id_and_consumed_by_write() {
        let request = json!({"jsonrpc":"2.0","id":"error-id","method":"mesh.health","params":{}});
        let (mut session, writes, _) = authenticate([vec![bytes(&request)]]);
        let pending = session.read_request().expect("pending request");
        let response = pending
            .error(&RpcErrorSpec::new(
                -32000,
                ErrorCode::ValidationFailed,
                RpcRetryClass::DeterministicFailure,
                RpcEffectClass::NoEffect,
                RpcLifecycle::BeforeProcessCreation,
                "evidence-1".to_owned(),
                "request failed validation".to_owned(),
                "diagnostic-1".to_owned(),
            ))
            .expect("structured error");
        session.write_response(response).expect("error write");
        let value: Value = serde_json::from_slice(
            writes
                .lock()
                .expect("writes")
                .last()
                .expect("error response"),
        )
        .expect("error JSON");
        assert_eq!(value["id"], "error-id");
        assert_eq!(value["error"]["data"]["error"]["code"], "VALIDATION_FAILED");
        assert!(decode_wire_payload(&bytes(&value), 8_388_608).is_ok());
    }

    #[test]
    fn method_deadlines_cover_health_queries_mutations_and_wait_boundaries() {
        let empty = Map::new();
        assert_eq!(
            RpcMethod::Health.timeout(&empty).unwrap(),
            Duration::from_secs(2)
        );
        assert_eq!(
            RpcMethod::ListAgents.timeout(&empty).unwrap(),
            Duration::from_secs(5)
        );
        assert_eq!(
            RpcMethod::InspectTask.timeout(&empty).unwrap(),
            Duration::from_secs(5)
        );
        assert_eq!(
            RpcMethod::DelegateTask.timeout(&empty).unwrap(),
            Duration::from_secs(10)
        );
        for (wait_ms, expected_ms) in [(0_u64, 5_000_u64), (30_000, 35_000)] {
            let params = Map::from_iter([("wait_ms".to_owned(), Value::from(wait_ms))]);
            assert_eq!(
                RpcMethod::WaitTask.timeout(&params).unwrap(),
                Duration::from_millis(expected_ms)
            );
        }

        let before = Instant::now();
        let (mut session, _, _) = authenticate([vec![bytes(&golden("health"))]]);
        let pending = session.read_request().expect("health request");
        let after = Instant::now();
        assert!(pending.deadline() >= before + Duration::from_secs(2));
        assert!(pending.deadline() <= after + Duration::from_secs(2));
    }

    #[test]
    fn bounded_write_deadline_uses_the_remaining_method_budget() {
        let now = Instant::now();
        let short_request_deadline = now + Duration::from_secs(3);
        assert_eq!(
            bounded_write_deadline(short_request_deadline, now, Duration::from_secs(5))
                .expect("request deadline is earlier"),
            short_request_deadline
        );

        let long_request_deadline = now + Duration::from_secs(10);
        assert_eq!(
            bounded_write_deadline(long_request_deadline, now, Duration::from_secs(5))
                .expect("write timeout is earlier"),
            now + Duration::from_secs(5)
        );

        for expired in [now, now.checked_sub(Duration::from_nanos(1)).expect("past")] {
            assert_eq!(
                bounded_write_deadline(expired, now, Duration::from_secs(5))
                    .expect_err("expired request")
                    .code,
                ErrorCode::IpcIoTimeout
            );
        }
    }

    #[test]
    fn success_and_error_responses_inherit_deadline_and_expiry_skips_transport() {
        let first = json!({"jsonrpc":"2.0","id":"late-success","method":"mesh.health","params":{}});
        let second = json!({"jsonrpc":"2.0","id":"late-error","method":"mesh.health","params":{}});
        let (mut session, writes, _) = authenticate([vec![bytes(&first)], vec![bytes(&second)]]);
        let writes_before = writes.lock().expect("writes").len();

        let pending = session.read_request().expect("success request");
        let request_deadline = pending.deadline();
        let response = session.health_response(pending).expect("health response");
        assert_eq!(
            response
                .capability
                .as_ref()
                .expect("response capability")
                .deadline,
            request_deadline
        );
        assert_eq!(
            session
                .write_response_at(response, request_deadline)
                .expect_err("expired success response")
                .code,
            ErrorCode::IpcIoTimeout
        );
        assert_eq!(writes.lock().expect("writes").len(), writes_before);

        let pending = session.read_request().expect("error request");
        let request_deadline = pending.deadline();
        let response = pending
            .error(&RpcErrorSpec::new(
                -32000,
                ErrorCode::ValidationFailed,
                RpcRetryClass::DeterministicFailure,
                RpcEffectClass::NoEffect,
                RpcLifecycle::BeforeProcessCreation,
                "deadline-test".to_owned(),
                "request expired".to_owned(),
                "deadline-test".to_owned(),
            ))
            .expect("structured error");
        assert_eq!(
            response
                .capability
                .as_ref()
                .expect("response capability")
                .deadline,
            request_deadline
        );
        assert_eq!(
            session
                .write_response_at(response, request_deadline)
                .expect_err("expired error response")
                .code,
            ErrorCode::IpcIoTimeout
        );
        assert_eq!(writes.lock().expect("writes").len(), writes_before);
        assert!(
            session
                .connection_state
                .lock()
                .expect("connection state")
                .by_token
                .is_empty()
        );
    }

    #[test]
    fn every_method_budget_is_enforced_through_response_write() {
        for method in ["health", "list-agents", "delegate-task", "wait-task"] {
            let request = wire_golden(&format!("wire-{method}-request"));
            let result = wire_golden(&format!("wire-{method}-response"))["result"].clone();
            let (mut session, writes, _) = authenticate([vec![bytes(&request)]]);
            let writes_before = writes.lock().expect("writes").len();

            let pending = session.read_request().expect("pending request");
            let request_deadline = pending.deadline();
            let response = pending.success(&result).expect("typed response");
            assert_eq!(
                session
                    .write_response_at(response, request_deadline)
                    .expect_err("method deadline includes response delivery")
                    .code,
                ErrorCode::IpcIoTimeout,
                "{method}"
            );
            assert_eq!(
                writes.lock().expect("writes").len(),
                writes_before,
                "{method}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn native_transport_errors_keep_stable_public_categories() {
        use mesh_win32::{NativeError, NativeErrorCode, NativeOperation};

        let cases = [
            (NativeErrorCode::FrameInvalid, ErrorCode::IpcFrameInvalid),
            (NativeErrorCode::FrameTooLarge, ErrorCode::IpcFrameTooLarge),
            (NativeErrorCode::IoTimeout, ErrorCode::IpcIoTimeout),
            (
                NativeErrorCode::ConnectionClosed,
                ErrorCode::IpcFrameInvalid,
            ),
            (NativeErrorCode::OsFailure, ErrorCode::ProtocolMalformed),
        ];
        for (native, expected) in cases {
            let native = NativeError::new(native, NativeOperation::ReadFrame);
            assert_eq!(SessionError::transport(native.into()).code, expected);
        }
    }

    #[test]
    fn fake_transport_handles_split_and_coalesced_payload_delivery() {
        let hello = bytes(&golden("hello"));
        let midpoint = hello.len() / 2;
        let split = vec![hello[..midpoint].to_vec(), hello[midpoint..].to_vec()];
        let auth = bytes(&golden("auth"));
        // One read can be assembled from split chunks; two complete payloads
        // queued together remain distinct reads rather than becoming one JSON value.
        let transport = FakeTransport::new([split, vec![auth]]);
        let key = endpoint_key();
        let guard = NonceReplayGuard::new(8);
        let challenged = AcceptedSession::new(transport, &key, &guard, health())
            .receive_hello_inner(Some(vector_nonce(0x22)))
            .expect("split hello");
        assert!(challenged.receive_auth().is_ok());
    }

    #[test]
    fn health_identity_is_typed_bounded_and_exact() {
        assert!(
            DaemonHealth::new(
                DaemonState::Running,
                "bad install".to_owned(),
                "consumer-001".to_owned(),
                "0.1.0".to_owned(),
                7,
                1,
                1000,
            )
            .is_err()
        );
        assert!(
            DaemonHealth::new(
                DaemonState::Running,
                "install-001".to_owned(),
                "consumer-001".to_owned(),
                "0.1.0".to_owned(),
                MAX_SAFE_INTEGER + 1,
                1,
                1000,
            )
            .is_err()
        );
        assert!(
            DaemonHealth::new(
                DaemonState::Running,
                "install-001".to_owned(),
                "consumer-001".to_owned(),
                "0.1.0".to_owned(),
                7,
                0,
                1000,
            )
            .is_err()
        );
    }
}
