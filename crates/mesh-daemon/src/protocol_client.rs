//! Bridge-side authenticated wire session.
//!
//! The consuming states in this module deliberately keep the framed transport
//! private until the daemon has returned a proof bound to the complete native
//! handshake transcript. HMAC and transcript construction stay exclusively in
//! `mesh-win32`.

use std::time::{Duration, Instant};

use mesh_win32::{
    AUTH_TAG_LENGTH, ClientAuth, ClientHello, EndpointKey, NONCE_LENGTH, Nonce,
    PROTOCOL_VERSION_V1, ServerChallenge, ServerReady, WIRE_MAJOR_V1, WIRE_MINOR_V1, WireLimitsV1,
};
use serde_json::{Map, Value, json};

use crate::{
    ErrorCode,
    protocol_frame::{decode_wire_payload, encode_wire_payload},
    protocol_handshake::{
        DaemonHealth, DaemonState, FramedTransport, SessionError, TransportError,
        wire_limits_from_value,
    },
};

const HANDSHAKE_HELLO_ID: &str = "handshake-1";
const HANDSHAKE_AUTH_ID: &str = "handshake-2";
const CLIENT_KIND: &str = "mcp-bridge-native";

/// Starts a client handshake and consumes the transport through all four wire
/// phases.
///
/// # Errors
///
/// Returns a stable, redaction-safe session error when local identity is
/// invalid, nonce generation fails, transport I/O fails, or the daemon does not
/// complete the exact authenticated v1 handshake.
pub fn authenticate_client<T: FramedTransport>(
    transport: T,
    endpoint_key: &EndpointKey,
    install_id: String,
    client_version: String,
    maximum_response_frame: u32,
) -> Result<AuthenticatedClient<T>, SessionError> {
    ClientHandshake::new(
        transport,
        endpoint_key,
        install_id,
        client_version,
        maximum_response_frame,
    )?
    .send_hello()?
    .receive_challenge()?
    .send_auth()?
    .receive_ready()
}

/// An unstarted client handshake. There is intentionally no transport accessor.
pub struct ClientHandshake<'a, T> {
    transport: T,
    endpoint_key: &'a EndpointKey,
    client: ClientHello,
    deadline: Instant,
}

impl<'a, T: FramedTransport> ClientHandshake<'a, T> {
    /// Creates a v1 bridge hello and one absolute deadline for the entire
    /// handshake.
    ///
    /// # Errors
    ///
    /// Rejects invalid local identity/version/limits or nonce generation
    /// failure before writing to the transport.
    pub fn new(
        transport: T,
        endpoint_key: &'a EndpointKey,
        install_id: String,
        client_version: String,
        maximum_response_frame: u32,
    ) -> Result<Self, SessionError> {
        let nonce = Nonce::generate().map_err(|_| authentication_error())?;
        let deadline = handshake_deadline()?;
        Self::with_nonce_and_deadline(
            transport,
            endpoint_key,
            install_id,
            client_version,
            maximum_response_frame,
            nonce,
            deadline,
        )
    }

    fn with_nonce_and_deadline(
        transport: T,
        endpoint_key: &'a EndpointKey,
        install_id: String,
        client_version: String,
        maximum_response_frame: u32,
        nonce: Nonce,
        deadline: Instant,
    ) -> Result<Self, SessionError> {
        let client = ClientHello::new(
            WIRE_MAJOR_V1,
            WIRE_MINOR_V1,
            WIRE_MINOR_V1,
            PROTOCOL_VERSION_V1,
            install_id,
            CLIENT_KIND.to_owned(),
            client_version,
            nonce,
            maximum_response_frame,
        )
        .map_err(|_| invalid_request("client handshake identity is invalid"))?;
        Ok(Self {
            transport,
            endpoint_key,
            client,
            deadline,
        })
    }

    /// Writes the fixed-ID, schema-valid hello and consumes this state.
    ///
    /// # Errors
    ///
    /// Rejects encoding, size, deadline, and transport failures.
    pub fn send_hello(mut self) -> Result<HelloSentClient<'a, T>, SessionError> {
        let value = json!({
            "jsonrpc": "2.0",
            "id": HANDSHAKE_HELLO_ID,
            "method": "mesh.handshake",
            "params": {
                "phase": "hello",
                "wire_major": self.client.wire_major,
                "min_minor": self.client.min_minor,
                "max_minor": self.client.max_minor,
                "protocol_versions": [self.client.protocol_version],
                "install_id": self.client.install_id,
                "client_kind": self.client.client_kind,
                "client_version": self.client.client_version,
                "client_nonce": self.client.client_nonce.to_lower_hex(),
                "max_response_frame": self.client.max_response_frame
            }
        });
        write_wire(
            &mut self.transport,
            &value,
            WireLimitsV1::protocol_v1_0().request_frame_bytes,
            self.deadline,
        )?;
        Ok(HelloSentClient {
            transport: self.transport,
            endpoint_key: self.endpoint_key,
            client: self.client,
            deadline: self.deadline,
        })
    }
}

/// A client that has sent hello and may only receive its matching challenge.
pub struct HelloSentClient<'a, T> {
    transport: T,
    endpoint_key: &'a EndpointKey,
    client: ClientHello,
    deadline: Instant,
}

impl<'a, T: FramedTransport> HelloSentClient<'a, T> {
    /// Reads and validates the fixed-ID challenge through the schema and native
    /// transcript boundary.
    ///
    /// # Errors
    ///
    /// Rejects malformed JSON, wrong IDs/kinds, incompatible identity/version,
    /// invalid nonces/limits, deadlines, and transport failures.
    pub fn receive_challenge(mut self) -> Result<ChallengedClient<'a, T>, SessionError> {
        let payload = read_wire(
            &mut self.transport,
            self.client.max_response_frame,
            self.deadline,
        )?;
        let object = decode_wire_payload(&payload, self.client.max_response_frame)?;
        let result = success_result(&object, HANDSHAKE_HELLO_ID, "handshake_challenge")?;
        let limits = wire_limits_from_value(
            required(result, "negotiated_limits")?,
            self.client.max_response_frame,
        )?;
        let challenge = ServerChallenge::new(
            &self.client,
            u32_field(result, "selected_major")?,
            u32_field(result, "selected_minor")?,
            u32_field(result, "protocol_version")?,
            string_field(result, "install_id")?,
            string_field(result, "daemon_version")?,
            u64_field(result, "daemon_generation")?,
            nonce_field(result, "server_nonce")?,
            limits,
        )
        .map_err(|_| authentication_error())?;
        Ok(ChallengedClient {
            transport: self.transport,
            endpoint_key: self.endpoint_key,
            client: self.client,
            challenge,
            deadline: self.deadline,
        })
    }
}

/// A client holding a fully validated challenge and no ordinary RPC API.
pub struct ChallengedClient<'a, T> {
    transport: T,
    endpoint_key: &'a EndpointKey,
    client: ClientHello,
    challenge: ServerChallenge,
    deadline: Instant,
}

impl<'a, T: FramedTransport> ChallengedClient<'a, T> {
    /// Creates the client proof exclusively through `mesh-win32`, writes the
    /// fixed-ID auth request, and consumes this state.
    ///
    /// # Errors
    ///
    /// Rejects proof construction, schema, size, deadline, and transport
    /// failures.
    pub fn send_auth(mut self) -> Result<AuthSentClient<'a, T>, SessionError> {
        let auth = ClientAuth::signed(self.endpoint_key, &self.client, &self.challenge)
            .map_err(|_| authentication_error())?;
        let value = json!({
            "jsonrpc": "2.0",
            "id": HANDSHAKE_AUTH_ID,
            "method": "mesh.handshake",
            "params": {
                "phase": "auth",
                "client_nonce": auth.client_nonce.to_lower_hex(),
                "server_nonce": auth.server_nonce.to_lower_hex(),
                "client_proof": lower_hex(&auth.client_proof)
            }
        });
        write_wire(
            &mut self.transport,
            &value,
            self.challenge.limits.request_frame_bytes,
            self.deadline,
        )?;
        Ok(AuthSentClient {
            transport: self.transport,
            endpoint_key: self.endpoint_key,
            client: self.client,
            challenge: self.challenge,
            auth,
            deadline: self.deadline,
        })
    }
}

/// A client that has sent its proof and may only receive daemon readiness.
pub struct AuthSentClient<'a, T> {
    transport: T,
    endpoint_key: &'a EndpointKey,
    client: ClientHello,
    challenge: ServerChallenge,
    auth: ClientAuth,
    deadline: Instant,
}

impl<T: FramedTransport> AuthSentClient<'_, T> {
    /// Verifies the matching ready health and server proof before releasing the
    /// transport.
    ///
    /// # Errors
    ///
    /// Rejects malformed JSON, wrong IDs/kinds/health, invalid server proof,
    /// deadlines, and transport failures.
    pub fn receive_ready(mut self) -> Result<AuthenticatedClient<T>, SessionError> {
        let payload = read_wire(
            &mut self.transport,
            self.challenge.limits.response_frame_bytes,
            self.deadline,
        )?;
        let object = decode_wire_payload(&payload, self.challenge.limits.response_frame_bytes)?;
        let result = success_result(&object, HANDSHAKE_AUTH_ID, "handshake_ready")?;
        let health = daemon_health_from_value(required(result, "health")?, &self.challenge)?;
        let ready = ServerReady {
            server_proof: tag_field(result, "server_proof")?,
        };
        ready
            .verify(self.endpoint_key, &self.client, &self.challenge, &self.auth)
            .map_err(|_| authentication_error())?;
        Ok(AuthenticatedClient {
            transport: self.transport,
            health,
            limits: self.challenge.limits,
        })
    }
}

/// A mutually authenticated bridge connection.
pub struct AuthenticatedClient<T> {
    transport: T,
    health: DaemonHealth,
    limits: WireLimitsV1,
}

impl<T> AuthenticatedClient<T> {
    #[must_use]
    pub const fn health(&self) -> &DaemonHealth {
        &self.health
    }

    #[must_use]
    pub const fn negotiated_limits(&self) -> WireLimitsV1 {
        self.limits
    }

    /// Releases the transport together with the exact authenticated health and
    /// negotiated-limit evidence. No pre-authentication state has this API.
    #[must_use]
    pub fn into_parts(self) -> (T, DaemonHealth, WireLimitsV1) {
        (self.transport, self.health, self.limits)
    }
}

fn daemon_health_from_value(
    value: &Value,
    challenge: &ServerChallenge,
) -> Result<DaemonHealth, SessionError> {
    let health = value
        .as_object()
        .ok_or_else(|| invalid_request("daemon health must be an object"))?;
    let state = match required(health, "daemon_state")?.as_str() {
        Some("READY") => DaemonState::Ready,
        Some("RUNNING") => DaemonState::Running,
        _ => return Err(invalid_request("daemon health state is invalid")),
    };
    let install_id = string_field(health, "install_id")?;
    let daemon_version = string_field(health, "daemon_version")?;
    let daemon_generation = u64_field(health, "daemon_generation")?;
    if required(health, "kind")? != "daemon_health"
        || u32_field(health, "wire_major")? != challenge.selected_major
        || u32_field(health, "wire_minor")? != challenge.selected_minor
        || u32_field(health, "protocol_version")? != challenge.protocol_version
        || install_id != challenge.install_id
        || daemon_version != challenge.daemon_version
        || daemon_generation != challenge.daemon_generation
    {
        return Err(authentication_error());
    }
    DaemonHealth::new(
        state,
        install_id,
        string_field(health, "consumer_id")?,
        daemon_version,
        daemon_generation,
        u64_field(health, "data_schema_version")?,
        u64_field(health, "started_at_ms")?,
    )
}

fn success_result<'a>(
    object: &'a Map<String, Value>,
    expected_id: &str,
    expected_kind: &str,
) -> Result<&'a Map<String, Value>, SessionError> {
    if object.get("id") != Some(&Value::from(expected_id)) {
        return Err(invalid_request("unexpected handshake response id"));
    }
    let result = object
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_request("handshake did not return a success result"))?;
    if result.get("kind").and_then(Value::as_str) != Some(expected_kind) {
        return Err(invalid_request("unexpected handshake response kind"));
    }
    Ok(result)
}

fn required<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value, SessionError> {
    object
        .get(name)
        .ok_or_else(|| invalid_request("required handshake field is missing"))
}

fn u32_field(object: &Map<String, Value>, name: &str) -> Result<u32, SessionError> {
    required(object, name)?
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| invalid_request("handshake integer is outside u32"))
}

fn u64_field(object: &Map<String, Value>, name: &str) -> Result<u64, SessionError> {
    required(object, name)?
        .as_u64()
        .ok_or_else(|| invalid_request("handshake integer is outside u64"))
}

fn string_field(object: &Map<String, Value>, name: &str) -> Result<String, SessionError> {
    required(object, name)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_request("handshake field must be text"))
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
        .ok_or_else(|| invalid_request("authentication field must be text"))?;
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(authentication_error());
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

fn read_wire<T: FramedTransport>(
    transport: &mut T,
    maximum_payload_bytes: u32,
    deadline: Instant,
) -> Result<Vec<u8>, SessionError> {
    ensure_before(deadline)?;
    let payload = transport
        .read_payload(maximum_payload_bytes as usize, deadline)
        .map_err(transport_error)?;
    ensure_before(deadline)?;
    Ok(payload)
}

fn write_wire<T: FramedTransport>(
    transport: &mut T,
    value: &Value,
    maximum_payload_bytes: u32,
    deadline: Instant,
) -> Result<(), SessionError> {
    ensure_before(deadline)?;
    let payload = encode_wire_payload(value, maximum_payload_bytes)?;
    transport
        .write_payload(&payload, maximum_payload_bytes as usize, deadline)
        .map_err(transport_error)?;
    ensure_before(deadline)
}

fn handshake_deadline() -> Result<Instant, SessionError> {
    Instant::now()
        .checked_add(Duration::from_millis(u64::from(
            WireLimitsV1::protocol_v1_0().handshake_timeout_ms,
        )))
        .ok_or_else(|| invalid_request("handshake deadline overflows"))
}

fn ensure_before(deadline: Instant) -> Result<(), SessionError> {
    if Instant::now() >= deadline {
        return Err(transport_error(TransportError::Timeout));
    }
    Ok(())
}

const fn invalid_request(message: &'static str) -> SessionError {
    SessionError {
        code: ErrorCode::ValidationFailed,
        message,
    }
}

const fn authentication_error() -> SessionError {
    SessionError {
        code: ErrorCode::IpcAuthenticationFailed,
        message: "pipe authentication failed",
    }
}

const fn transport_error(error: TransportError) -> SessionError {
    match error {
        TransportError::FrameInvalid => SessionError {
            code: ErrorCode::IpcFrameInvalid,
            message: "pipe frame is invalid",
        },
        TransportError::FrameTooLarge => SessionError {
            code: ErrorCode::IpcFrameTooLarge,
            message: "pipe frame is too large",
        },
        TransportError::Timeout => SessionError {
            code: ErrorCode::IpcIoTimeout,
            message: "pipe I/O timed out",
        },
        TransportError::ConnectionClosed => SessionError {
            code: ErrorCode::IpcFrameInvalid,
            message: "pipe connection closed during a frame",
        },
        TransportError::Io => SessionError {
            code: ErrorCode::ProtocolMalformed,
            message: "pipe transport failed",
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use super::*;

    type ReadQueue = Arc<Mutex<VecDeque<Result<Vec<u8>, TransportError>>>>;

    #[derive(Clone)]
    struct FakeTransport {
        reads: ReadQueue,
        writes: Arc<Mutex<Vec<Vec<u8>>>>,
        deadlines: Arc<Mutex<Vec<Instant>>>,
        maximums: Arc<Mutex<Vec<usize>>>,
    }

    impl FakeTransport {
        fn new(reads: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                reads: Arc::new(Mutex::new(
                    reads.into_iter().map(Ok).collect::<VecDeque<_>>(),
                )),
                writes: Arc::new(Mutex::new(Vec::new())),
                deadlines: Arc::new(Mutex::new(Vec::new())),
                maximums: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn failing(error: TransportError) -> Self {
            Self {
                reads: Arc::new(Mutex::new(VecDeque::from([Err(error)]))),
                writes: Arc::new(Mutex::new(Vec::new())),
                deadlines: Arc::new(Mutex::new(Vec::new())),
                maximums: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    impl FramedTransport for FakeTransport {
        fn peer_pid(&self) -> u32 {
            41
        }

        fn read_payload(
            &mut self,
            maximum_payload_bytes: usize,
            deadline: Instant,
        ) -> Result<Vec<u8>, TransportError> {
            self.deadlines.lock().expect("deadlines").push(deadline);
            self.maximums
                .lock()
                .expect("maximums")
                .push(maximum_payload_bytes);
            let payload = self
                .reads
                .lock()
                .expect("reads")
                .pop_front()
                .ok_or(TransportError::ConnectionClosed)??;
            if payload.len() > maximum_payload_bytes {
                return Err(TransportError::FrameTooLarge);
            }
            Ok(payload)
        }

        fn write_payload(
            &mut self,
            payload: &[u8],
            maximum_payload_bytes: usize,
            deadline: Instant,
        ) -> Result<(), TransportError> {
            self.deadlines.lock().expect("deadlines").push(deadline);
            self.maximums
                .lock()
                .expect("maximums")
                .push(maximum_payload_bytes);
            if payload.len() > maximum_payload_bytes {
                return Err(TransportError::FrameTooLarge);
            }
            self.writes.lock().expect("writes").push(payload.to_vec());
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
            "health" => include_str!("../../../protocol/v1/golden/wire-health-response.json"),
            _ => panic!("unknown golden"),
        };
        serde_json::from_str(source).expect("shared golden")
    }

    fn bytes(value: &Value) -> Vec<u8> {
        serde_json::to_vec(value).expect("JSON bytes")
    }

    fn endpoint_key() -> EndpointKey {
        EndpointKey::from_bytes(std::array::from_fn(|index| {
            u8::try_from(index).expect("key index")
        }))
    }

    fn client_with(
        transport: FakeTransport,
        key: &EndpointKey,
        maximum_response_frame: u32,
    ) -> ClientHandshake<'_, FakeTransport> {
        ClientHandshake::with_nonce_and_deadline(
            transport,
            key,
            "install-001".to_owned(),
            "0.1.0".to_owned(),
            maximum_response_frame,
            Nonce::from_bytes([0x11; NONCE_LENGTH]),
            Instant::now() + Duration::from_secs(2),
        )
        .expect("client")
    }

    #[test]
    fn consumes_all_four_shared_goldens_and_one_absolute_deadline() {
        let key = endpoint_key();
        let transport = FakeTransport::new([bytes(&golden("challenge")), bytes(&golden("ready"))]);
        let writes = Arc::clone(&transport.writes);
        let deadlines = Arc::clone(&transport.deadlines);
        let maximums = Arc::clone(&transport.maximums);
        let authenticated = client_with(transport, &key, 8_388_608)
            .send_hello()
            .expect("hello")
            .receive_challenge()
            .expect("challenge")
            .send_auth()
            .expect("auth")
            .receive_ready()
            .expect("ready");

        assert_eq!(authenticated.health().install_id(), "install-001");
        assert_eq!(authenticated.health().daemon_generation(), 7);
        assert_eq!(
            authenticated.negotiated_limits(),
            WireLimitsV1::protocol_v1_0()
        );
        let writes: Vec<Value> = writes
            .lock()
            .expect("writes")
            .iter()
            .map(|payload| serde_json::from_slice(payload).expect("wire JSON"))
            .collect();
        assert_eq!(writes, [golden("hello"), golden("auth")]);
        let deadlines = deadlines.lock().expect("deadlines");
        assert_eq!(deadlines.len(), 4);
        assert!(deadlines.iter().all(|deadline| *deadline == deadlines[0]));
        assert_eq!(
            *maximums.lock().expect("maximums"),
            [1_048_576, 8_388_608, 1_048_576, 8_388_608]
        );
        let (transport, _, _) = authenticated.into_parts();
        assert!(transport.reads.lock().expect("reads").is_empty());
    }

    #[test]
    fn rejects_wrong_response_ids_and_kinds() {
        let key = endpoint_key();
        let mut wrong_id = golden("challenge");
        wrong_id["id"] = Value::from("handshake-2");
        let error = client_with(FakeTransport::new([bytes(&wrong_id)]), &key, 8_388_608)
            .send_hello()
            .expect("hello")
            .receive_challenge()
            .err()
            .expect("wrong id");
        assert_eq!(error.code, ErrorCode::ValidationFailed);

        let mut wrong_kind = golden("health");
        wrong_kind["id"] = Value::from(HANDSHAKE_HELLO_ID);
        let error = client_with(FakeTransport::new([bytes(&wrong_kind)]), &key, 8_388_608)
            .send_hello()
            .expect("hello")
            .receive_challenge()
            .err()
            .expect("wrong kind");
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn rejects_challenge_install_version_nonce_and_limit_drift() {
        let key = endpoint_key();
        for (field, value) in [
            ("install_id", Value::from("other-install")),
            ("selected_minor", Value::from(1)),
            ("server_nonce", Value::from("AA".repeat(NONCE_LENGTH))),
        ] {
            let mut challenge = golden("challenge");
            challenge["result"][field] = value;
            assert!(
                client_with(FakeTransport::new([bytes(&challenge)]), &key, 8_388_608)
                    .send_hello()
                    .expect("hello")
                    .receive_challenge()
                    .is_err(),
                "{field}"
            );
        }

        let mut limits = golden("challenge");
        limits["result"]["negotiated_limits"]["response_frame_bytes"] = Value::from(8_192);
        let error = client_with(FakeTransport::new([bytes(&limits)]), &key, 4_096)
            .send_hello()
            .expect("hello")
            .receive_challenge()
            .err()
            .expect("above client offer");
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn rejects_wrong_server_proof_and_health_identity() {
        let key = endpoint_key();
        let mut wrong_proof = golden("ready");
        wrong_proof["result"]["server_proof"] = Value::from("00".repeat(AUTH_TAG_LENGTH));
        let error = client_with(
            FakeTransport::new([bytes(&golden("challenge")), bytes(&wrong_proof)]),
            &key,
            8_388_608,
        )
        .send_hello()
        .expect("hello")
        .receive_challenge()
        .expect("challenge")
        .send_auth()
        .expect("auth")
        .receive_ready()
        .err()
        .expect("proof mismatch");
        assert_eq!(error.code, ErrorCode::IpcAuthenticationFailed);

        let mut wrong_health = golden("ready");
        wrong_health["result"]["health"]["daemon_generation"] = Value::from(8);
        let error = client_with(
            FakeTransport::new([bytes(&golden("challenge")), bytes(&wrong_health)]),
            &key,
            8_388_608,
        )
        .send_hello()
        .expect("hello")
        .receive_challenge()
        .expect("challenge")
        .send_auth()
        .expect("auth")
        .receive_ready()
        .err()
        .expect("health mismatch");
        assert_eq!(error.code, ErrorCode::IpcAuthenticationFailed);
    }

    #[test]
    fn strict_boundary_rejects_duplicate_and_unknown_fields() {
        let key = endpoint_key();
        let duplicate = br#"{"jsonrpc":"2.0","id":"handshake-1","id":"handshake-2","result":{"kind":"handshake_challenge"}}"#.to_vec();
        let error = client_with(FakeTransport::new([duplicate]), &key, 8_388_608)
            .send_hello()
            .expect("hello")
            .receive_challenge()
            .err()
            .expect("duplicate key");
        assert_eq!(error.code, ErrorCode::IpcFrameInvalid);

        let mut unknown = golden("challenge");
        unknown["result"]["unexpected"] = Value::Bool(true);
        let error = client_with(FakeTransport::new([bytes(&unknown)]), &key, 8_388_608)
            .send_hello()
            .expect("hello")
            .receive_challenge()
            .err()
            .expect("unknown field");
        assert_eq!(error.code, ErrorCode::ValidationFailed);
    }

    #[test]
    fn timeout_is_typed_and_expired_deadline_performs_no_io() {
        let key = endpoint_key();
        let transport = FakeTransport::failing(TransportError::Timeout);
        let error = client_with(transport, &key, 8_388_608)
            .send_hello()
            .expect("hello")
            .receive_challenge()
            .err()
            .expect("transport timeout");
        assert_eq!(error.code, ErrorCode::IpcIoTimeout);

        let transport = FakeTransport::new([]);
        let writes = Arc::clone(&transport.writes);
        let expired = ClientHandshake::with_nonce_and_deadline(
            transport,
            &key,
            "install-001".to_owned(),
            "0.1.0".to_owned(),
            8_388_608,
            Nonce::from_bytes([0x11; NONCE_LENGTH]),
            Instant::now(),
        )
        .expect("client")
        .send_hello()
        .err()
        .expect("expired");
        assert_eq!(expired.code, ErrorCode::IpcIoTimeout);
        assert!(writes.lock().expect("writes").is_empty());
    }
}
