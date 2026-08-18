#![allow(clippy::missing_errors_doc)]

use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;

use data_encoding::HEXLOWER;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::{NativeError, NativeErrorCode, NativeOperation};

pub const WIRE_MAJOR_V1: u32 = 1;
pub const WIRE_MINOR_V1: u32 = 0;
pub const PROTOCOL_VERSION_V1: u32 = 1;
pub const NONCE_LENGTH: usize = 32;
pub const AUTH_TAG_LENGTH: usize = 32;
pub const CLIENT_PROOF_DOMAIN: &[u8] = b"codex-agent-mesh\0client-proof-v1\0";
pub const SERVER_PROOF_DOMAIN: &[u8] = b"codex-agent-mesh\0server-proof-v1\0";

const CLIENT_KIND_V1: &str = "mcp-bridge-native";
const MIN_RESPONSE_FRAME: u32 = 4_096;
const MAX_RESPONSE_FRAME: u32 = 8_388_608;
const MAX_VERSION_LENGTH: usize = 128;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

type HmacSha256 = Hmac<Sha256>;

pub struct EndpointKey([u8; AUTH_TAG_LENGTH]);

impl EndpointKey {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; AUTH_TAG_LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Result<Self, NativeError> {
        let mut bytes = [0_u8; AUTH_TAG_LENGTH];
        if getrandom::fill(&mut bytes).is_err() {
            bytes.zeroize();
            return Err(handshake_os_error());
        }
        Ok(Self(bytes))
    }

    pub(crate) const fn secret_bytes(&self) -> &[u8; AUTH_TAG_LENGTH] {
        &self.0
    }
}

impl Drop for EndpointKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for EndpointKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("EndpointKey([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Nonce([u8; NONCE_LENGTH]);

impl Nonce {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; NONCE_LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Result<Self, NativeError> {
        let mut bytes = [0_u8; NONCE_LENGTH];
        getrandom::fill(&mut bytes).map_err(|_| handshake_os_error())?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; NONCE_LENGTH] {
        &self.0
    }

    #[must_use]
    pub fn to_lower_hex(self) -> String {
        HEXLOWER.encode(&self.0)
    }
}

/// The exact v1.0 negotiated-limit field order from the shared protocol schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireLimitsV1 {
    pub request_frame_bytes: u32,
    pub response_frame_bytes: u32,
    pub max_in_flight: u32,
    pub max_events_per_page: u32,
    pub handshake_timeout_ms: u32,
    pub health_timeout_ms: u32,
    pub startup_timeout_ms: u32,
    pub query_timeout_ms: u32,
    pub mutation_timeout_ms: u32,
    pub max_wait_ms: u32,
    pub write_timeout_ms: u32,
    pub stderr_budget_bytes: u32,
    pub stderr_line_bytes: u32,
}

impl WireLimitsV1 {
    #[must_use]
    pub const fn protocol_v1_0() -> Self {
        Self {
            request_frame_bytes: 1_048_576,
            response_frame_bytes: 8_388_608,
            max_in_flight: 16,
            max_events_per_page: 200,
            handshake_timeout_ms: 2_000,
            health_timeout_ms: 2_000,
            startup_timeout_ms: 15_000,
            query_timeout_ms: 5_000,
            mutation_timeout_ms: 10_000,
            max_wait_ms: 30_000,
            write_timeout_ms: 5_000,
            stderr_budget_bytes: 65_536,
            stderr_line_bytes: 4_096,
        }
    }

    fn values(self) -> [u32; 13] {
        [
            self.request_frame_bytes,
            self.response_frame_bytes,
            self.max_in_flight,
            self.max_events_per_page,
            self.handshake_timeout_ms,
            self.health_timeout_ms,
            self.startup_timeout_ms,
            self.query_timeout_ms,
            self.mutation_timeout_ms,
            self.max_wait_ms,
            self.write_timeout_ms,
            self.stderr_budget_bytes,
            self.stderr_line_bytes,
        ]
    }

    fn validate(self, max_response_frame: u32) -> Result<(), NativeError> {
        let mut expected = Self::protocol_v1_0();
        // v1.0 freezes every limit except the response size negotiated down
        // from the client's offer.
        expected.response_frame_bytes = self.response_frame_bytes;
        if self != expected
            || !(MIN_RESPONSE_FRAME..=MAX_RESPONSE_FRAME).contains(&self.response_frame_bytes)
            || self.response_frame_bytes > max_response_frame
        {
            return Err(invalid_handshake());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientHello {
    pub wire_major: u32,
    pub min_minor: u32,
    pub max_minor: u32,
    pub protocol_version: u32,
    pub install_id: String,
    pub client_kind: String,
    pub client_version: String,
    pub client_nonce: Nonce,
    pub max_response_frame: u32,
}

impl ClientHello {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wire_major: u32,
        min_minor: u32,
        max_minor: u32,
        protocol_version: u32,
        install_id: String,
        client_kind: String,
        client_version: String,
        client_nonce: Nonce,
        max_response_frame: u32,
    ) -> Result<Self, NativeError> {
        let hello = Self {
            wire_major,
            min_minor,
            max_minor,
            protocol_version,
            install_id,
            client_kind,
            client_version,
            client_nonce,
            max_response_frame,
        };
        hello.validate()?;
        Ok(hello)
    }

    fn validate(&self) -> Result<(), NativeError> {
        if self.wire_major != WIRE_MAJOR_V1
            || self.min_minor != WIRE_MINOR_V1
            || self.max_minor != WIRE_MINOR_V1
            || self.protocol_version != PROTOCOL_VERSION_V1
            || self.client_kind != CLIENT_KIND_V1
            || !(MIN_RESPONSE_FRAME..=MAX_RESPONSE_FRAME).contains(&self.max_response_frame)
            || !valid_id(&self.install_id)
            || !valid_version(&self.client_version)
        {
            return Err(invalid_handshake());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerChallenge {
    pub selected_major: u32,
    pub selected_minor: u32,
    pub protocol_version: u32,
    pub install_id: String,
    pub daemon_version: String,
    pub daemon_generation: u64,
    pub server_nonce: Nonce,
    pub limits: WireLimitsV1,
}

impl ServerChallenge {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: &ClientHello,
        selected_major: u32,
        selected_minor: u32,
        protocol_version: u32,
        install_id: String,
        daemon_version: String,
        daemon_generation: u64,
        server_nonce: Nonce,
        limits: WireLimitsV1,
    ) -> Result<Self, NativeError> {
        let challenge = Self {
            selected_major,
            selected_minor,
            protocol_version,
            install_id,
            daemon_version,
            daemon_generation,
            server_nonce,
            limits,
        };
        challenge.validate(client)?;
        Ok(challenge)
    }

    fn validate(&self, client: &ClientHello) -> Result<(), NativeError> {
        client.validate()?;
        if self.selected_major != client.wire_major
            || self.selected_minor < client.min_minor
            || self.selected_minor > client.max_minor
            || self.protocol_version != client.protocol_version
            || self.install_id != client.install_id
            || !valid_version(&self.daemon_version)
            || self.daemon_generation > MAX_SAFE_INTEGER
        {
            return Err(authentication_failed());
        }
        self.limits.validate(client.max_response_frame)
    }
}

/// Fixed ordered transcript shared by the hello, challenge, auth, and ready phases.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeTranscript(Vec<u8>);

impl HandshakeTranscript {
    pub fn new(client: &ClientHello, challenge: &ServerChallenge) -> Result<Self, NativeError> {
        challenge.validate(client)?;
        let mut output = Vec::with_capacity(512);
        field_u32(&mut output, client.wire_major)?;
        field_u32(&mut output, client.min_minor)?;
        field_u32(&mut output, client.max_minor)?;
        field_u32(&mut output, challenge.selected_minor)?;
        field_u32(&mut output, client.protocol_version)?;
        field_str(&mut output, &client.install_id)?;
        field_str(&mut output, &client.client_kind)?;
        field_str(&mut output, &client.client_version)?;
        field_str(&mut output, &client.client_nonce.to_lower_hex())?;
        field_u32(&mut output, client.max_response_frame)?;
        field_str(&mut output, &challenge.daemon_version)?;
        field_u64(&mut output, challenge.daemon_generation)?;
        field_str(&mut output, &challenge.server_nonce.to_lower_hex())?;
        for value in challenge.limits.values() {
            field_u32(&mut output, value)?;
        }
        Ok(Self(output))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientAuth {
    pub client_nonce: Nonce,
    pub server_nonce: Nonce,
    pub client_proof: [u8; AUTH_TAG_LENGTH],
}

impl ClientAuth {
    pub fn signed(
        key: &EndpointKey,
        client: &ClientHello,
        challenge: &ServerChallenge,
    ) -> Result<Self, NativeError> {
        challenge.validate(client)?;
        let transcript = HandshakeTranscript::new(client, challenge)?;
        Ok(Self {
            client_nonce: client.client_nonce,
            server_nonce: challenge.server_nonce,
            client_proof: sign(key, CLIENT_PROOF_DOMAIN, transcript.as_bytes())?,
        })
    }

    pub fn verify(
        &self,
        key: &EndpointKey,
        client: &ClientHello,
        challenge: &ServerChallenge,
    ) -> Result<(), NativeError> {
        challenge.validate(client)?;
        if self.client_nonce != client.client_nonce || self.server_nonce != challenge.server_nonce {
            return Err(authentication_failed());
        }
        let transcript = HandshakeTranscript::new(client, challenge)?;
        verify_tag(
            key,
            CLIENT_PROOF_DOMAIN,
            transcript.as_bytes(),
            &self.client_proof,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerReady {
    pub server_proof: [u8; AUTH_TAG_LENGTH],
}

impl ServerReady {
    pub fn signed(
        key: &EndpointKey,
        client: &ClientHello,
        challenge: &ServerChallenge,
        auth: &ClientAuth,
    ) -> Result<Self, NativeError> {
        auth.verify(key, client, challenge)?;
        let transcript = HandshakeTranscript::new(client, challenge)?;
        Ok(Self {
            server_proof: server_tag(key, &transcript, auth)?,
        })
    }

    pub fn verify(
        &self,
        key: &EndpointKey,
        client: &ClientHello,
        challenge: &ServerChallenge,
        auth: &ClientAuth,
    ) -> Result<(), NativeError> {
        auth.verify(key, client, challenge)?;
        let transcript = HandshakeTranscript::new(client, challenge)?;
        let mut input = transcript.as_bytes().to_vec();
        field_str(&mut input, &HEXLOWER.encode(&auth.client_proof))?;
        verify_tag(key, SERVER_PROOF_DOMAIN, &input, &self.server_proof)
    }
}

/// A bounded in-memory nonce cache scoped to one daemon generation.
#[derive(Debug)]
pub struct NonceReplayGuard {
    capacity: usize,
    state: Mutex<ReplayState>,
}

#[derive(Debug)]
struct ReplayState {
    order: VecDeque<Nonce>,
    set: HashSet<Nonce>,
}

impl NonceReplayGuard {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(ReplayState {
                order: VecDeque::with_capacity(capacity),
                set: HashSet::with_capacity(capacity),
            }),
        }
    }

    pub fn check_and_record(&self, nonce: Nonce) -> Result<(), NativeError> {
        if self.capacity == 0 {
            return Err(invalid_handshake());
        }
        let mut state = self.state.lock().map_err(|_| invalid_handshake())?;
        if state.set.contains(&nonce) {
            return Err(authentication_failed());
        }
        if state.order.len() == self.capacity
            && let Some(expired) = state.order.pop_front()
        {
            state.set.remove(&expired);
        }
        state.order.push_back(nonce);
        state.set.insert(nonce);
        Ok(())
    }
}

fn server_tag(
    key: &EndpointKey,
    transcript: &HandshakeTranscript,
    auth: &ClientAuth,
) -> Result<[u8; AUTH_TAG_LENGTH], NativeError> {
    let mut input = transcript.as_bytes().to_vec();
    field_str(&mut input, &HEXLOWER.encode(&auth.client_proof))?;
    sign(key, SERVER_PROOF_DOMAIN, &input)
}

fn field_u32(output: &mut Vec<u8>, value: u32) -> Result<(), NativeError> {
    field_str(output, &value.to_string())
}

fn field_u64(output: &mut Vec<u8>, value: u64) -> Result<(), NativeError> {
    field_str(output, &value.to_string())
}

fn field_str(output: &mut Vec<u8>, value: &str) -> Result<(), NativeError> {
    let bytes = value.as_bytes();
    let length = u32::try_from(bytes.len()).map_err(|_| invalid_handshake())?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

fn sign(
    key: &EndpointKey,
    domain: &[u8],
    transcript: &[u8],
) -> Result<[u8; AUTH_TAG_LENGTH], NativeError> {
    let mut mac = HmacSha256::new_from_slice(&key.0).map_err(|_| invalid_handshake())?;
    mac.update(domain);
    mac.update(transcript);
    Ok(mac.finalize().into_bytes().into())
}

fn verify_tag(
    key: &EndpointKey,
    domain: &[u8],
    transcript: &[u8],
    tag: &[u8; AUTH_TAG_LENGTH],
) -> Result<(), NativeError> {
    let mut mac = HmacSha256::new_from_slice(&key.0).map_err(|_| invalid_handshake())?;
    mac.update(domain);
    mac.update(transcript);
    mac.verify_slice(tag).map_err(|_| authentication_failed())
}

fn valid_id(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(first) if first.is_ascii_alphanumeric())
        && bytes
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        && value.len() <= 128
}

fn valid_version(value: &str) -> bool {
    !value.is_empty() && value.chars().count() <= MAX_VERSION_LENGTH
}

const fn invalid_handshake() -> NativeError {
    NativeError::new(
        NativeErrorCode::InvalidArgument,
        NativeOperation::AuthenticateHandshake,
    )
}

const fn authentication_failed() -> NativeError {
    NativeError::new(
        NativeErrorCode::AuthenticationFailed,
        NativeOperation::AuthenticateHandshake,
    )
}

const fn handshake_os_error() -> NativeError {
    NativeError::new(
        NativeErrorCode::OsFailure,
        NativeOperation::AuthenticateHandshake,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce(hex: &str) -> Nonce {
        let bytes = HEXLOWER.decode(hex.as_bytes()).expect("nonce hex");
        Nonce::from_bytes(bytes.try_into().expect("32-byte nonce"))
    }

    fn vector_messages() -> (EndpointKey, ClientHello, ServerChallenge) {
        let key = EndpointKey::from_bytes(std::array::from_fn(|index| {
            u8::try_from(index).expect("key index")
        }));
        let client = ClientHello::new(
            1,
            0,
            0,
            1,
            "install-001".to_owned(),
            "mcp-bridge-native".to_owned(),
            "0.1.0".to_owned(),
            nonce(&"11".repeat(32)),
            8_388_608,
        )
        .expect("client hello");
        let challenge = ServerChallenge::new(
            &client,
            1,
            0,
            1,
            client.install_id.clone(),
            "0.1.0".to_owned(),
            7,
            nonce(&"22".repeat(32)),
            WireLimitsV1::protocol_v1_0(),
        )
        .expect("challenge");
        (key, client, challenge)
    }

    #[test]
    fn consumes_shared_four_phase_handshake_vector() {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../protocol/v1/handshake-vectors.json"))
                .expect("shared handshake vector");
        let vector = &vectors[0];
        assert_eq!(
            vector["client_domain"].as_str().expect("client domain"),
            String::from_utf8_lossy(CLIENT_PROOF_DOMAIN)
        );
        assert_eq!(
            vector["server_domain"].as_str().expect("server domain"),
            String::from_utf8_lossy(SERVER_PROOF_DOMAIN)
        );
        let (key, client, challenge) = vector_messages();
        let transcript = HandshakeTranscript::new(&client, &challenge).expect("transcript");
        assert_eq!(
            HEXLOWER.encode(transcript.as_bytes()),
            vector["transcript_hex"].as_str().expect("transcript hex")
        );
        let auth = ClientAuth::signed(&key, &client, &challenge).expect("auth");
        assert_eq!(
            HEXLOWER.encode(&auth.client_proof),
            vector["client_proof"].as_str().expect("client proof")
        );
        let ready = ServerReady::signed(&key, &client, &challenge, &auth).expect("ready");
        assert_eq!(
            HEXLOWER.encode(&ready.server_proof),
            vector["server_proof"].as_str().expect("server proof")
        );
        ready
            .verify(&key, &client, &challenge, &auth)
            .expect("verify ready");
    }

    #[test]
    fn challenge_and_both_proofs_bind_every_phase() {
        let (key, client, challenge) = vector_messages();
        let auth = ClientAuth::signed(&key, &client, &challenge).expect("auth");
        let ready = ServerReady::signed(&key, &client, &challenge, &auth).expect("ready");
        let mut changed = challenge.clone();
        changed.daemon_generation += 1;
        assert_eq!(
            auth.verify(&key, &client, &changed)
                .expect_err("bound auth")
                .code(),
            NativeErrorCode::AuthenticationFailed
        );
        assert_eq!(
            ready
                .verify(&key, &client, &changed, &auth)
                .expect_err("bound ready")
                .code(),
            NativeErrorCode::AuthenticationFailed
        );
    }

    #[test]
    fn rejects_non_schema_limits_and_challenge_echo_drift() {
        let (_, client, challenge) = vector_messages();
        let mut limits = WireLimitsV1::protocol_v1_0();
        limits.max_in_flight += 1;
        assert_eq!(
            ServerChallenge::new(
                &client,
                WIRE_MAJOR_V1,
                WIRE_MINOR_V1,
                PROTOCOL_VERSION_V1,
                client.install_id.clone(),
                challenge.daemon_version.clone(),
                challenge.daemon_generation,
                challenge.server_nonce,
                limits,
            )
            .expect_err("non-schema max-in-flight")
            .code(),
            NativeErrorCode::InvalidArgument
        );

        assert_eq!(
            ServerChallenge::new(
                &client,
                WIRE_MAJOR_V1,
                WIRE_MINOR_V1,
                PROTOCOL_VERSION_V1,
                "different-install".to_owned(),
                challenge.daemon_version.clone(),
                challenge.daemon_generation,
                challenge.server_nonce,
                WireLimitsV1::protocol_v1_0(),
            )
            .expect_err("install echo drift")
            .code(),
            NativeErrorCode::AuthenticationFailed
        );

        let mut drifted = challenge;
        drifted.selected_major += 1;
        assert_eq!(
            HandshakeTranscript::new(&client, &drifted)
                .expect_err("selected major drift")
                .code(),
            NativeErrorCode::AuthenticationFailed
        );
    }

    #[test]
    fn rejects_auth_nonce_echo_drift() {
        let (key, client, challenge) = vector_messages();
        let mut auth = ClientAuth::signed(&key, &client, &challenge).expect("auth");
        auth.client_nonce = Nonce::from_bytes([9; NONCE_LENGTH]);
        assert_eq!(
            auth.verify(&key, &client, &challenge)
                .expect_err("client nonce echo drift")
                .code(),
            NativeErrorCode::AuthenticationFailed
        );
    }

    #[test]
    fn nonce_replay_guard_is_bounded_and_rejects_live_replay() {
        let guard = NonceReplayGuard::new(2);
        let first = Nonce::from_bytes([1; NONCE_LENGTH]);
        let second = Nonce::from_bytes([2; NONCE_LENGTH]);
        let third = Nonce::from_bytes([3; NONCE_LENGTH]);
        guard.check_and_record(first).expect("first");
        assert_eq!(
            guard.check_and_record(first).expect_err("replay").code(),
            NativeErrorCode::AuthenticationFailed
        );
        guard.check_and_record(second).expect("second");
        guard.check_and_record(third).expect("third");
        guard.check_and_record(first).expect("expired nonce");
    }
}
