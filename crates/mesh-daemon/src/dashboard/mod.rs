//! Loopback dashboard HTTP boundary: read-only and per-install
//! authenticated.
//!
//! The daemon binds this router only to `127.0.0.1`. A browser session is
//! established through a short-lived one-time bootstrap token exchanged for
//! an `HttpOnly` `SameSite=Strict` cookie. Every response carries CSP and
//! hardening headers. Task routes are read-only: the dashboard never approves,
//! cancels, retries, acknowledges, or deletes task data. The only mutation is
//! the independently gated safe-settings writer. Task data comes from the same
//! persisted projections the MCP tools read.

#![allow(clippy::cast_possible_truncation, clippy::missing_errors_doc)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::adapters::registry::AdapterRegistry;
use crate::reader::{MAX_SAFE_INTEGER, PublicEventPoll, ReaderPool};
use crate::settings::{SettingsDocument, SettingsStore, validate_http_settings};
use crate::storage::StorageError;

/// Cookie name carrying the dashboard session.
pub const SESSION_COOKIE: &str = "mesh_dashboard_session";
/// One-time bootstrap tokens live at most ten minutes.
const BOOTSTRAP_TTL_MS: u64 = 10 * 60 * 1000;
/// Browser sessions live at most one hour.
const SESSION_TTL_MS: u64 = 60 * 60 * 1000;
/// Upper bound for one encoded event rendered by the dashboard.
const MAX_EVENT_BYTES: usize = 256 * 1024;
/// One SSE stream lives at most ten minutes before a bounded close.
const STREAM_LIFETIME: Duration = Duration::from_mins(10);
/// Poll cadence for the persisted-event tail.
const STREAM_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Upper bound for one dashboard read transaction.
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const INDEX_ASSET: &[u8] = include_bytes!("../../../../packages/dashboard/public/index.html");
const SCRIPT_ASSET: &[u8] = include_bytes!("../../../../packages/dashboard/public/dashboard.js");
const STYLE_ASSET: &[u8] = include_bytes!("../../../../packages/dashboard/public/dashboard.css");

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BootstrapQuery {
    token: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TaskListQuery {
    limit: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EventQuery {
    after_seq: Option<i64>,
    limit: Option<usize>,
}

/// Redaction-safe dashboard failure.
#[derive(Debug, thiserror::Error)]
pub enum DashboardError {
    #[error("dashboard secret storage failed")]
    SecretStorage,
    #[error("dashboard secret is unavailable on this platform")]
    SecretUnsupported,
    #[error("reader pool is unavailable")]
    ReaderUnavailable,
}

/// In-memory single-use bootstrap tokens and browser sessions.
pub struct SessionStore {
    inner: Mutex<SessionInner>,
    #[allow(clippy::type_complexity)]
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

#[derive(Default)]
struct SessionInner {
    bootstrap: HashMap<String, u64>,
    sessions: HashMap<String, u64>,
    /// Per-session CSRF tokens for the settings writer surface.
    csrf: HashMap<String, String>,
}

fn system_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

impl Default for SessionStore {
    fn default() -> Self {
        Self {
            inner: Mutex::new(SessionInner::default()),
            clock: Box::new(system_clock_ms),
        }
    }
}

impl SessionStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a store with an injected clock for deterministic tests.
    #[must_use]
    pub fn with_clock(clock: Box<dyn Fn() -> u64 + Send + Sync>) -> Self {
        Self {
            inner: Mutex::new(SessionInner::default()),
            clock,
        }
    }

    /// Mints one short-lived one-time bootstrap token.
    ///
    /// # Panics
    ///
    /// Panics if the session lock is poisoned by a panicked peer.
    pub fn mint_bootstrap(&self) -> String {
        let token = random_token();
        let now = (self.clock)();
        let mut inner = self.inner.lock().expect("session lock");
        inner.bootstrap.retain(|_, expiry| *expiry > now);
        inner
            .bootstrap
            .insert(token.clone(), now + BOOTSTRAP_TTL_MS);
        token
    }

    /// Exchanges a bootstrap token for a session token exactly once.
    ///
    /// # Panics
    ///
    /// Panics if the session lock is poisoned by a panicked peer.
    pub fn exchange_bootstrap(&self, token: &str) -> Option<String> {
        let now = (self.clock)();
        let mut inner = self.inner.lock().expect("session lock");
        let expiry = inner.bootstrap.remove(token)?;
        if expiry <= now {
            return None;
        }
        let session = random_token();
        inner.sessions.retain(|_, expiry| *expiry > now);
        let csrf = random_token();
        inner.csrf.insert(session.clone(), csrf);
        inner.sessions.insert(session.clone(), now + SESSION_TTL_MS);
        Some(session)
    }

    /// CSRF token bound to one live session, for the settings writer.
    ///
    /// # Panics
    ///
    /// Panics if the session lock is poisoned by a panicked peer.
    pub fn csrf_for_session(&self, session: &str) -> Option<String> {
        let now = (self.clock)();
        let inner = self.inner.lock().expect("session lock");
        let live = inner
            .sessions
            .get(session)
            .is_some_and(|expiry| *expiry > now);
        live.then(|| inner.csrf.get(session).cloned())?
    }

    /// Validates one session token and returns it for CSRF binding.
    fn active_session(&self, token: &str) -> Option<String> {
        let now = (self.clock)();
        let inner = self.inner.lock().expect("session lock");
        inner
            .sessions
            .get(token)
            .filter(|expiry| **expiry > now)
            .map(|_| token.to_owned())
    }

    /// Validates one session token.
    ///
    /// # Panics
    ///
    /// Panics if the session lock is poisoned by a panicked peer.
    pub fn validate_session(&self, token: &str) -> bool {
        self.active_session(token).is_some()
    }
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64url(&bytes)
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 63] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(triple >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[triple as usize & 63] as char);
        }
    }
    out
}

/// DPAPI-protected per-install dashboard secret stored under the data root.
pub struct DashboardSecret {
    path: PathBuf,
}

impl DashboardSecret {
    /// Loads the persisted secret, creating and protecting a fresh random
    /// secret when the file does not exist yet. The plaintext never hits
    /// disk; only the DPAPI envelope is stored.
    pub fn load_or_create(root: &Path, install_id: &str) -> Result<Self, DashboardError> {
        let path = root.join("dashboard-secret.bin");
        if path.exists() {
            let envelope = std::fs::read(&path).map_err(|_| DashboardError::SecretStorage)?;
            mesh_win32::ProtectedEndpointKey::from_bytes(envelope)
                .and_then(|protected| {
                    mesh_win32::unprotect_dashboard_secret(&protected, install_id)
                })
                .map_err(|_| DashboardError::SecretStorage)?;
            return Ok(Self { path });
        }
        let key =
            mesh_win32::EndpointKey::generate().map_err(|_| DashboardError::SecretUnsupported)?;
        let protected = mesh_win32::protect_dashboard_secret(&key, install_id)
            .map_err(|_| DashboardError::SecretUnsupported)?;
        std::fs::write(&path, protected.as_bytes()).map_err(|_| DashboardError::SecretStorage)?;
        Ok(Self { path })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Shared dashboard state: reader pool, session store, and the optional
/// settings writer surface. Settings writes stay disabled until the
/// security gate for that surface is explicitly turned on.
#[derive(Clone)]
pub struct DashboardState {
    readers: ReaderPool,
    sessions: Arc<SessionStore>,
    consumer_id: String,
    settings: Option<SettingsStore>,
    settings_writes_enabled: bool,
    registry: Option<AdapterRegistry>,
    stream_lifetime: Duration,
    stream_poll_interval: Duration,
    #[allow(clippy::type_complexity)]
    now_us: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl DashboardState {
    #[must_use]
    pub fn new(
        readers: ReaderPool,
        sessions: Arc<SessionStore>,
        consumer_id: impl Into<String>,
    ) -> Self {
        Self {
            readers,
            sessions,
            consumer_id: consumer_id.into(),
            settings: None,
            settings_writes_enabled: false,
            registry: None,
            stream_lifetime: STREAM_LIFETIME,
            stream_poll_interval: STREAM_POLL_INTERVAL,
            now_us: Arc::new(system_now_us),
        }
    }

    /// Attaches the settings store; `writes_enabled` gates the one
    /// authenticated mutation route.
    #[must_use]
    pub fn with_settings(mut self, settings: SettingsStore, writes_enabled: bool) -> Self {
        self.settings = Some(settings);
        self.settings_writes_enabled = writes_enabled;
        self
    }

    /// Attaches the live adapter registry used by the overview.
    #[must_use]
    pub fn with_registry(mut self, registry: AdapterRegistry) -> Self {
        self.registry = Some(registry);
        self
    }

    #[cfg(test)]
    fn with_stream_timing(mut self, lifetime: Duration, poll_interval: Duration) -> Self {
        self.stream_lifetime = lifetime;
        self.stream_poll_interval = poll_interval;
        self
    }

    #[must_use]
    pub fn sessions(&self) -> &Arc<SessionStore> {
        &self.sessions
    }

    fn now_us(&self) -> i64 {
        (self.now_us)()
    }
}

fn system_now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_micros() as i64)
        .unwrap_or_default()
}

/// Builds the dashboard router with the security guard applied to every route.
/// Only the separately gated settings endpoint may mutate durable state.
pub fn dashboard_router(state: DashboardState) -> Router {
    Router::new()
        .route("/bootstrap", get(bootstrap))
        .route("/", get(index))
        .route("/assets/{*asset_path}", get(asset))
        .route("/api/v1/overview", get(overview))
        .route("/api/v1/tasks", get(task_list))
        .route("/api/v1/tasks/{task_id}", get(task_detail))
        .route(
            "/api/v1/tasks/{task_id}/events/stream",
            get(task_event_stream),
        )
        .route("/api/v1/settings", get(settings_get).put(settings_put))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_guard,
        ))
        .with_state(state)
}

/// Rejects non-loopback hosts, foreign origins, and any request body, and
/// stamps hardening headers on every response.
async fn security_guard(
    State(_state): State<DashboardState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
    else {
        return harden_response(error_response(StatusCode::FORBIDDEN, "host_not_allowed"));
    };
    if !is_loopback_authority(host) {
        return harden_response(error_response(StatusCode::FORBIDDEN, "host_not_allowed"));
    }
    if let Some(origin) = headers.get(header::ORIGIN) {
        let Ok(origin) = origin.to_str() else {
            return harden_response(error_response(StatusCode::FORBIDDEN, "origin_not_allowed"));
        };
        if !origin_matches_host(origin, host) {
            return harden_response(error_response(StatusCode::FORBIDDEN, "origin_not_allowed"));
        }
    }
    let is_settings_write =
        request.method() == axum::http::Method::PUT && request.uri().path() == "/api/v1/settings";
    if headers.contains_key(header::TRANSFER_ENCODING) {
        return harden_response(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_body_framing",
        ));
    }
    let length = match strict_content_length(headers) {
        Ok(length) => length.unwrap_or_default(),
        Err(()) => {
            return harden_response(error_response(
                StatusCode::BAD_REQUEST,
                "invalid_body_framing",
            ));
        }
    };
    if is_settings_write {
        let bound =
            u64::try_from(crate::settings::MAX_SETTINGS_BYTES).expect("settings bound fits u64");
        if length > bound {
            return harden_response(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "settings_body_too_large",
            ));
        }
    } else if length > 0 {
        return harden_response(error_response(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_not_accepted",
        ));
    }
    harden_response(next.run(request).await)
}

fn strict_content_length(headers: &HeaderMap) -> Result<Option<u64>, ()> {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    value.parse().map(Some).map_err(|_| ())
}

fn harden_response(mut response: Response) -> Response {
    let headers_mut = response.headers_mut();
    headers_mut.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    headers_mut.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers_mut.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers_mut.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn is_loopback_authority(authority: &str) -> bool {
    loopback_host(authority).is_some()
}

/// Exact-authority Origin check: the browser Origin must be `http://` plus
/// the same loopback host and port as the request Host. A second local
/// site on another port is rejected.
fn origin_matches_host(origin: &str, host: &str) -> bool {
    let Some(rest) = origin.strip_prefix("http://") else {
        return false;
    };
    if rest.contains('\\') || rest.contains('\0') {
        return false;
    }
    let origin_authority = rest.split('/').next().unwrap_or_default();
    if loopback_host(origin_authority).is_none() || loopback_host(host).is_none() {
        return false;
    }
    normalize_authority(origin_authority) == normalize_authority(host)
}

fn loopback_host(authority: &str) -> Option<&str> {
    let host = split_host_port(authority).map_or(authority, |(host, _)| host);
    matches!(
        host.to_ascii_lowercase().as_str(),
        "127.0.0.1" | "localhost" | "[::1]"
    )
    .then_some(host)
}

fn normalize_authority(authority: &str) -> String {
    match split_host_port(authority) {
        Some((host, port)) => format!("{}:{port}", host.to_ascii_lowercase()),
        None => format!("{}:80", authority.to_ascii_lowercase()),
    }
}

fn split_host_port(authority: &str) -> Option<(&str, &str)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?;
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let host_with_brackets = authority.get(..host.len().saturating_add(2))?;
        return Some((host_with_brackets, port));
    }
    let (host, port) = authority.rsplit_once(':')?;
    if host.is_empty() || host.contains(':') || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some((host, port))
}

fn session_token(headers: &HeaderMap) -> Option<String> {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())?;
    cookie.split(';').find_map(|part| {
        let part = part.trim();
        let value = part.strip_prefix(SESSION_COOKIE)?.strip_prefix('=')?;
        if value.is_empty() || !value.bytes().all(is_token_byte) {
            return None;
        }
        Some(value.to_owned())
    })
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
}

fn error_response(status: StatusCode, code: &str) -> Response {
    let body = json!({ "error": code }).to_string();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .expect("static error response")
}

/// Exchanges a one-time bootstrap token for a session cookie.
async fn bootstrap(
    State(state): State<DashboardState>,
    query: Result<Query<BootstrapQuery>, QueryRejection>,
) -> Response {
    let Ok(Query(BootstrapQuery { token: Some(token) })) = query else {
        return error_response(StatusCode::BAD_REQUEST, "bootstrap_token_required");
    };
    if token.is_empty() || !token.bytes().all(is_token_byte) {
        return error_response(StatusCode::BAD_REQUEST, "bootstrap_token_required");
    }
    let Some(session) = state.sessions().exchange_bootstrap(&token) else {
        return error_response(StatusCode::UNAUTHORIZED, "invalid_bootstrap_token");
    };
    let cookie = format!(
        "{SESSION_COOKIE}={session}; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age={}",
        SESSION_TTL_MS / 1000
    );
    Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, "/")
        .header(header::SET_COOKIE, cookie)
        .body(axum::body::Body::empty())
        .expect("static bootstrap response")
}

fn require_session(state: &DashboardState, headers: &HeaderMap) -> Option<()> {
    require_session_token(state, headers).map(|_| ())
}

fn require_session_token(state: &DashboardState, headers: &HeaderMap) -> Option<String> {
    let token = session_token(headers)?;
    state.sessions().active_session(&token)
}

async fn index(State(state): State<DashboardState>, headers: HeaderMap) -> Response {
    if require_session(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication_required");
    }
    asset_response(INDEX_ASSET, "text/html; charset=utf-8")
}

/// Serves the small compiled dashboard bundle from an immutable allowlist.
/// No request-derived filesystem path is ever opened, so traversal and
/// reparse-point attacks cannot cross the daemon's data root.
async fn asset(
    State(state): State<DashboardState>,
    AxumPath(asset_path): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if require_session(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication_required");
    }
    let Some((bytes, content_type)) = static_asset(&asset_path) else {
        return error_response(StatusCode::NOT_FOUND, "asset_not_found");
    };
    asset_response(bytes, content_type)
}

fn static_asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains("..")
        || path.contains('\\')
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'-' | b'_'))
    {
        return None;
    }
    match path {
        "dashboard.js" => Some((SCRIPT_ASSET, "text/javascript; charset=utf-8")),
        "dashboard.css" => Some((STYLE_ASSET, "text/css; charset=utf-8")),
        "index.html" => Some((INDEX_ASSET, "text/html; charset=utf-8")),
        _ => None,
    }
}

fn asset_response(bytes: &'static [u8], content_type: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, bytes.len())
        .body(axum::body::Body::from(bytes))
        .expect("static asset response")
}

/// Read-only overview: persisted scheduler occupancy and current config.
async fn overview(State(state): State<DashboardState>, headers: HeaderMap) -> Response {
    if require_session(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication_required");
    }
    let readers = state.readers.clone();
    let registry = state.registry.clone();
    let projection = tokio::task::spawn_blocking(move || {
        let occupancy = readers.occupancy(READ_TIMEOUT)?;
        let config = readers.empty_config(READ_TIMEOUT)?;
        let agents = registry.map(|registry| registry.list_protocol_values());
        Ok::<_, StorageError>((occupancy, config, agents))
    })
    .await;
    match projection {
        Ok(Ok((occupancy, config, agents))) => {
            let per_adapter: Value = occupancy
                .per_adapter
                .iter()
                .map(|(adapter, count)| (adapter.clone(), Value::from(*count)))
                .collect::<serde_json::Map<String, Value>>()
                .into();
            let mut body = json!({
                "kind": "dashboard_overview",
                "occupancy": { "global": occupancy.global, "per_adapter": per_adapter },
                "config": {
                    "digest": config.config_digest,
                    "value": config.value
                }
            });
            if let Some(agents) = agents {
                body["agents"] = Value::Array(agents);
            }
            Json(body).into_response()
        }
        Ok(Err(_)) | Err(_) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable")
        }
    }
}

/// Read-only task detail with a bounded replayable event page.
async fn task_detail(
    State(state): State<DashboardState>,
    AxumPath(task_id): AxumPath<String>,
    query: Result<Query<EventQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Response {
    if require_session(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication_required");
    }
    if !task_id.bytes().all(is_token_byte) || task_id.len() > 128 {
        return error_response(StatusCode::BAD_REQUEST, "invalid_task_id");
    }
    let Some((after_seq, limit)) = parse_event_query(query) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_event_query");
    };
    let readers = state.readers.clone();
    let consumer_id = state.consumer_id.clone();
    let task_id = task_id.clone();
    let projection = tokio::task::spawn_blocking(move || {
        readers.public_task_detail(
            &task_id,
            &consumer_id,
            after_seq,
            limit,
            MAX_EVENT_BYTES,
            READ_TIMEOUT,
        )
    })
    .await;
    match projection {
        Ok(Ok((snapshot, page))) => {
            let events: Vec<Value> = page
                .events
                .iter()
                .map(|event| event.value.clone())
                .collect();
            Json(json!({
                "kind": "dashboard_task_detail",
                "task": snapshot.task.value,
                "attempt": snapshot.attempt.as_ref().map(|attempt| attempt.value.clone()),
                "interaction": snapshot
                    .interaction
                    .as_ref()
                    .map(|interaction| interaction.value.clone()),
                "events": events,
                "next_seq": page.next_seq,
                "cursor": {
                    "oldest_available_seq": page.cursor.oldest_available_seq,
                    "last_committed_seq": page.cursor.last_committed_seq
                },
                "terminal_result": snapshot
                    .result
                    .as_ref()
                    .map(dashboard_terminal_result)
            }))
            .into_response()
        }
        Ok(Err(StorageError::CursorExpired { .. })) => {
            error_response(StatusCode::GONE, "cursor_expired")
        }
        Ok(Err(
            StorageError::StaleGeneration | StorageError::Sql(rusqlite::Error::QueryReturnedNoRows),
        )) => error_response(StatusCode::NOT_FOUND, "task_not_found"),
        Ok(Err(StorageError::Quarantined(_))) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "storage_quarantined")
        }
        Ok(Err(_)) | Err(_) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable")
        }
    }
}

fn dashboard_terminal_result(result: &crate::reader::ResultRead) -> Value {
    json!({
        "result_id": result.delivery.result_id,
        "state": result.delivery.terminal_state,
        "result_version": result.delivery.result_version,
        "terminal_event_seq": result.terminal_event_seq,
        "ack_status": result.value.get("ack_status").cloned().unwrap_or(Value::Null),
        "review": result.review.as_ref().map(|review| json!({
            "verdict": review.verdict,
            "reviewed_at_ms": review.reviewed_at_ms,
            "diagnosis": review.diagnosis.as_ref().map(|diagnosis| {
                crate::adapters::sanitize_raw(&Value::String(diagnosis.clone())).0
            }),
        })),
    })
}

fn parse_event_query(query: Result<Query<EventQuery>, QueryRejection>) -> Option<(i64, usize)> {
    let Query(EventQuery { after_seq, limit }) = query.ok()?;
    let after_seq = after_seq.unwrap_or(0);
    let limit = limit.unwrap_or(50);
    if !(0..=MAX_SAFE_INTEGER).contains(&after_seq) || !(1..=200).contains(&limit) {
        return None;
    }
    Some((after_seq, limit))
}

/// Binds the dashboard to an ephemeral loopback port and serves it on a
/// spawned task. Dropping the returned handle aborts serving.
pub async fn bind_and_serve_loopback(
    state: DashboardState,
) -> Result<
    (
        std::net::SocketAddr,
        tokio::task::JoinHandle<std::io::Result<()>>,
    ),
    std::io::Error,
> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let app = dashboard_router(state);
    let handle = tokio::spawn(axum::serve(listener, app).into_future());
    Ok((address, handle))
}

/// Read-only bounded task list (newest first).
async fn task_list(
    State(state): State<DashboardState>,
    query: Result<Query<TaskListQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Response {
    if require_session(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication_required");
    }
    let Ok(Query(TaskListQuery { limit })) = query else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_limit");
    };
    let limit = limit.unwrap_or(50);
    if !(1..=200).contains(&limit) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_limit");
    }
    let readers = state.readers.clone();
    let projection =
        tokio::task::spawn_blocking(move || readers.task_summaries(limit, READ_TIMEOUT)).await;
    match projection {
        Ok(Ok(tasks)) => Json(json!({
            "kind": "dashboard_tasks",
            "tasks": tasks
                .iter()
                .map(|task| json!({
                    "task_id": task.task_id,
                    "state": task.state,
                    "generation": task.generation,
                    "last_event_seq": task.last_event_seq,
                    "created_at_ms": task.created_at_ms,
                    "updated_at_ms": task.updated_at_ms,
                }))
                .collect::<Vec<Value>>(),
        }))
        .into_response(),
        Ok(Err(_)) | Err(_) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable")
        }
    }
}

/// Replayable Server-Sent Events tail for one task. Events come from the
/// persisted projection only; the stream is a latency optimization over
/// the same durable events, and closes with `mesh_complete` after the
/// terminal result, or with `mesh_timeout` at the bounded lifetime.
async fn task_event_stream(
    State(state): State<DashboardState>,
    AxumPath(task_id): AxumPath<String>,
    query: Result<Query<EventQuery>, QueryRejection>,
    headers: HeaderMap,
) -> Response {
    if require_session(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication_required");
    }
    let (after_seq, limit) = match event_stream_cursor(&task_id, &query, &headers) {
        Ok(cursor) => cursor,
        Err(code) => return error_response(StatusCode::BAD_REQUEST, code),
    };

    // Probe before returning 200 so initial cursor/storage failures remain HTTP
    // errors rather than apparently successful streams with error events.
    let initial = match initial_event_poll(state.readers.clone(), &task_id, after_seq, limit).await
    {
        Ok(poll) => poll,
        Err(response) => return response,
    };

    let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(run_event_stream(
        event_tx,
        state.readers.clone(),
        task_id,
        limit,
        initial,
        state.stream_lifetime,
        state.stream_poll_interval,
    ));
    let body = axum::body::Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(event_rx));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .body(body)
        .expect("static stream response")
}

fn event_stream_cursor(
    task_id: &str,
    query: &Result<Query<EventQuery>, QueryRejection>,
    headers: &HeaderMap,
) -> Result<(i64, usize), &'static str> {
    if !task_id.bytes().all(is_token_byte) || task_id.len() > 128 {
        return Err("invalid_task_id");
    }
    let Ok(Query(EventQuery { after_seq, limit })) = query.as_ref() else {
        return Err("invalid_event_query");
    };
    let (after_seq, limit) = (*after_seq, *limit);
    let header_after = parse_last_event_id(headers);
    let Ok(header_after) = header_after else {
        return Err("invalid_event_query");
    };
    if after_seq.is_some() && header_after.is_some() && after_seq != header_after {
        return Err("cursor_mismatch");
    }
    let after_seq = after_seq.or(header_after).unwrap_or(0);
    let limit = limit.unwrap_or(200);
    if !(0..=MAX_SAFE_INTEGER).contains(&after_seq) || !(1..=200).contains(&limit) {
        return Err("invalid_event_query");
    }
    Ok((after_seq, limit))
}

async fn initial_event_poll(
    readers: ReaderPool,
    task_id: &str,
    after_seq: i64,
    limit: usize,
) -> Result<PublicEventPoll, Response> {
    let task = task_id.to_owned();
    let initial = tokio::task::spawn_blocking(move || {
        readers.public_event_poll(&task, after_seq, limit, MAX_EVENT_BYTES, READ_TIMEOUT)
    })
    .await;
    match initial {
        Ok(Ok(poll)) => Ok(poll),
        Ok(Err(error)) => Err(event_stream_error(&error)),
        Err(_) => Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage_unavailable",
        )),
    }
}

async fn run_event_stream(
    event_tx: SseSender,
    readers: ReaderPool,
    task: String,
    limit: usize,
    mut poll: PublicEventPoll,
    stream_lifetime: Duration,
    stream_poll_interval: Duration,
) {
    let deadline = tokio::time::Instant::now() + stream_lifetime;
    loop {
        if !emit_sse_poll(&event_tx, &poll).await {
            return;
        }
        let cursor = poll.page.next_seq;
        let caught_up = cursor >= poll.page.cursor.last_committed_seq;
        if poll.terminal && caught_up {
            send_sse_control(&event_tx, b"event: mesh_complete\ndata: {}\n\n").await;
            return;
        }
        let wake = (tokio::time::Instant::now() + stream_poll_interval).min(deadline);
        tokio::time::sleep_until(wake).await;
        if tokio::time::Instant::now() >= deadline {
            send_sse_control(&event_tx, b"event: mesh_timeout\ndata: {}\n\n").await;
            return;
        }
        let query_readers = readers.clone();
        let query_task = task.clone();
        let next = tokio::task::spawn_blocking(move || {
            query_readers.public_event_poll(
                &query_task,
                cursor,
                limit,
                MAX_EVENT_BYTES,
                READ_TIMEOUT,
            )
        })
        .await;
        let Ok(Ok(next)) = next else {
            send_sse_control(&event_tx, b"event: mesh_error\ndata: {}\n\n").await;
            return;
        };
        poll = next;
    }
}

async fn send_sse_control(sender: &SseSender, frame: &'static [u8]) {
    let _ = sender.send(Ok(axum::body::Bytes::from_static(frame))).await;
}

fn parse_last_event_id(headers: &HeaderMap) -> Result<Option<i64>, ()> {
    let mut values = headers.get_all("last-event-id").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    value
        .to_str()
        .map_err(|_| ())?
        .parse::<i64>()
        .map(Some)
        .map_err(|_| ())
}

type SseSender = tokio::sync::mpsc::Sender<Result<axum::body::Bytes, std::io::Error>>;

async fn emit_sse_poll(sender: &SseSender, poll: &PublicEventPoll) -> bool {
    for event in &poll.page.events {
        let Ok(data) = serde_json::to_string(&event.value) else {
            let _ = sender
                .send(Ok(axum::body::Bytes::from_static(
                    b"event: mesh_error\ndata: {}\n\n",
                )))
                .await;
            return false;
        };
        let frame = format!("id: {}\nevent: mesh_event\ndata: {data}\n\n", event.seq);
        if sender
            .send(Ok(axum::body::Bytes::from(frame)))
            .await
            .is_err()
        {
            return false;
        }
    }
    true
}

fn event_stream_error(error: &StorageError) -> Response {
    match error {
        StorageError::CursorExpired { .. } => error_response(StatusCode::GONE, "cursor_expired"),
        StorageError::InvalidRequest => {
            error_response(StatusCode::BAD_REQUEST, "invalid_event_query")
        }
        StorageError::StaleGeneration | StorageError::Sql(rusqlite::Error::QueryReturnedNoRows) => {
            error_response(StatusCode::NOT_FOUND, "task_not_found")
        }
        StorageError::Quarantined(_) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "storage_quarantined")
        }
        _ => error_response(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable"),
    }
}

/// Returns the current settings plus the session CSRF token for the
/// (gated) settings writer.
async fn settings_get(State(state): State<DashboardState>, headers: HeaderMap) -> Response {
    let Some(session) = require_session_token(&state, &headers) else {
        return error_response(StatusCode::UNAUTHORIZED, "authentication_required");
    };
    let Some(store) = state.settings.as_ref() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "settings_unavailable");
    };
    let document = match store.load() {
        Ok(document) => document,
        Err(_) => SettingsDocument::from_record(crate::settings::default_settings().to_record())
            .unwrap_or_else(|_| crate::settings::default_settings()),
    };
    let csrf = state
        .sessions()
        .csrf_for_session(&session)
        .unwrap_or_default();
    Json(json!({
        "kind": "dashboard_settings",
        "config_version": document.config_version,
        "settings": Value::Object(document.settings),
        "csrf_token": csrf,
        "writes_enabled": state.settings_writes_enabled,
    }))
    .into_response()
}

/// The single authenticated mutation route: schema-validated settings
/// write behind session auth, a bound CSRF token, and the settings gate.
async fn settings_put(
    State(state): State<DashboardState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(session) = require_session_token(&state, &headers) else {
        return error_response(StatusCode::UNAUTHORIZED, "authentication_required");
    };
    if !state.settings_writes_enabled {
        return error_response(StatusCode::FORBIDDEN, "settings_writes_disabled");
    }
    let Some(store) = state.settings.as_ref() else {
        return error_response(StatusCode::SERVICE_UNAVAILABLE, "settings_unavailable");
    };
    let expected = state.sessions().csrf_for_session(&session);
    let provided = headers
        .get("x-csrf-token")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    match (expected, provided) {
        (Some(expected), Some(provided)) if constant_time_eq(&expected, &provided) => {}
        _ => return error_response(StatusCode::FORBIDDEN, "csrf_required"),
    }
    if body.len() > crate::settings::MAX_SETTINGS_BYTES {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, "settings_body_too_large");
    }
    let document = match validate_http_settings(&body) {
        Ok(document) => document,
        Err(error) => {
            let code = if matches!(error, crate::settings::SettingsError::TooLarge) {
                "settings_body_too_large"
            } else {
                "settings_invalid"
            };
            return error_response(StatusCode::BAD_REQUEST, code);
        }
    };
    let store = store.clone();
    let now_us = state.now_us();
    match tokio::task::spawn_blocking(move || store.update(document, now_us)).await {
        Ok(Ok(classification)) => Json(json!({
            "kind": "dashboard_settings_write",
            "hot_reload": classification.hot_reload,
            "restart_required": classification.restart_required,
        }))
        .into_response(),
        Ok(Err(_)) | Err(_) => {
            error_response(StatusCode::SERVICE_UNAVAILABLE, "settings_unavailable")
        }
    }
}

/// Byte-wise constant-time comparison for token equality.
fn constant_time_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.bytes()
        .zip(right.bytes())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// Parsed HTTP/1.1 reply used by the boundary tests.
#[cfg(test)]
pub(crate) struct HttpReply {
    pub status: u16,
    headers: Vec<(String, String)>,
    pub body: String,
}

#[cfg(test)]
impl HttpReply {
    pub(crate) fn parse(bytes: &[u8]) -> Self {
        let text = String::from_utf8_lossy(bytes).into_owned();
        let mut parts = text.splitn(2, "\r\n\r\n");
        let head = parts.next().unwrap_or_default();
        let body = parts.next().unwrap_or_default().to_owned();
        let mut lines = head.split("\r\n");
        let status = lines
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or_default();
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key.trim().to_ascii_lowercase(), value.trim().to_owned()))
            .collect();
        Self {
            status,
            headers,
            body,
        }
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

#[cfg(test)]
mod dashboard_tests;
