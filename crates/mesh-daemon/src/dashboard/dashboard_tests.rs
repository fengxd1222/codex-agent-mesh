//! Dashboard boundary tests: authentication, header guards, read-only
//! projections, and the DPAPI secret envelope.

use super::{
    BOOTSTRAP_TTL_MS, DashboardSecret, DashboardState, HttpReply, SessionStore,
    bind_and_serve_loopback,
};
use crate::reader::ReaderPool;
use crate::scheduler::SchedulerLimits;
use crate::storage::{AttemptSpec, DispatchOutcome, ResultDelivery};
use crate::writer::WriterHandle;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TEST_CONSUMER: &str = "c";

/// Deterministic clock the tests advance explicitly.
struct TestClock {
    now_ms: Mutex<u64>,
}

impl TestClock {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            now_ms: Mutex::new(1_000),
        })
    }

    fn advance(&self, millis: u64) {
        *self.now_ms.lock().expect("clock") += millis;
    }
}

fn clock_fn(clock: &Arc<TestClock>) -> Box<dyn Fn() -> u64 + Send + Sync> {
    let clock = Arc::clone(clock);
    Box::new(move || *clock.now_ms.lock().expect("clock"))
}

async fn start_dashboard(
    root: &Path,
) -> (
    SocketAddr,
    DashboardState,
    Arc<TestClock>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let writer = WriterHandle::start_portable(root.to_path_buf(), "install", 1).expect("writer");
    writer.ensure_empty_config_v1(1).expect("config v1");
    writer.shutdown().expect("shutdown bootstrap writer");
    let readers = ReaderPool::open(root).expect("readers");
    let clock = TestClock::new();
    let sessions = Arc::new(SessionStore::with_clock(clock_fn(&clock)));
    let state = DashboardState::new(readers, Arc::clone(&sessions), TEST_CONSUMER);
    let (address, handle) = bind_and_serve_loopback(state.clone())
        .await
        .expect("bind loopback");
    (address, state, clock, handle)
}

/// Each seeded task gets its own adapter instance (sha256 of the task id)
/// so the per-adapter occupancy limit never blocks a second seed.
fn adapter_digest_for(task_id: &str) -> String {
    use sha2::{Digest as _, Sha256};
    format!("{:x}", Sha256::digest(task_id.as_bytes()))
}

fn seed_task(root: &Path, task_id: &str) -> i64 {
    let writer = WriterHandle::start_portable(root.to_path_buf(), "install", 1).expect("writer");
    let aid = crate::scheduler::AdapterInstanceId::new(
        "fake",
        "local",
        "default",
        &adapter_digest_for(task_id),
    )
    .expect("aid")
    .encode();
    writer
        .submit_for_scheduling(
            "c",
            "submit",
            format!("k-{task_id}"),
            format!("body-{task_id}").into_bytes(),
            task_id,
            None,
            5,
            Some(&aid),
            1,
        )
        .expect("submit");
    let spec = AttemptSpec {
        adapter_instance_id: aid,
        config_digest: adapter_digest_for(task_id),
        adapter_version: "0.1.0".to_owned(),
        ..AttemptSpec::default()
    };
    let generation = match writer
        .claim_dispatch_slot(
            format!("claim-{task_id}"),
            task_id,
            0,
            spec,
            SchedulerLimits::DEFAULT,
            2,
        )
        .expect("claim")
    {
        DispatchOutcome::Dispatched(attempt) => attempt.generation,
        DispatchOutcome::Blocked(blocked) => panic!("blocked: {blocked:?}"),
    };
    writer.shutdown().expect("shutdown writer");
    generation
}

fn finalize_seeded_task(root: &Path, task_id: &str, generation: i64) -> ResultDelivery {
    let writer = WriterHandle::start_portable(root.to_path_buf(), "install", 1).expect("writer");
    writer
        .transition(
            format!("run-{task_id}"),
            task_id,
            generation,
            vec!["PREPARING".into(), "QUEUED".into()],
            "RUNNING",
            2,
        )
        .or_else(|_| {
            writer.clone().transition(
                format!("run-{task_id}"),
                task_id,
                generation,
                vec!["RUNNING".into()],
                "RUNNING",
                2,
            )
        })
        .expect("reach RUNNING");
    writer
        .transition(
            format!("finalize-{task_id}"),
            task_id,
            generation,
            vec!["RUNNING".into()],
            "FINALIZING",
            3,
        )
        .expect("reach FINALIZING");
    let delivery = writer
        .finalize(
            TEST_CONSUMER,
            format!("key-final-{task_id}"),
            format!("body-final-{task_id}").into_bytes(),
            task_id,
            generation,
            "SUCCEEDED",
            "aa".repeat(32),
            4,
        )
        .expect("finalize");
    writer.shutdown().expect("shutdown finalizer");
    delivery
}

async fn request(
    address: SocketAddr,
    method: &str,
    target: &str,
    host: &str,
    extra: &[(&str, &str)],
) -> HttpReply {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let mut raw = format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (name, value) in extra {
        use std::fmt::Write as _;
        let _ = write!(raw, "{name}: {value}\r\n");
    }
    raw.push_str("\r\n");
    stream.write_all(raw.as_bytes()).await.expect("write");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.expect("read");
    HttpReply::parse(&bytes)
}

async fn raw_request(address: SocketAddr, raw: &[u8]) -> HttpReply {
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    stream.write_all(raw).await.expect("write raw request");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.expect("read reply");
    HttpReply::parse(&bytes)
}

async fn session_cookie(address: SocketAddr, sessions: &Arc<SessionStore>) -> String {
    let token = sessions.mint_bootstrap();
    let exchange = request(
        address,
        "GET",
        &format!("/bootstrap?token={token}"),
        "127.0.0.1",
        &[],
    )
    .await;
    assert_eq!(exchange.status, 303, "bootstrap must redirect");
    exchange
        .header("set-cookie")
        .expect("session cookie")
        .split(';')
        .next()
        .expect("cookie pair")
        .to_owned()
}

async fn request_with_body(
    address: SocketAddr,
    method: &str,
    target: &str,
    host: &str,
    extra: &[(&str, &str)],
    body: &[u8],
) -> HttpReply {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let mut raw = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in extra {
        use std::fmt::Write as _;
        let _ = write!(raw, "{name}: {value}\r\n");
    }
    raw.push_str("\r\n");
    stream.write_all(raw.as_bytes()).await.expect("write head");
    stream.write_all(body).await.expect("write body");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.expect("read");
    HttpReply::parse(&bytes)
}

async fn authenticated(
    address: SocketAddr,
    sessions: &Arc<SessionStore>,
    method: &str,
    target: &str,
) -> HttpReply {
    let cookie = session_cookie(address, sessions).await;
    request(address, method, target, "127.0.0.1", &[("Cookie", &cookie)]).await
}

#[tokio::test]
async fn bootstrap_exchange_sets_strict_cookie_and_is_single_use() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, state, _clock, handle) = start_dashboard(root.path()).await;
    let sessions = Arc::clone(state.sessions());
    let token = sessions.mint_bootstrap();
    let first = request(
        address,
        "GET",
        &format!("/bootstrap?token={token}"),
        "127.0.0.1",
        &[],
    )
    .await;
    assert_eq!(first.status, 303);
    assert_eq!(first.header("location"), Some("/"));
    let cookie = first.header("set-cookie").expect("cookie set");
    assert!(cookie.contains("HttpOnly"));
    assert!(cookie.contains("SameSite=Strict"));
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains(super::SESSION_COOKIE));
    let second = request(
        address,
        "GET",
        &format!("/bootstrap?token={token}"),
        "127.0.0.1",
        &[],
    )
    .await;
    assert_eq!(second.status, 401, "bootstrap token is single-use");
    handle.abort();
}

#[tokio::test]
async fn bootstrap_tokens_expire_by_clock() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, _state, clock, handle) = start_dashboard(root.path()).await;
    let sessions = Arc::new(SessionStore::with_clock(clock_fn(&clock)));
    let token = sessions.mint_bootstrap();
    clock.advance(BOOTSTRAP_TTL_MS + 1);
    let expired = request(
        address,
        "GET",
        &format!("/bootstrap?token={token}"),
        "127.0.0.1",
        &[],
    )
    .await;
    assert_eq!(expired.status, 401);
    handle.abort();
}

#[tokio::test]
async fn unauthenticated_and_forged_sessions_are_rejected() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, state, _clock, handle) = start_dashboard(root.path()).await;
    let anonymous = request(address, "GET", "/api/v1/overview", "127.0.0.1", &[]).await;
    assert_eq!(anonymous.status, 401);
    let forged = request(
        address,
        "GET",
        "/api/v1/overview",
        "127.0.0.1",
        &[("Cookie", "mesh_dashboard_session=not-a-real-token")],
    )
    .await;
    assert_eq!(forged.status, 401);
    let authed = authenticated(address, state.sessions(), "GET", "/api/v1/overview").await;
    assert_eq!(authed.status, 200);
    handle.abort();
}

#[tokio::test]
async fn host_and_origin_guards_reject_foreign_requests() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, _state, _clock, handle) = start_dashboard(root.path()).await;
    let foreign_host = request(address, "GET", "/", "evil.example", &[]).await;
    assert_eq!(foreign_host.status, 403);
    assert_eq!(foreign_host.header("cache-control"), Some("no-store"));
    assert!(foreign_host.header("content-security-policy").is_some());
    let foreign_origin = request(
        address,
        "GET",
        "/",
        "127.0.0.1",
        &[("Origin", "https://evil.example")],
    )
    .await;
    assert_eq!(foreign_origin.status, 403);
    assert_eq!(foreign_origin.header("cache-control"), Some("no-store"));
    assert!(foreign_origin.header("content-security-policy").is_some());
    let same_origin = request(
        address,
        "GET",
        "/",
        "localhost",
        &[("Origin", "http://localhost")],
    )
    .await;
    assert_eq!(
        same_origin.status, 401,
        "exact origin ok; auth still required"
    );
    let other_port = request(
        address,
        "GET",
        "/",
        "localhost",
        &[("Origin", "http://localhost:9999")],
    )
    .await;
    assert_eq!(
        other_port.status, 403,
        "a second loopback port is a foreign origin"
    );
    let host_mismatch = request(
        address,
        "GET",
        "/",
        "127.0.0.1",
        &[("Origin", "http://localhost")],
    )
    .await;
    assert_eq!(host_mismatch.status, 403, "127.0.0.1 is not localhost");
    handle.abort();
}

#[tokio::test]
async fn security_headers_and_body_rejection_apply_to_every_response() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, _state, _clock, handle) = start_dashboard(root.path()).await;
    let reply = request(address, "GET", "/api/v1/overview", "127.0.0.1", &[]).await;
    assert_eq!(reply.status, 401);
    assert_eq!(
        reply.header("content-security-policy"),
        Some(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
    );
    assert_eq!(reply.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(reply.header("referrer-policy"), Some("no-referrer"));
    assert_eq!(reply.header("cache-control"), Some("no-store"));
    let with_body = request(
        address,
        "GET",
        "/api/v1/overview",
        "127.0.0.1",
        &[("Content-Length", "5")],
    )
    .await;
    assert_eq!(with_body.status, 413);
    assert_eq!(
        with_body.header("content-security-policy"),
        Some(
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
    );

    let chunked = raw_request(
        address,
        b"GET /api/v1/overview HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    )
    .await;
    assert_eq!(chunked.status, 400);
    assert!(chunked.body.contains("invalid_body_framing"));
    assert_eq!(chunked.header("cache-control"), Some("no-store"));

    let oversized_settings = request(
        address,
        "PUT",
        "/api/v1/settings",
        "127.0.0.1",
        &[("Content-Length", "65537")],
    )
    .await;
    assert_eq!(oversized_settings.status, 413);
    assert_eq!(oversized_settings.header("cache-control"), Some("no-store"));
    handle.abort();
}

#[tokio::test]
async fn overview_returns_persisted_projection() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, state, _clock, handle) = start_dashboard(root.path()).await;
    seed_task(root.path(), "task-dash-overview");
    let reply = authenticated(address, state.sessions(), "GET", "/api/v1/overview").await;
    assert_eq!(reply.status, 200);
    let value: serde_json::Value = serde_json::from_str(&reply.body).expect("json");
    assert_eq!(value["kind"], "dashboard_overview");
    assert!(
        value["config"]["digest"]
            .as_str()
            .is_some_and(|digest| !digest.is_empty())
    );
    handle.abort();
}

#[tokio::test]
async fn task_detail_replays_events_and_reports_unknown_tasks() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, state, _clock, handle) = start_dashboard(root.path()).await;
    seed_task(root.path(), "task-dash-1");
    let reply = authenticated(
        address,
        state.sessions(),
        "GET",
        "/api/v1/tasks/task-dash-1?after_seq=0&limit=50",
    )
    .await;
    assert_eq!(reply.status, 200);
    let value: serde_json::Value = serde_json::from_str(&reply.body).expect("json");
    assert_eq!(value["kind"], "dashboard_task_detail");
    assert_eq!(value["task"]["task_id"], "task-dash-1");
    assert!(
        value["events"]
            .as_array()
            .is_some_and(|events| !events.is_empty()),
        "seeded task must expose its committed events"
    );
    let unknown = authenticated(
        address,
        state.sessions(),
        "GET",
        "/api/v1/tasks/task-missing",
    )
    .await;
    assert_eq!(unknown.status, 404);
    assert!(unknown.body.contains("task_not_found"));
    handle.abort();
}

#[tokio::test]
async fn event_query_bounds_are_enforced() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, state, _clock, handle) = start_dashboard(root.path()).await;
    seed_task(root.path(), "task-dash-bounds");
    for bad in [
        "limit=0",
        "limit=201",
        "after_seq=-1",
        "after_seq=abc",
        "after_seq=9007199254740992",
    ] {
        let reply = authenticated(
            address,
            state.sessions(),
            "GET",
            &format!("/api/v1/tasks/task-dash-bounds?{bad}"),
        )
        .await;
        assert_eq!(reply.status, 400, "query {bad} must be rejected");
    }
    handle.abort();
}

#[tokio::test]
async fn no_mutation_routes_exist_anywhere() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, state, _clock, handle) = start_dashboard(root.path()).await;
    seed_task(root.path(), "task-read-only");
    let cookie = session_cookie(address, state.sessions()).await;
    for target in [
        "/api/v1/tasks",
        "/api/v1/tasks/task-read-only",
        "/api/v1/tasks/task-read-only/events/stream",
        "/api/v1/tasks/task-read-only/approve",
        "/api/v1/tasks/task-read-only/cancel",
        "/api/v1/tasks/task-read-only/retry",
        "/api/v1/tasks/task-read-only/ack",
        "/api/v1/tasks/task-read-only/delete",
    ] {
        for method in ["POST", "PUT", "DELETE", "PATCH"] {
            let reply = request(
                address,
                method,
                target,
                "127.0.0.1",
                &[("Cookie", cookie.as_str())],
            )
            .await;
            assert!(
                [404, 405].contains(&reply.status),
                "{method} {target} must never mutate; got {}",
                reply.status
            );
        }
    }
    let detail = request(
        address,
        "GET",
        "/api/v1/tasks/task-read-only",
        "127.0.0.1",
        &[("Cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(detail.status, 200, "task remains readable after probes");
    handle.abort();
}

#[tokio::test]
async fn traversal_like_task_ids_are_rejected_without_file_access() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, state, _clock, handle) = start_dashboard(root.path()).await;
    for task_id in ["..%2F..%2Fsecret", "a/b"] {
        let reply = authenticated(
            address,
            state.sessions(),
            "GET",
            &format!("/api/v1/tasks/{task_id}"),
        )
        .await;
        assert!(
            [400, 404].contains(&reply.status),
            "{task_id} returned {}",
            reply.status
        );
    }
    handle.abort();
}

#[cfg(windows)]
#[tokio::test]
async fn dashboard_secret_load_or_create_persists_dpapi_envelope() {
    let root = tempfile::tempdir().expect("tempdir");
    let install_id = "0123456789abcdef0123456789abcdef";
    let secret = DashboardSecret::load_or_create(root.path(), install_id).expect("create");
    assert!(secret.path().is_file());
    let first = std::fs::read(secret.path()).expect("envelope");
    assert!(!first.is_empty());
    assert!(first.len() <= mesh_win32::MAX_PROTECTED_ENDPOINT_KEY_BYTES);
    // A second load validates the envelope unprotects and is not rewritten.
    DashboardSecret::load_or_create(root.path(), install_id).expect("reload");
    let second = std::fs::read(secret.path()).expect("envelope again");
    assert_eq!(first, second, "existing secret must be reused");
    // A different install identity cannot adopt the envelope.
    assert!(
        DashboardSecret::load_or_create(root.path(), "1123456789abcdef0123456789abcdef").is_err()
    );
}

#[tokio::test]
async fn settings_read_and_disabled_write_gate() {
    let root = tempfile::tempdir().expect("tempdir");
    let writer =
        WriterHandle::start_portable(root.path().to_path_buf(), "install", 1).expect("writer");
    writer.ensure_empty_config_v1(1).expect("config");
    writer.shutdown().expect("shutdown");
    let readers = ReaderPool::open(root.path()).expect("readers");
    let sessions = Arc::new(SessionStore::new());
    let state = DashboardState::new(readers, Arc::clone(&sessions), TEST_CONSUMER)
        .with_settings(crate::settings::SettingsStore::new(root.path()), false);
    let (address, handle) = super::bind_and_serve_loopback(state.clone())
        .await
        .expect("bind");
    let cookie = session_cookie(address, &sessions).await;

    let read = request(
        address,
        "GET",
        "/api/v1/settings",
        "127.0.0.1",
        &[("Cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(read.status, 200);
    let value: serde_json::Value = serde_json::from_str(&read.body).expect("json");
    assert_eq!(value["kind"], "dashboard_settings");
    assert_eq!(value["writes_enabled"], false);
    assert!(
        value["csrf_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );

    let disabled = request_with_body(
        address,
        "PUT",
        "/api/v1/settings",
        "127.0.0.1",
        &[("Cookie", cookie.as_str())],
        b"{}",
    )
    .await;
    assert_eq!(disabled.status, 403);
    assert!(disabled.body.contains("settings_writes_disabled"));
    handle.abort();
}

#[tokio::test]
async fn settings_write_requires_csrf_and_validates_schema() {
    let root = tempfile::tempdir().expect("tempdir");
    let writer =
        WriterHandle::start_portable(root.path().to_path_buf(), "install", 1).expect("writer");
    writer.ensure_empty_config_v1(1).expect("config");
    writer.shutdown().expect("shutdown");
    let readers = ReaderPool::open(root.path()).expect("readers");
    let sessions = Arc::new(SessionStore::new());
    let state = DashboardState::new(readers, Arc::clone(&sessions), TEST_CONSUMER)
        .with_settings(crate::settings::SettingsStore::new(root.path()), true);
    let (address, handle) = super::bind_and_serve_loopback(state.clone())
        .await
        .expect("bind");
    let cookie = session_cookie(address, &sessions).await;

    let read = request(
        address,
        "GET",
        "/api/v1/settings",
        "127.0.0.1",
        &[("Cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(read.status, 200);
    let value: serde_json::Value = serde_json::from_str(&read.body).expect("json");
    let csrf = value["csrf_token"].as_str().expect("csrf").to_owned();

    let missing = request_with_body(
        address,
        "PUT",
        "/api/v1/settings",
        "127.0.0.1",
        &[("Cookie", cookie.as_str())],
        b"{\"kind\":\"config\"}",
    )
    .await;
    assert_eq!(missing.status, 403);
    assert!(missing.body.contains("csrf_required"));

    let forged = request_with_body(
        address,
        "PUT",
        "/api/v1/settings",
        "127.0.0.1",
        &[("Cookie", cookie.as_str()), ("X-CSRF-Token", "forged")],
        b"{\"kind\":\"config\"}",
    )
    .await;
    assert_eq!(forged.status, 403);

    let invalid = request_with_body(
        address,
        "PUT",
        "/api/v1/settings",
        "127.0.0.1",
        &[("Cookie", cookie.as_str()), ("X-CSRF-Token", csrf.as_str())],
        b"{\"kind\":\"event\"}",
    )
    .await;
    assert_eq!(invalid.status, 400);
    assert!(invalid.body.contains("settings_invalid"));

    let mut record = crate::settings::default_settings().to_record();
    record["settings"]["improvement_enabled"] = serde_json::json!(true);
    let body = serde_json::to_string(&record).expect("body");
    let accepted = request_with_body(
        address,
        "PUT",
        "/api/v1/settings",
        "127.0.0.1",
        &[("Cookie", cookie.as_str()), ("X-CSRF-Token", csrf.as_str())],
        body.as_bytes(),
    )
    .await;
    assert_eq!(accepted.status, 200);
    let written: serde_json::Value = serde_json::from_str(&accepted.body).expect("json");
    assert_eq!(written["kind"], "dashboard_settings_write");
    assert!(
        written["hot_reload"]
            .as_array()
            .is_some_and(|keys| keys.iter().any(|key| key == "improvement_enabled"))
    );
    let stored = crate::settings::SettingsStore::new(root.path())
        .load()
        .expect("stored");
    assert_eq!(stored.config_version, 1);
    assert_eq!(stored.settings["improvement_enabled"], true);
    assert!(root.path().join("config.toml").is_file());
    handle.abort();
}

#[tokio::test]
async fn task_list_is_bounded_and_authenticated() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, state, _clock, handle) = start_dashboard(root.path()).await;
    seed_task(root.path(), "task-list-1");
    seed_task(root.path(), "task-list-2");
    let anonymous = request(address, "GET", "/api/v1/tasks", "127.0.0.1", &[]).await;
    assert_eq!(anonymous.status, 401);
    let listed = authenticated(address, state.sessions(), "GET", "/api/v1/tasks?limit=1").await;
    assert_eq!(listed.status, 200);
    let value: serde_json::Value = serde_json::from_str(&listed.body).expect("json");
    assert_eq!(value["kind"], "dashboard_tasks");
    assert_eq!(
        value["tasks"].as_array().map(Vec::len),
        Some(1),
        "limit is honored"
    );
    let bad = authenticated(address, state.sessions(), "GET", "/api/v1/tasks?limit=201").await;
    assert_eq!(bad.status, 400);
    handle.abort();
}

#[tokio::test]
async fn static_assets_are_authenticated_and_traversal_safe() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, state, _clock, handle) = start_dashboard(root.path()).await;
    let anonymous = request(address, "GET", "/assets/dashboard.js", "127.0.0.1", &[]).await;
    assert_eq!(anonymous.status, 401);
    std::fs::write(root.path().join("dashboard.js"), b"outside-root-sentinel")
        .expect("decoy asset");

    let script = authenticated(address, state.sessions(), "GET", "/assets/dashboard.js").await;
    assert_eq!(script.status, 200);
    assert_eq!(
        script.header("content-type"),
        Some("text/javascript; charset=utf-8")
    );
    assert!(script.body.contains("querySelector"));
    assert!(!script.body.contains("outside-root-sentinel"));

    let style = authenticated(address, state.sessions(), "GET", "/assets/dashboard.css").await;
    assert_eq!(style.status, 200);
    assert_eq!(
        style.header("content-type"),
        Some("text/css; charset=utf-8")
    );

    let index = authenticated(address, state.sessions(), "GET", "/").await;
    assert_eq!(index.status, 200);
    assert!(index.body.contains("/assets/dashboard.js"));

    for target in [
        "/assets/../dashboard.js",
        "/assets/%2e%2e/%2e%2e/secret",
        "/assets/dashboard.js%00",
        "/assets/unknown.js",
    ] {
        let reply = authenticated(address, state.sessions(), "GET", target).await;
        assert!(
            [400, 404].contains(&reply.status),
            "asset path {target} returned {}",
            reply.status
        );
    }
    handle.abort();
}

#[tokio::test]
async fn structured_query_parsing_rejects_ambiguous_or_unknown_fields() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, state, _clock, handle) = start_dashboard(root.path()).await;
    seed_task(root.path(), "task-query-1");
    for query in [
        "limit=abc",
        "limit=0",
        "limit=201",
        "limit=1&limit=2",
        "offset=1",
    ] {
        let reply = authenticated(
            address,
            state.sessions(),
            "GET",
            &format!("/api/v1/tasks?{query}"),
        )
        .await;
        assert_eq!(reply.status, 400, "task query {query} must be rejected");
    }
    for query in [
        "after_seq=abc",
        "after_seq=-1",
        "after_seq=0&after_seq=1",
        "after_seq=0&unknown=1",
    ] {
        let reply = authenticated(
            address,
            state.sessions(),
            "GET",
            &format!("/api/v1/tasks/task-query-1/events/stream?{query}"),
        )
        .await;
        assert_eq!(reply.status, 400, "event query {query} must be rejected");
    }
    handle.abort();
}

#[tokio::test]
async fn sse_stream_replays_events_and_closes_on_terminal() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, state, _clock, handle) = start_dashboard(root.path()).await;
    let generation = seed_task(root.path(), "task-sse-1");
    let delivery = finalize_seeded_task(root.path(), "task-sse-1", generation);

    let detail = authenticated(address, state.sessions(), "GET", "/api/v1/tasks/task-sse-1").await;
    assert_eq!(detail.status, 200, "terminal detail remains readable");
    let detail_value: serde_json::Value = serde_json::from_str(&detail.body).expect("detail json");
    assert_eq!(detail_value["terminal_result"]["state"], "SUCCEEDED");
    assert_eq!(detail_value["terminal_result"]["ack_status"], "PENDING");
    assert!(detail_value["terminal_result"].get("ack_token").is_none());
    assert!(!detail.body.contains(&delivery.ack_token));
    let anonymous = request(
        address,
        "GET",
        "/api/v1/tasks/task-sse-1/events/stream",
        "127.0.0.1",
        &[],
    )
    .await;
    assert_eq!(anonymous.status, 401);

    let cookie = session_cookie(address, state.sessions()).await;
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let raw = format!(
        "GET /api/v1/tasks/task-sse-1/events/stream?after_seq=0 HTTP/1.1
Host: 127.0.0.1
Connection: close
Cookie: {cookie}

"
    );
    stream.write_all(raw.as_bytes()).await.expect("write");
    let mut bytes = Vec::new();
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        stream.read_to_end(&mut bytes),
    )
    .await
    .expect("stream must close within the bound");
    read.expect("read");
    let text = String::from_utf8_lossy(&bytes).into_owned();
    assert!(
        text.contains("200"),
        "status line: {}",
        &text[..80.min(text.len())]
    );
    assert!(text.contains("text/event-stream"), "content type set");
    assert!(
        text.contains("event: mesh_event"),
        "seeded events replay: {}",
        &text[text.len().saturating_sub(300)..]
    );
    assert!(
        text.contains("event: mesh_complete"),
        "terminal closes the stream"
    );
    // Token leakage: neither session nor bootstrap material appears in body.
    let session_value = cookie
        .strip_prefix("mesh_dashboard_session=")
        .expect("cookie value");
    assert!(!text.contains(session_value));
    handle.abort();
}

#[tokio::test]
async fn sse_stream_rejects_bad_queries_and_unknown_tasks() {
    let root = tempfile::tempdir().expect("tempdir");
    let (address, state, _clock, handle) = start_dashboard(root.path()).await;
    seed_task(root.path(), "task-sse-bounds");
    let bad = authenticated(
        address,
        state.sessions(),
        "GET",
        "/api/v1/tasks/task-sse-bounds/events/stream?after_seq=-5",
    )
    .await;
    assert_eq!(bad.status, 400);
    let unknown = authenticated(
        address,
        state.sessions(),
        "GET",
        "/api/v1/tasks/task-sse-missing/events/stream?after_seq=0",
    )
    .await;
    assert_eq!(unknown.status, 404);

    let cookie = session_cookie(address, state.sessions()).await;
    let mismatch = request(
        address,
        "GET",
        "/api/v1/tasks/task-sse-bounds/events/stream?after_seq=0",
        "127.0.0.1",
        &[("Cookie", cookie.as_str()), ("Last-Event-ID", "1")],
    )
    .await;
    assert_eq!(mismatch.status, 400);
    let invalid_header = request(
        address,
        "GET",
        "/api/v1/tasks/task-sse-bounds/events/stream",
        "127.0.0.1",
        &[("Cookie", cookie.as_str()), ("Last-Event-ID", "not-a-seq")],
    )
    .await;
    assert_eq!(invalid_header.status, 400);
    let duplicate_header = request(
        address,
        "GET",
        "/api/v1/tasks/task-sse-bounds/events/stream",
        "127.0.0.1",
        &[
            ("Cookie", cookie.as_str()),
            ("Last-Event-ID", "0"),
            ("Last-Event-ID", "1"),
        ],
    )
    .await;
    assert_eq!(duplicate_header.status, 400);
    handle.abort();
}

#[tokio::test]
async fn sse_nonterminal_stream_closes_with_timeout() {
    let root = tempfile::tempdir().expect("tempdir");
    let writer =
        WriterHandle::start_portable(root.path().to_path_buf(), "install", 1).expect("writer");
    writer.ensure_empty_config_v1(1).expect("config v1");
    writer.shutdown().expect("shutdown bootstrap writer");
    let readers = ReaderPool::open(root.path()).expect("readers");
    let clock = TestClock::new();
    let sessions = Arc::new(SessionStore::with_clock(clock_fn(&clock)));
    let state = DashboardState::new(readers, Arc::clone(&sessions), TEST_CONSUMER)
        .with_stream_timing(
            std::time::Duration::from_millis(60),
            std::time::Duration::from_millis(5),
        );
    let (address, handle) = bind_and_serve_loopback(state.clone())
        .await
        .expect("bind loopback");
    seed_task(root.path(), "task-sse-timeout");

    let cookie = session_cookie(address, state.sessions()).await;
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect");
    let raw = format!(
        "GET /api/v1/tasks/task-sse-timeout/events/stream?after_seq=0 HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nCookie: {cookie}\r\n\r\n"
    );
    stream.write_all(raw.as_bytes()).await.expect("write");
    let mut bytes = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        stream.read_to_end(&mut bytes),
    )
    .await
    .expect("stream closes at configured lifetime")
    .expect("read stream");
    let text = String::from_utf8_lossy(&bytes);
    assert!(text.contains("event: mesh_event"));
    assert!(text.contains("event: mesh_timeout"));
    assert!(!text.contains("event: mesh_complete"));
    handle.abort();
}

fn append_text_event(root: &Path, task_id: &str, generation: i64, text: &str) {
    let database = root.join("mesh.sqlite3");
    let connection = rusqlite::Connection::open(database).expect("open seeded database");
    let payload = serde_json::json!({ "text": text }).to_string();
    let seq: i64 = connection
        .query_row(
            "UPDATE tasks SET last_event_seq=last_event_seq+1, projection_event_seq=last_event_seq+1 WHERE task_id=?1 RETURNING last_event_seq",
            [task_id],
            |row| row.get(0),
        )
        .expect("advance seq");
    connection
        .execute(
            "INSERT INTO events(task_id,event_seq,event_id,generation,kind,payload,committed_at) VALUES(?1,?2,?3,?4,'text_delta',?5,5)",
            rusqlite::params![
                task_id,
                seq,
                format!("hostile-{seq}"),
                generation,
                payload
            ],
        )
        .expect("insert hostile event");
}

fn seed_hostile_task(root: &Path, task_id: &str) {
    let generation = seed_task(root, task_id);
    let writer = WriterHandle::start_portable(root.to_path_buf(), "install", 1).expect("writer");
    writer
        .transition(
            format!("run-{task_id}"),
            task_id,
            generation,
            vec!["PREPARING".into(), "QUEUED".into()],
            "RUNNING",
            2,
        )
        .or_else(|_| {
            writer.clone().transition(
                format!("run-{task_id}"),
                task_id,
                generation,
                vec!["RUNNING".into()],
                "RUNNING",
                2,
            )
        })
        .expect("reach RUNNING");
    writer.shutdown().expect("shutdown before hostile insert");
    append_text_event(
        root,
        task_id,
        generation,
        "</div><img src=\"http://127.0.0.1/xss\" onerror=\"window.__mesh_xss=1\"><svg/onload=\"window.__mesh_xss=2\">",
    );
    append_text_event(
        root,
        task_id,
        generation,
        "\"><a href=\"javascript:window.__mesh_xss=3\">click</a>",
    );
    append_text_event(
        root,
        task_id,
        generation,
        "provider echoed secret-marker-m6",
    );
    append_text_event(root, task_id, generation, &"A".repeat(65_536));
    drop(finalize_seeded_task(root, task_id, generation));
}

fn env_path(name: &str, fallback: std::path::PathBuf) -> std::path::PathBuf {
    std::env::var(name).map_or(fallback, std::path::PathBuf::from)
}

fn collect_pipe(pipe: &mut Option<impl std::io::Read>) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Some(reader) = pipe.as_mut() {
        let _ = std::io::Read::read_to_end(reader, &mut bytes);
    }
    bytes
}

fn run_edge_driver(
    driver: &std::path::Path,
    payload: &serde_json::Value,
) -> (std::process::ExitStatus, Vec<u8>, Vec<u8>) {
    use std::io::Write;
    let mut child = std::process::Command::new("node")
        .arg(driver)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn node driver");
    {
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin
            .write_all(payload.to_string().as_bytes())
            .expect("write driver config");
    }
    drop(child.stdin.take());
    let started = std::time::Instant::now();
    loop {
        if child.try_wait().expect("try wait").is_some() {
            let stdout = collect_pipe(&mut child.stdout);
            let stderr = collect_pipe(&mut child.stderr);
            let status = child.wait().expect("wait after exit");
            return (status, stdout, stderr);
        }
        if started.elapsed() > std::time::Duration::from_secs(90) {
            let _ = child.kill();
            panic!("edge driver exceeded 90s");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

#[tokio::test]
#[ignore = "opt-in Edge CDP dashboard security fixture"]
async fn edge_security_acceptance() {
    let root = env_path(
        "MESH_DASHBOARD_SECURITY_ROOT",
        tempfile::tempdir().expect("tempdir").keep(),
    );
    std::fs::create_dir_all(&root).expect("data root");
    let driver = env_path(
        "MESH_DASHBOARD_SECURITY_DRIVER",
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/dashboard-fixtures/edge-cdp.mjs"),
    );
    let edge = std::env::var("MESH_DASHBOARD_SECURITY_EDGE").unwrap_or_default();
    let profile = env_path("MESH_DASHBOARD_SECURITY_PROFILE", root.join("edge-profile"));
    std::fs::create_dir_all(&profile).expect("profile");
    assert!(
        driver.is_file(),
        "edge driver missing: {}",
        driver.display()
    );
    assert!(
        std::path::Path::new(&edge).is_file(),
        "Edge executable missing"
    );

    seed_hostile_task(&root, "task-m6-hostile");
    let readers = ReaderPool::open(&root).expect("readers");
    let sessions = Arc::new(SessionStore::new());
    let state = DashboardState::new(readers, Arc::clone(&sessions), TEST_CONSUMER)
        .with_settings(crate::settings::SettingsStore::new(&root), false);
    let (address, handle) = bind_and_serve_loopback(state.clone()).await.expect("bind");
    let token = sessions.mint_bootstrap();
    let payload = serde_json::json!({
        "bootstrapUrl": format!("http://{address}/bootstrap?token={token}"),
        "taskId": "task-m6-hostile",
        "secretMarker": "secret-marker-m6",
        "profileDir": profile,
        "edgePath": edge,
    });

    let output = tokio::task::spawn_blocking(move || run_edge_driver(&driver, &payload))
        .await
        .expect("driver thread");
    handle.abort();

    let stdout = String::from_utf8_lossy(&output.1);
    let report: serde_json::Value = serde_json::from_str(stdout.lines().last().unwrap_or("{}"))
        .unwrap_or_else(|_| serde_json::json!({ "status": "FAIL", "reason": stdout }));
    assert_eq!(
        report["status"],
        "PASS",
        "edge fixture: {} stderr={}",
        report,
        String::from_utf8_lossy(&output.2)
    );
    assert!(!stdout.contains("secret-marker-m6"));
    assert!(!stdout.contains(&token));
}
