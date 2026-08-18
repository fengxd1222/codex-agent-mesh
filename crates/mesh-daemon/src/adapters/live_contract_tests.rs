//! Opt-in live contract tests for the three provider adapters.
//!
//! These tests are `#[ignore]`d and additionally require
//! `MESH_LIVE_ADAPTER_TESTS=1`, so credentialed provider runs never happen
//! in offline CI. Each test drives one real local CLI through the
//! supervisor, verifies the normalized event stream, and writes a
//! machine-local evidence record under the evidence directory.

#![allow(
    clippy::cast_possible_truncation,
    clippy::duration_suboptimal_units,
    clippy::missing_panics_doc,
    clippy::too_many_arguments,
    clippy::too_many_lines
)]

use crate::adapters::NormalizedKind;
use crate::adapters::acp;
use crate::adapters::claude;
use crate::adapters::grok::{self, GrokLaunchRequest, GrokProbeEvidence, GrokTransportSelection};
use crate::adapters::kimi::{self, KimiLaunchRequest, KimiProbeEvidence, KimiTransportSelection};
use crate::adapters::live_contract::{
    CORE_CHECKS, LiveContractRecord, LiveRun, evidence_path, sanitize_reason,
};
use crate::adapters::{
    CLAUDE_FIXTURE_BUNDLE_ID, Effort, GROK_FIXTURE_BUNDLE_ID, KIMI_FIXTURE_BUNDLE_ID, Quality,
    confirm_admission, digest_file,
};
use crate::domain::TaskState;
use crate::scheduler::{AdapterInstanceId, SchedulerLimits};
use crate::storage::{AttemptSpec, DispatchOutcome};
use crate::supervisor::{
    ProcessSupervisor, ResumeGate, SpawnOutcome, SpawnRequest, SupervisedAttempt,
};
use crate::writer::WriterHandle;
use serde_json::Value;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const ADAPTER_ENV: &str = "MESH_LIVE_ADAPTER_TESTS";
const EVIDENCE_DIR_ENV: &str = "MESH_LIVE_EVIDENCE_DIR";
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(4 * 60);
const POLL_INTERVAL: Duration = Duration::from_millis(200);

fn client_initialize_params() -> serde_json::Value {
    serde_json::json!({
        "protocolVersion": 1,
        "clientCapabilities": {
            "fs": { "readTextFile": false, "writeTextFile": false },
            "terminal": false
        }
    })
}

fn require_live_opt_in() {
    assert_eq!(
        std::env::var(ADAPTER_ENV).ok().as_deref(),
        Some("1"),
        "credentialed live adapter tests require {ADAPTER_ENV}=1"
    );
}

fn evidence_dir() -> PathBuf {
    let dir = match std::env::var(EVIDENCE_DIR_ENV) {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/live-adapter-evidence"),
    };
    std::fs::create_dir_all(&dir).expect("create evidence dir");
    dir
}

fn resolve_exe(override_env: &str, default_suffix: &str) -> Result<PathBuf, String> {
    if let Some(path) = std::env::var_os(override_env) {
        let path = PathBuf::from(path);
        return if path.is_file() {
            Ok(path)
        } else {
            Err(format!("override {override_env} is not a file"))
        };
    }
    let home = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .ok_or_else(|| "USERPROFILE is not set".to_owned())?;
    let path = home.join(default_suffix);
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!(
            "default executable {default_suffix} not found; set {override_env}"
        ))
    }
}

fn capture_stdout(exe: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new(exe)
        .args(args)
        .output()
        .map_err(|error| sanitize_reason(&format!("probe spawn failed: {error}")))?;
    if !output.status.success() {
        return Err(format!("probe {} failed", args.join(" ")));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| format!("probe {} printed non-utf8", args.join(" ")))
}

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_micros() as i64)
        .unwrap_or_default()
}

fn parse_probe_version(stdout: &str) -> Option<String> {
    stdout.split_whitespace().find_map(|token| {
        let mut parts = token.split('.');
        let major = parts.next()?;
        let minor = parts.next()?;
        let patch = parts.next()?;
        if parts.next().is_some()
            || major.is_empty()
            || !major.bytes().all(|byte| byte.is_ascii_digit())
            || !minor.bytes().all(|byte| byte.is_ascii_digit())
            || !patch.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        Some(format!("{major}.{minor}.{patch}"))
    })
}

fn claim_attempt(
    writer: &WriterHandle,
    adapter: &str,
    config_digest: &str,
    version: &str,
    suffix: &str,
    now: i64,
) -> String {
    let aid = AdapterInstanceId::new(adapter, "local", "default", config_digest)
        .expect("adapter instance id")
        .encode();
    writer
        .submit_for_scheduling(
            "live",
            "submit",
            format!("k-live-{adapter}-{suffix}"),
            format!("body-live-{adapter}-{suffix}").into_bytes(),
            format!("task-live-{adapter}-{suffix}"),
            None,
            5,
            Some(&aid),
            now,
        )
        .expect("submit");
    let spec = AttemptSpec {
        adapter_instance_id: aid,
        config_digest: config_digest.to_owned(),
        adapter_version: version.to_owned(),
        ..AttemptSpec::default()
    };
    match writer
        .claim_dispatch_slot(
            format!("claim-live-{adapter}-{suffix}"),
            format!("task-live-{adapter}-{suffix}"),
            0,
            spec,
            SchedulerLimits::DEFAULT,
            now + 1,
        )
        .expect("claim")
    {
        DispatchOutcome::Dispatched(attempt) => attempt.attempt_id,
        DispatchOutcome::Blocked(blocked) => panic!("live claim blocked: {blocked:?}"),
    }
}

/// Proxy variables grok needs on this network: x.ai egress goes through a
/// local forward proxy (the user's PowerShell `grok` wrapper sets the same
/// variables). Values come from the caller's environment and are forwarded
/// in memory only; nothing is persisted.
fn grok_proxy_extra_env() -> Vec<(OsString, OsString)> {
    let proxy = std::env::var("GROK_FORWARD_PROXY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            std::env::var("HTTPS_PROXY")
                .ok()
                .filter(|value| !value.trim().is_empty())
        });
    let Some(proxy) = proxy else {
        return Vec::new();
    };
    let no_proxy = std::env::var("NO_PROXY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "localhost,127.0.0.1,::1".into());
    [
        ("HTTP_PROXY", proxy.clone()),
        ("HTTPS_PROXY", proxy.clone()),
        ("ALL_PROXY", proxy),
        ("NO_PROXY", no_proxy.clone()),
        ("GROK_WEB_FETCH_PROXY", no_proxy),
    ]
    .into_iter()
    .map(|(key, value)| (OsString::from(key), OsString::from(value)))
    .collect()
}

#[allow(clippy::too_many_arguments)]
fn spawn_supervised(
    writer: &WriterHandle,
    adapter: &str,
    config_digest: &str,
    version: &str,
    suffix: &str,
    executable: &Path,
    arguments: Vec<OsString>,
    extra_env: Vec<(OsString, OsString)>,
    workspace: &Path,
    data_root: &Path,
) -> Result<SupervisedAttempt, String> {
    let attempt_id = claim_attempt(writer, adapter, config_digest, version, suffix, now_us());
    let supervisor = ProcessSupervisor::new(writer.clone());
    match supervisor.spawn(
        SpawnRequest {
            task_id: format!("task-live-{adapter}-{suffix}"),
            generation: 0,
            attempt_id,
            executable: executable.to_path_buf(),
            arguments,
            env_allowlist: Vec::new(),
            extra_env,
            current_dir: Some(workspace.to_path_buf()),
            data_root: data_root.to_path_buf(),
            spool_quota_bytes: 0,
            now_us: now_us(),
            consumer_id: "live".into(),
        },
        ResumeGate::Resume,
    ) {
        Ok(SpawnOutcome::Started(live)) => Ok(*live),
        Ok(SpawnOutcome::AbortedBeforeResume { .. }) => {
            Err("supervisor aborted before resume".into())
        }
        Err(error) => Err(sanitize_reason(&format!("spawn failed: {error}"))),
    }
}

fn spool_frames(spool: &Path) -> Vec<Value> {
    let Ok(text) = std::fs::read_to_string(spool) else {
        return Vec::new();
    };
    text.lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn wait_for_frame(spool: &Path, predicate: impl Fn(&Value) -> bool) -> Result<Value, String> {
    let started = Instant::now();
    loop {
        for frame in spool_frames(spool) {
            if predicate(&frame) {
                return Ok(frame);
            }
        }
        if started.elapsed() > RESPONSE_TIMEOUT {
            // Keep the failure self-explanatory in the evidence record.
            let seen = spool_frames(spool);
            let summary = match seen.last() {
                Some(frame) => {
                    let method = frame.get("method").and_then(Value::as_str).unwrap_or("");
                    let id = frame.get("id").map(ToString::to_string).unwrap_or_default();
                    format!("; saw {} frames, last id={id} method={method}", seen.len())
                }
                None => "; no frames observed".into(),
            };
            return Err(format!("timed out waiting for a provider frame{summary}"));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn result_frame(id: i64, frame: &Value) -> bool {
    frame.get("id").and_then(Value::as_i64) == Some(id) && frame.get("result").is_some()
}

fn acp_request(id: u64, method: &str, params: &Value) -> Result<Vec<u8>, String> {
    acp::encode_request(id, method, params).map_err(|_| format!("encode {method} failed"))
}

/// Drives the full ACP conversation against a live provider stdio server:
/// handshake, streamed updates, terminal; optionally a cancelled session.
#[allow(clippy::too_many_arguments)]
fn run_acp_contract(
    adapter: &str,
    exe: &Path,
    arguments: &[OsString],
    extra_env: Vec<(OsString, OsString)>,
    config_digest: &str,
    objective: &str,
    cancel_objective: &str,
    auth_method_id: Option<&str>,
    attempt_cancel: bool,
) -> LiveRun {
    let digest = digest_file(exe).unwrap_or_else(|_| "0".repeat(64));
    let version = capture_stdout(exe, &["--version"])
        .ok()
        .and_then(|stdout| parse_probe_version(&stdout))
        .unwrap_or_else(|| "unproven".into());
    let mut run = LiveRun::new(digest, version.clone());

    match drive_acp_session(
        adapter,
        exe,
        arguments,
        extra_env.clone(),
        config_digest,
        &version,
        "ok",
        objective,
        false,
        auth_method_id,
    ) {
        Ok(checks) => run.checks.extend(checks),
        Err(reason) => {
            run.failure = Some(reason);
            return run;
        }
    }

    // The cancel leg proves the Cancellation capability; adapters that
    // do not admit it (kimi 0.28.1 answers session/cancel with
    // "Method not found") skip the leg entirely.
    if attempt_cancel {
        match drive_acp_session(
            adapter,
            exe,
            arguments,
            extra_env,
            config_digest,
            &version,
            "cancel",
            cancel_objective,
            true,
            auth_method_id,
        ) {
            Ok(checks) => run.checks.extend(checks),
            Err(reason) => run.failure = Some(reason),
        }
    }
    run
}

#[allow(clippy::too_many_arguments)]
fn drive_acp_session(
    adapter: &str,
    exe: &Path,
    arguments: &[OsString],
    extra_env: Vec<(OsString, OsString)>,
    config_digest: &str,
    version: &str,
    suffix: &str,
    objective: &str,
    cancel_mid_stream: bool,
    auth_method_id: Option<&str>,
) -> Result<Vec<&'static str>, String> {
    let root = tempfile::tempdir().expect("tempdir");
    let workspace = tempfile::tempdir().expect("tempdir");
    let writer =
        WriterHandle::start_portable(root.path().to_path_buf(), "live", 1).expect("writer");
    let mut live = spawn_supervised(
        &writer,
        adapter,
        config_digest,
        version,
        suffix,
        exe,
        arguments.to_vec(),
        extra_env,
        workspace.path(),
        root.path(),
    )?;
    let spool = live.stdout_spool_path().to_path_buf();
    // jsonrpc ids: initialize, optional authenticate, session/new, prompt,
    // cancel. Providers reject reused ids, so keep them strictly ordered.
    let mut next_id = 1_u64;
    let initialize_id = next_id;
    next_id += 1;
    let auth_id = auth_method_id.map(|_| next_id);
    if auth_id.is_some() {
        next_id += 1;
    }
    let session_new_id = next_id;
    next_id += 1;
    let prompt_id = next_id;
    next_id += 1;
    let cancel_id = next_id;

    live.write_stdin_line(&acp_request(
        initialize_id,
        "initialize",
        &client_initialize_params(),
    )?)
    .map_err(|error| sanitize_reason(&format!("initialize write failed: {error}")))?;
    let init = wait_for_frame(&spool, |frame| {
        result_frame(i64::try_from(initialize_id).expect("id"), frame)
    })?;
    if acp::parse_initialize_result(&init).is_none() {
        return Err("initialize result lacked server capabilities".into());
    }
    if let (Some(auth_id), Some(method_id)) = (auth_id, auth_method_id) {
        // grok's documented flow requires authenticate before prompting;
        // kimi 0.28.1 answers prompts from its cached login state.
        live.write_stdin_line(&acp_request(
            auth_id,
            "authenticate",
            &serde_json::json!({ "methodId": method_id }),
        )?)
        .map_err(|error| sanitize_reason(&format!("authenticate write failed: {error}")))?;
        wait_for_frame(&spool, |frame| {
            result_frame(i64::try_from(auth_id).expect("id"), frame)
                || frame.get("id").and_then(Value::as_i64)
                    == Some(i64::try_from(auth_id).expect("id"))
        })?;
    }
    live.write_stdin_line(&acp_request(
        session_new_id,
        "session/new",
        &serde_json::json!({
            "cwd": workspace.path().to_string_lossy(),
            "mcpServers": []
        }),
    )?)
    .map_err(|error| sanitize_reason(&format!("session/new write failed: {error}")))?;
    let session = wait_for_frame(&spool, |frame| {
        result_frame(i64::try_from(session_new_id).expect("id"), frame)
    })
    .map_err(|reason| format!("session/new failed: {reason}"))?;
    let session_id = session
        .pointer("/result/sessionId")
        .and_then(Value::as_str)
        .ok_or("session/new result lacked sessionId")?
        .to_owned();
    let prompt = acp::encode_session_prompt(prompt_id, &session_id, objective)
        .map_err(|_| "prompt encode failed".to_owned())?;
    live.write_stdin_line(&prompt)
        .map_err(|error| sanitize_reason(&format!("prompt write failed: {error}")))?;
    let _first_update = wait_for_frame(&spool, |frame| {
        frame.get("method").and_then(Value::as_str) == Some("session/update")
    })?;

    let mut checks = vec!["handshake", "stream_updates"];
    if cancel_mid_stream {
        let cancel_line = acp::encode_cancel(cancel_id, &session_id)
            .map_err(|_| "cancel encode failed".to_owned())?;
        live.write_stdin_line(&cancel_line)
            .map_err(|error| sanitize_reason(&format!("cancel write failed: {error}")))?;
        let settled = wait_for_frame(&spool, |frame| {
            result_frame(i64::try_from(prompt_id).expect("id"), frame)
                || result_frame(i64::try_from(cancel_id).expect("id"), frame)
        })?;
        if result_frame(i64::try_from(cancel_id).expect("id"), &settled) {
            let _ = wait_for_frame(&spool, |frame| {
                result_frame(i64::try_from(prompt_id).expect("id"), frame)
            })?;
        }
        checks.push("cancel");
    }
    let terminal = wait_for_frame(&spool, |frame| {
        result_frame(i64::try_from(prompt_id).expect("id"), frame)
    })?;
    let stop = terminal
        .pointer("/result/stopReason")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if cancel_mid_stream && !stop.starts_with("cancel") {
        return Err(format!("cancel session ended with stopReason {stop}"));
    }
    if !cancel_mid_stream && stop != "end_turn" {
        return Err(format!("success session ended with stopReason {stop}"));
    }
    checks.push("terminal");
    // ACP stdio servers stay alive across prompts by design; the terminal
    // response frame, not process exit, completes the contract. Dropping
    // the attempt lets the supervisor job terminate the tree.
    Ok(checks)
}

pub(crate) fn write_live_evidence(
    run: LiveRun,
    adapter: &str,
    transport: &str,
    bundle_id: &str,
) -> LiveRun {
    let outcome =
        if run.failure.is_none() && CORE_CHECKS.iter().all(|check| run.checks.contains(check)) {
            "PASS"
        } else {
            "FAIL"
        };
    let mut checks: Vec<String> = Vec::new();
    for check in &run.checks {
        let check = (*check).to_owned();
        if !checks.contains(&check) {
            checks.push(check);
        }
    }
    let record = LiveContractRecord {
        adapter: adapter.to_owned(),
        executable_digest: run.executable_digest.clone(),
        executable_version: run.executable_version.clone(),
        transport: transport.to_owned(),
        fixture_bundle_id: bundle_id.to_owned(),
        checks,
        outcome: outcome.into(),
        reason: run
            .failure
            .clone()
            .map(|reason| sanitize_reason(&reason))
            .unwrap_or_default(),
        checked_at_us: now_us(),
    };
    let encoded = record.encode().expect("encode live record");
    std::fs::write(evidence_path(&evidence_dir(), adapter), encoded).expect("write live evidence");
    run
}

fn assert_passing(run: LiveRun, adapter: &str) {
    assert!(
        run.failure.is_none(),
        "{adapter} live contract failed: {}",
        run.failure.unwrap_or_default()
    );
    for check in CORE_CHECKS {
        assert!(
            run.checks.contains(check),
            "{adapter} live contract missing check {check}"
        );
    }
}

#[test]
#[ignore = "credentialed; requires MESH_LIVE_ADAPTER_TESTS=1"]
fn live_contract_grok_acp() {
    require_live_opt_in();
    let exe = resolve_exe("MESH_LIVE_GROK_EXE", ".grok/bin/grok.exe").unwrap_or_else(|reason| {
        write_live_evidence(
            LiveRun::failing(reason),
            "grok",
            "acp",
            GROK_FIXTURE_BUNDLE_ID,
        );
        panic!("grok executable unavailable")
    });
    let evidence = GrokProbeEvidence {
        executable: exe.clone(),
        display_path: "grok.exe".into(),
        version_stdout: Some(capture_stdout(&exe, &["--version"]).expect("grok version")),
        help_stdout: Some(capture_stdout(&exe, &["--help"]).expect("grok help")),
        agent_stdio_help_stdout: Some(
            capture_stdout(&exe, &["agent", "stdio", "--help"]).expect("grok agent stdio help"),
        ),
        live_contract_passed: false,
        account: "local".into(),
        profile: "default".into(),
    };
    let admission = grok::probe_grok(&evidence);
    confirm_admission(&admission, &exe).expect("digest stable across probe");
    let request = GrokLaunchRequest {
        objective: "Reply with exactly one word: ok".into(),
        quality: Quality::Standard,
        effort: Effort::Medium,
        workspace: "workspace".into(),
        session_id: None,
    };
    let plan = grok::plan_grok_spawn(
        &exe,
        &admission,
        &request,
        GrokTransportSelection::Acp,
        &serde_json::json!({}),
    )
    .expect("grok spawn plan");
    let run = run_acp_contract(
        "grok",
        &exe,
        &plan.arguments,
        grok_proxy_extra_env(),
        &grok::grok_config_digest(),
        "Reply with exactly one word: ok",
        "Write the numbers 1 through 100, one number per line.",
        // grok's documented ACP flow authenticates with the cached token
        // before any prompt; the method id comes from the initialize
        // response's authMethods and is provider-specific.
        Some("cached_token"),
        admission.admits(crate::adapters::AdapterCapability::Cancellation),
    );
    assert_passing(
        write_live_evidence(run, "grok", "acp", GROK_FIXTURE_BUNDLE_ID),
        "grok",
    );
}

#[test]
#[ignore = "credentialed; requires MESH_LIVE_ADAPTER_TESTS=1"]
fn live_contract_kimi_acp() {
    require_live_opt_in();
    let exe =
        resolve_exe("MESH_LIVE_KIMI_EXE", ".kimi-code/bin/kimi.exe").unwrap_or_else(|reason| {
            write_live_evidence(
                LiveRun::failing(reason),
                "kimi",
                "acp",
                KIMI_FIXTURE_BUNDLE_ID,
            );
            panic!("kimi executable unavailable")
        });
    let evidence = KimiProbeEvidence {
        executable: exe.clone(),
        display_path: "kimi.exe".into(),
        version_stdout: Some(capture_stdout(&exe, &["--version"]).expect("kimi version")),
        help_stdout: Some(capture_stdout(&exe, &["--help"]).expect("kimi help")),
        acp_help_stdout: Some(capture_stdout(&exe, &["acp", "--help"]).expect("kimi acp help")),
        live_contract_passed: false,
        account: "local".into(),
        profile: "default".into(),
    };
    let probe = kimi::probe_kimi(&evidence);
    confirm_admission(&probe.admission, &exe).expect("digest stable across probe");
    let request = KimiLaunchRequest {
        objective: "Reply with exactly one word: ok".into(),
        quality: Quality::Standard,
        effort: Effort::Medium,
        workspace: "workspace".into(),
        session_id: None,
    };
    let plan = kimi::plan_kimi_spawn(
        &exe,
        &probe.admission,
        &request,
        KimiTransportSelection::Acp,
        &serde_json::json!({}),
    )
    .expect("kimi spawn plan");
    let run = run_acp_contract(
        "kimi",
        &exe,
        &plan.arguments,
        Vec::new(),
        &kimi::kimi_config_digest(),
        "Reply with exactly one word: ok",
        "Write the numbers 1 through 100, one number per line.",
        // kimi 0.28.1 answers from its cached login without authenticate,
        // and its ACP server has no session/cancel method.
        None,
        probe
            .admission
            .admits(crate::adapters::AdapterCapability::Cancellation),
    );
    assert_passing(
        write_live_evidence(run, "kimi", "acp", KIMI_FIXTURE_BUNDLE_ID),
        "kimi",
    );
}

#[test]
#[ignore = "credentialed; requires MESH_LIVE_ADAPTER_TESTS=1"]
fn live_contract_claude_stream_json() {
    require_live_opt_in();
    let exe =
        resolve_exe("MESH_LIVE_CLAUDE_EXE", ".local/bin/claude.exe").unwrap_or_else(|reason| {
            write_live_evidence(
                LiveRun::failing(reason),
                "claude",
                "stream_json",
                CLAUDE_FIXTURE_BUNDLE_ID,
            );
            panic!("claude executable unavailable")
        });
    let version_stdout = capture_stdout(&exe, &["--version"]).expect("claude version");
    let version = parse_probe_version(&version_stdout).unwrap_or_else(|| "unproven".into());
    let digest = digest_file(&exe).expect("claude digest");
    // The wire contract is exercised directly; whether this installed
    // version is admitted by the fixture-pinned matrix stays a separate
    // decision recorded through the evidence version field.
    let run = (|| -> LiveRun {
        let root = tempfile::tempdir().expect("tempdir");
        let workspace = tempfile::tempdir().expect("tempdir");
        let writer =
            WriterHandle::start_portable(root.path().to_path_buf(), "live", 1).expect("writer");
        let arguments = vec![
            OsString::from("--print"),
            OsString::from("--output-format"),
            OsString::from("stream-json"),
            OsString::from("--verbose"),
            OsString::from("--"),
            OsString::from("Reply with exactly one word: ok"),
        ];
        let mut live = match spawn_supervised(
            &writer,
            "claude",
            &claude::claude_config_digest(),
            &version,
            "ok",
            &exe,
            arguments,
            Vec::new(),
            workspace.path(),
            root.path(),
        ) {
            Ok(live) => live,
            Err(reason) => {
                return LiveRun {
                    checks: Vec::new(),
                    failure: Some(reason),
                    executable_version: version.clone(),
                    executable_digest: digest.clone(),
                };
            }
        };
        let spool = live.stdout_spool_path().to_path_buf();
        let outcome = (|| -> Result<Vec<&'static str>, String> {
            let result = wait_for_frame(&spool, |frame| {
                frame.get("type").and_then(Value::as_str) == Some("result")
            })?;
            // A provider-reported error (for example an authentication
            // failure) is a contract failure with the honest status, not a
            // decode defect.
            if result.get("is_error").and_then(Value::as_bool) == Some(true) {
                let status = result
                    .get("api_error_status")
                    .and_then(Value::as_i64)
                    .unwrap_or_default();
                return Err(format!(
                    "provider result reported is_error with api_error_status {status}"
                ));
            }
            let Ok(text) = std::fs::read_to_string(&spool) else {
                return Err("stdout spool unreadable".into());
            };
            let decoded: Vec<_> = text
                .lines()
                .flat_map(claude::decode_stream_json_line)
                .collect();
            if !decoded
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::Terminal { state } if state == TaskState::Succeeded))
            {
                return Err("stream-json result did not decode to a success terminal".into());
            }
            if !decoded
                .iter()
                .any(|event| matches!(event.kind, NormalizedKind::TextDelta { .. }))
            {
                return Err("stream-json contained no text deltas".into());
            }
            let exit = live.wait(RESPONSE_TIMEOUT).expect("wait");
            if exit != Some(0) {
                return Err(format!("claude exited with {exit:?}"));
            }
            Ok(vec!["handshake", "stream_updates", "terminal"])
        })();
        let mut run = LiveRun::new(digest.clone(), version.clone());
        match outcome {
            Ok(checks) => run.checks.extend(checks),
            Err(reason) => run.failure = Some(reason),
        }
        run
    })();
    assert_passing(
        write_live_evidence(run, "claude", "stream_json", CLAUDE_FIXTURE_BUNDLE_ID),
        "claude",
    );
}
