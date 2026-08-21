//! Production scheduler loop: claim a queued task, spawn the admitted
//! local adapter, persist normalized events, and finalize.
//!
//! This is the only production caller of [`crate::supervisor`]. Live
//! observation is the durable event log: dashboard SSE and `wait_task`
//! replay those rows, never an in-memory provider stream.

#![allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::adapters::acp;
use crate::adapters::claude::{self, ClaudeLaunchRequest};
use crate::adapters::grok::{self, GrokLaunchRequest, GrokTransportSelection};
use crate::adapters::kimi::{self, KimiLaunchRequest, KimiTransportSelection};
use crate::adapters::registry::AdapterRegistry;
use crate::adapters::{AdmissionRecord, AdmissionStatus, Effort, NormalizedKind, Quality};
use crate::reader::ReaderPool;
use crate::scheduler::{SchedulerLimits, SchedulerPolicy, plan_dispatch};
use crate::storage::{AttemptSpec, DispatchOutcome};
use crate::supervisor::{
    ProcessSupervisor, ResumeGate, SpawnOutcome, SpawnRequest, SupervisedAttempt,
};
use crate::writer::WriterHandle;

const LOOP_WAIT: Duration = Duration::from_millis(250);
const SPOOL_POLL: Duration = Duration::from_millis(150);
const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Wakes the dispatcher after a new durable task is admitted.
#[derive(Clone, Debug)]
pub struct DispatchWake {
    signal: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

impl DispatchWake {
    #[must_use]
    pub fn new() -> Self {
        Self {
            signal: Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new())),
        }
    }

    pub fn notify(&self) {
        let (lock, cond) = &*self.signal;
        if let Ok(mut pending) = lock.lock() {
            *pending = true;
            cond.notify_one();
        }
    }

    fn wait_timeout(&self, timeout: Duration) {
        let (lock, cond) = &*self.signal;
        let Ok(guard) = lock.lock() else {
            thread::sleep(timeout);
            return;
        };
        if *guard {
            return;
        }
        let _ = cond.wait_timeout(guard, timeout);
    }

    fn take(&self) -> bool {
        let (lock, _) = &*self.signal;
        lock.lock().is_ok_and(|mut pending| {
            let was = *pending;
            *pending = false;
            was
        })
    }
}

impl Default for DispatchWake {
    fn default() -> Self {
        Self::new()
    }
}

/// Background production dispatcher. Dropping the handle requests stop.
pub struct DispatcherHandle {
    shutdown: Arc<AtomicBool>,
    wake: DispatchWake,
    thread: Option<JoinHandle<()>>,
}

impl DispatcherHandle {
    #[must_use]
    pub fn wake(&self) -> DispatchWake {
        self.wake.clone()
    }
}

impl Drop for DispatcherHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.wake.notify();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Starts the production loop. The loop owns no occupancy: every claim
/// re-reads `SQLite` through the writer.
#[must_use]
pub fn start(
    reader: ReaderPool,
    writer: WriterHandle,
    registry: AdapterRegistry,
    consumer_id: String,
    data_root: PathBuf,
) -> DispatcherHandle {
    let wake = DispatchWake::new();
    let shutdown = Arc::new(AtomicBool::new(false));
    let loop_wake = wake.clone();
    let loop_shutdown = Arc::clone(&shutdown);
    let thread = thread::Builder::new()
        .name("mesh-dispatcher".into())
        .spawn(move || {
            run_loop(
                &reader,
                &writer,
                &registry,
                &consumer_id,
                &data_root,
                &loop_wake,
                &loop_shutdown,
            );
        })
        .ok();
    DispatcherHandle {
        shutdown,
        wake,
        thread,
    }
}

fn run_loop(
    reader: &ReaderPool,
    writer: &WriterHandle,
    registry: &AdapterRegistry,
    consumer_id: &str,
    data_root: &Path,
    wake: &DispatchWake,
    shutdown: &Arc<AtomicBool>,
) {
    while !shutdown.load(Ordering::Acquire) {
        wake.take();
        dispatch_round(reader, writer, registry, consumer_id, data_root);
        if shutdown.load(Ordering::Acquire) {
            break;
        }
        wake.wait_timeout(LOOP_WAIT);
    }
}

fn dispatch_round(
    reader: &ReaderPool,
    writer: &WriterHandle,
    registry: &AdapterRegistry,
    consumer_id: &str,
    data_root: &Path,
) {
    let Ok(candidates) = reader.dispatch_candidates(READ_TIMEOUT) else {
        return;
    };
    if candidates.is_empty() {
        return;
    }
    let Ok(occupancy) = reader.occupancy(READ_TIMEOUT) else {
        return;
    };
    let settings = registry.load_settings();
    let limits = limits_from_settings(&settings);
    let Ok(plan) = plan_dispatch(
        &candidates,
        &occupancy,
        SchedulerPolicy {
            limits,
            ..SchedulerPolicy::default()
        },
        now_us(),
    ) else {
        return;
    };
    for planned in plan.dispatch {
        let _ = dispatch_one(
            reader,
            writer,
            registry,
            consumer_id,
            data_root,
            &planned.task_id,
            planned.generation,
            &planned.adapter_instance_id,
            limits,
        );
    }
}

fn limits_from_settings(settings: &crate::settings::SettingsDocument) -> SchedulerLimits {
    let concurrency = settings
        .settings
        .get("concurrency")
        .and_then(Value::as_object);
    let global = concurrency
        .and_then(|map| map.get("global"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(SchedulerLimits::DEFAULT.global);
    let per_adapter = concurrency
        .and_then(|map| map.get("per_adapter"))
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .unwrap_or(SchedulerLimits::DEFAULT.per_adapter);
    SchedulerLimits {
        global,
        per_adapter,
    }
    .validate()
    .unwrap_or(SchedulerLimits::DEFAULT)
}

fn dispatch_one(
    reader: &ReaderPool,
    writer: &WriterHandle,
    registry: &AdapterRegistry,
    consumer_id: &str,
    data_root: &Path,
    task_id: &str,
    generation: i64,
    adapter_instance_id: &str,
    limits: SchedulerLimits,
) -> Result<(), String> {
    let admission = registry
        .list_admissions()
        .into_iter()
        .find(|record| record.adapter_instance_id == adapter_instance_id)
        .ok_or_else(|| "adapter disappeared".to_owned())?;
    if !matches!(admission.status, AdmissionStatus::Enabled) {
        fail_task(
            writer,
            consumer_id,
            task_id,
            generation,
            "adapter is not enabled",
        );
        return Err("adapter not enabled".into());
    }
    let request = reader
        .task_request(task_id, READ_TIMEOUT)
        .map_err(|_| "task request unavailable".to_owned())?;
    let params: Value = serde_json::from_slice(&request.bytes)
        .map_err(|_| "task request is not json".to_owned())?;
    let objective = params
        .get("objective")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let workspace = params
        .get("workspace")
        .and_then(Value::as_object)
        .ok_or_else(|| "workspace missing".to_owned())?;
    let workspace_path = workspace
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or(".")
        .to_owned();
    let quality = params
        .get("quality")
        .and_then(Value::as_str)
        .and_then(|value| Quality::parse(value).ok())
        .unwrap_or(Quality::Standard);
    let effort = params
        .get("effort")
        .and_then(Value::as_str)
        .and_then(|value| Effort::parse(value).ok())
        .unwrap_or(Effort::Medium);
    let timeout = params
        .get("timeout_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(300);
    let cwd = PathBuf::from(&workspace_path);
    let cwd = if cwd.is_dir() {
        cwd
    } else {
        data_root.to_path_buf()
    };
    let executable = AdapterRegistry::executable_for(&admission)
        .ok_or_else(|| "executable missing".to_owned())?;
    let spec = AttemptSpec {
        effect_profile: params
            .get("effect_profile")
            .and_then(Value::as_str)
            .unwrap_or("READ_ONLY")
            .to_owned(),
        isolation_level: "NONE".into(),
        retry_class: "NEVER".into(),
        adapter_instance_id: adapter_instance_id.to_owned(),
        adapter_version: admission.executable_version.clone(),
        config_version: 1,
        config_digest: config_digest_from_instance(adapter_instance_id),
        worktree_id: None,
    };
    let claimed = writer
        .claim_dispatch_slot(
            format!("claim:{task_id}:{generation}"),
            task_id,
            generation,
            spec,
            limits,
            now_us(),
        )
        .map_err(|error| format!("claim failed: {error}"))?;
    let DispatchOutcome::Dispatched(attempt) = claimed else {
        return Ok(());
    };
    spawn_follow_console(task_id);
    let plan = spawn_plan(
        &admission,
        &executable,
        &objective,
        &workspace_path,
        quality,
        effort,
    )
    .inspect_err(|_| {
        fail_task(
            writer,
            consumer_id,
            task_id,
            generation,
            "adapter spawn plan failed",
        );
    })?;
    let supervisor = ProcessSupervisor::new(writer.clone());
    let started = supervisor.spawn(
        SpawnRequest {
            task_id: task_id.to_owned(),
            generation,
            attempt_id: attempt.attempt_id,
            executable: plan.executable,
            arguments: plan.arguments,
            env_allowlist: Vec::new(),
            extra_env: extra_env(admission.adapter, &registry.load_settings()),
            current_dir: Some(cwd),
            data_root: data_root.to_path_buf(),
            spool_quota_bytes: 0,
            now_us: now_us(),
            consumer_id: consumer_id.to_owned(),
        },
        ResumeGate::Resume,
    );
    let mut live = match started {
        Ok(SpawnOutcome::Started(live)) => *live,
        Ok(SpawnOutcome::AbortedBeforeResume { .. }) => {
            fail_task(writer, consumer_id, task_id, generation, "spawn aborted");
            return Err("spawn aborted".into());
        }
        Err(error) => {
            fail_task(
                writer,
                consumer_id,
                task_id,
                generation,
                "provider process failed to start",
            );
            return Err(format!("spawn failed: {error}"));
        }
    };
    drive_attempt(
        writer,
        consumer_id,
        &mut live,
        admission.adapter,
        &objective,
        plan.acp_auth,
        plan.acp.then_some(plan.workspace.as_str()),
        Duration::from_secs(timeout.max(1)),
        task_id,
        generation,
    );
    Ok(())
}

struct PlannedSpawn {
    executable: PathBuf,
    arguments: Vec<OsString>,
    acp_auth: Option<&'static str>,
    acp: bool,
    workspace: String,
}

fn spawn_plan(
    admission: &AdmissionRecord,
    executable: &Path,
    objective: &str,
    workspace: &str,
    quality: Quality,
    effort: Effort,
) -> Result<PlannedSpawn, String> {
    match admission.adapter {
        "claude" => {
            let plan = claude::plan_claude_spawn(
                executable,
                admission,
                &ClaudeLaunchRequest {
                    objective: objective.to_owned(),
                    quality,
                    effort,
                    session_id: None,
                },
                &json!({}),
            )
            .map_err(|error| error.to_string())?;
            Ok(PlannedSpawn {
                executable: plan.executable,
                arguments: plan.arguments,
                acp_auth: None,
                acp: false,
                workspace: workspace.to_owned(),
            })
        }
        "grok" => {
            let selection = grok::select_grok_transport(admission, false)
                .or_else(|_| grok::select_grok_transport(admission, true))
                .map_err(|error| error.to_string())?;
            let plan = grok::plan_grok_spawn(
                executable,
                admission,
                &GrokLaunchRequest {
                    objective: objective.to_owned(),
                    quality,
                    effort,
                    workspace: workspace.to_owned(),
                    session_id: None,
                },
                selection,
                &json!({}),
            )
            .map_err(|error| error.to_string())?;
            let acp = matches!(selection, GrokTransportSelection::Acp);
            Ok(PlannedSpawn {
                executable: plan.executable,
                arguments: plan.arguments,
                acp_auth: acp.then_some("cached_token"),
                acp,
                workspace: workspace.to_owned(),
            })
        }
        "kimi" => {
            let selection = kimi::select_kimi_transport(admission, false)
                .or_else(|_| kimi::select_kimi_transport(admission, true))
                .map_err(|error| error.to_string())?;
            let plan = kimi::plan_kimi_spawn(
                executable,
                admission,
                &KimiLaunchRequest {
                    objective: objective.to_owned(),
                    quality,
                    effort,
                    workspace: workspace.to_owned(),
                    session_id: None,
                },
                selection,
                &json!({}),
            )
            .map_err(|error| error.to_string())?;
            Ok(PlannedSpawn {
                executable: plan.executable,
                arguments: plan.arguments,
                acp_auth: None,
                acp: matches!(selection, KimiTransportSelection::Acp),
                workspace: workspace.to_owned(),
            })
        }
        _ => Err("unknown adapter".into()),
    }
}

fn spawn_follow_console(task_id: &str) {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let mut command = std::process::Command::new(exe);
    command.args(["follow", "--install-slot", "stable", "--task-id", task_id]);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
        command.creation_flags(CREATE_NEW_CONSOLE);
    }
    let _ = command.spawn();
}

fn extra_env(
    adapter: &str,
    settings: &crate::settings::SettingsDocument,
) -> Vec<(OsString, OsString)> {
    if !matches!(adapter, "grok" | "kimi" | "claude") {
        return Vec::new();
    }
    let Some(proxy) = resolved_forward_proxy(settings) else {
        return Vec::new();
    };
    let no_proxy = std::env::var("NO_PROXY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "localhost,127.0.0.1,::1".into());
    let mut pairs = vec![
        ("HTTP_PROXY", proxy.clone()),
        ("HTTPS_PROXY", proxy.clone()),
        ("ALL_PROXY", proxy),
        ("NO_PROXY", no_proxy.clone()),
    ];
    if adapter == "grok" {
        pairs.push(("GROK_WEB_FETCH_PROXY", no_proxy));
    }
    pairs
        .into_iter()
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect()
}

fn resolved_forward_proxy(settings: &crate::settings::SettingsDocument) -> Option<String> {
    env_nonempty("GROK_FORWARD_PROXY")
        .or_else(|| {
            settings
                .settings
                .get("forward_proxy")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        })
        .or_else(|| env_nonempty("HTTPS_PROXY"))
        .or_else(|| env_nonempty("HTTP_PROXY"))
        .or_else(|| env_nonempty("ALL_PROXY"))
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn drive_attempt(
    writer: &WriterHandle,
    consumer_id: &str,
    live: &mut SupervisedAttempt,
    adapter: &str,
    objective: &str,
    acp_auth: Option<&str>,
    acp_workspace: Option<&str>,
    timeout: Duration,
    task_id: &str,
    generation: i64,
) {
    let spool = live.stdout_spool_path().to_path_buf();
    if let Some(workspace) = acp_workspace
        && adapter != "claude"
        && let Err(reason) = drive_acp(
            live, &spool, objective, workspace, acp_auth, timeout, writer, task_id, generation,
        )
    {
        persist_warning(writer, task_id, generation, &reason);
        fail_task(writer, consumer_id, task_id, generation, &reason);
        let _ = live.cancel("handshake", Duration::from_secs(2), now_us());
        return;
    }
    let hard_deadline = Instant::now() + timeout.saturating_mul(2);
    let mut idle_deadline = Instant::now() + timeout;
    let mut consumed = 0_usize;
    let mut spool_len = 0_u64;
    let mut activity = ActivityBuffer::default();
    loop {
        match persist_new_frames(
            writer,
            adapter,
            &spool,
            &mut consumed,
            &mut activity,
            task_id,
            generation,
        ) {
            FrameOutcome::Continue => {}
            FrameOutcome::Failed(reason) => {
                fail_task(writer, consumer_id, task_id, generation, &reason);
                let _ = live.cancel("provider_error", Duration::from_secs(2), now_us());
                return;
            }
            FrameOutcome::Succeeded => {
                succeed_task(writer, consumer_id, task_id, generation);
                let _ = live.cancel("complete", Duration::from_secs(2), now_us());
                return;
            }
        }
        if let Ok(meta) = std::fs::metadata(&spool)
            && meta.len() > spool_len
        {
            spool_len = meta.len();
            idle_deadline = Instant::now() + timeout;
        }
        match live.wait(SPOOL_POLL) {
            Ok(Some(code)) => {
                match persist_new_frames(
                    writer,
                    adapter,
                    &spool,
                    &mut consumed,
                    &mut activity,
                    task_id,
                    generation,
                ) {
                    FrameOutcome::Failed(reason) => {
                        fail_task(writer, consumer_id, task_id, generation, &reason);
                        return;
                    }
                    FrameOutcome::Succeeded => {
                        succeed_task(writer, consumer_id, task_id, generation);
                        return;
                    }
                    FrameOutcome::Continue => {
                        activity.flush(writer, task_id, generation);
                        let _ = live.finalize_exit(code, now_us());
                        return;
                    }
                }
            }
            Ok(None) => {
                if Instant::now() >= idle_deadline || Instant::now() >= hard_deadline {
                    persist_warning(writer, task_id, generation, "provider timed out");
                    fail_task(
                        writer,
                        consumer_id,
                        task_id,
                        generation,
                        "provider timed out",
                    );
                    let _ = live.cancel("timeout", Duration::from_secs(2), now_us());
                    return;
                }
            }
            Err(_) => {
                persist_warning(writer, task_id, generation, "provider wait failed");
                fail_task(
                    writer,
                    consumer_id,
                    task_id,
                    generation,
                    "provider wait failed",
                );
                return;
            }
        }
    }
}

fn drive_acp(
    live: &mut SupervisedAttempt,
    spool: &Path,
    objective: &str,
    workspace: &str,
    auth_method_id: Option<&str>,
    timeout: Duration,
    writer: &WriterHandle,
    task_id: &str,
    generation: i64,
) -> Result<(), String> {
    let mut next_id = 1_u64;
    let initialize_id = next_id;
    next_id += 1;
    live.write_stdin_line(
        &acp::encode_request(
            initialize_id,
            acp::METHOD_INITIALIZE,
            &json!({
                "protocolVersion": 1,
                "clientCapabilities": {
                    "fs": { "readTextFile": false, "writeTextFile": false },
                    "terminal": false
                }
            }),
        )
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    wait_result_frame(spool, initialize_id, timeout)?;
    persist_warning(writer, task_id, generation, "adapter handshake started");
    if let Some(method_id) = auth_method_id {
        let auth_id = next_id;
        next_id += 1;
        live.write_stdin_line(
            &acp::encode_request(
                auth_id,
                acp::METHOD_AUTHENTICATE,
                &json!({ "methodId": method_id }),
            )
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let _ = wait_result_frame(spool, auth_id, timeout);
    }
    let session_id = next_id;
    next_id += 1;
    live.write_stdin_line(
        &acp::encode_request(
            session_id,
            acp::METHOD_SESSION_NEW,
            &json!({ "cwd": workspace, "mcpServers": [] }),
        )
        .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let session = wait_result_frame(spool, session_id, timeout)?;
    let session_key = session
        .pointer("/result/sessionId")
        .and_then(Value::as_str)
        .ok_or_else(|| "session/new lacked sessionId".to_owned())?
        .to_owned();
    let prompt_id = next_id;
    live.write_stdin_line(
        &acp::encode_session_prompt(prompt_id, &session_key, objective)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn complete_spool_lines(unread: &str) -> (Vec<&str>, usize) {
    let mut consumed = 0_usize;
    let mut lines = Vec::new();
    for line in unread.split_inclusive('\n') {
        if !line.ends_with('\n') {
            break;
        }
        consumed += line.len();
        let line = line.trim_end_matches(['\n', '\r']);
        if !line.trim().is_empty() {
            lines.push(line);
        }
    }
    (lines, consumed)
}

fn spool_frames(spool: &Path) -> Vec<Value> {
    let Ok(bytes) = std::fs::read(spool) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&bytes);
    let (lines, _) = complete_spool_lines(&text);
    lines
        .into_iter()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

fn wait_result_frame(spool: &Path, id: u64, timeout: Duration) -> Result<Value, String> {
    let started = Instant::now();
    let want = i64::try_from(id).unwrap_or(0);
    loop {
        for frame in spool_frames(spool) {
            if frame.get("id").and_then(Value::as_i64) == Some(want)
                && frame.get("result").is_some()
            {
                return Ok(frame);
            }
        }
        if started.elapsed() > timeout {
            return Err(format!("timed out waiting for ACP id {id}"));
        }
        thread::sleep(SPOOL_POLL);
    }
}

#[derive(Default)]
struct ActivityBuffer {
    channel: Option<&'static str>,
    text: String,
}

impl ActivityBuffer {
    fn push_text(&mut self, writer: &WriterHandle, task_id: &str, generation: i64, text: &str) {
        self.append(writer, task_id, generation, "text", text);
    }

    fn push_thinking(&mut self, writer: &WriterHandle, task_id: &str, generation: i64, text: &str) {
        self.append(writer, task_id, generation, "thinking", text);
    }

    fn append(
        &mut self,
        writer: &WriterHandle,
        task_id: &str,
        generation: i64,
        channel: &'static str,
        text: &str,
    ) {
        if self.channel.is_some_and(|current| current != channel) {
            self.flush(writer, task_id, generation);
        }
        self.channel = Some(channel);
        self.text.push_str(text);
        if self.text.len() >= 240 {
            self.flush(writer, task_id, generation);
        }
    }

    fn flush(&mut self, writer: &WriterHandle, task_id: &str, generation: i64) {
        let Some(channel) = self.channel.take() else {
            return;
        };
        let text = std::mem::take(&mut self.text);
        if text.trim().is_empty() {
            return;
        }
        match channel {
            "thinking" => persist_activity(
                writer,
                task_id,
                generation,
                "warning",
                json!({ "warning": format!("thinking: {text}") }),
            ),
            _ => persist_activity(
                writer,
                task_id,
                generation,
                "text_delta",
                json!({ "text": text }),
            ),
        }
    }
}

fn persist_activity(
    writer: &WriterHandle,
    task_id: &str,
    generation: i64,
    kind: &str,
    payload: serde_json::Value,
) {
    let digest = format!("{:x}", Sha256::digest(payload.to_string().as_bytes()));
    let _ = writer.record_adapter_event(
        format!("evt:{task_id}:{generation}:{kind}:{digest}"),
        task_id,
        generation,
        kind,
        payload,
        now_us(),
    );
}

enum FrameOutcome {
    Continue,
    Failed(String),
    Succeeded,
}

fn persist_new_frames(
    writer: &WriterHandle,
    adapter: &str,
    spool: &Path,
    consumed: &mut usize,
    activity: &mut ActivityBuffer,
    task_id: &str,
    generation: i64,
) -> FrameOutcome {
    let Ok(bytes) = std::fs::read(spool) else {
        return FrameOutcome::Continue;
    };
    let text = String::from_utf8_lossy(&bytes);
    if text.len() < *consumed {
        *consumed = 0;
    }
    let unread = &text[*consumed..];
    let (lines, delta) = complete_spool_lines(unread);
    *consumed += delta;
    for line in lines {
        let events = match adapter {
            "claude" => claude::decode_stream_json_line(line),
            "kimi" => kimi::decode_kimi_line(line),
            _ => grok::decode_grok_line(line),
        };
        for event in events {
            match event.kind {
                NormalizedKind::TextDelta { text } => {
                    activity.push_text(writer, task_id, generation, &text);
                }
                NormalizedKind::Warning { warning } if warning.starts_with("thinking: ") => {
                    activity.push_thinking(
                        writer,
                        task_id,
                        generation,
                        warning.trim_start_matches("thinking: "),
                    );
                }
                NormalizedKind::Warning { warning }
                    if warning == "Adapter reported a deterministic warning." => {}
                NormalizedKind::Warning { warning } => {
                    activity.flush(writer, task_id, generation);
                    persist_activity(
                        writer,
                        task_id,
                        generation,
                        "warning",
                        json!({ "warning": warning }),
                    );
                }
                NormalizedKind::ToolProposal {
                    operation_digest,
                    interaction_id,
                } => {
                    activity.flush(writer, task_id, generation);
                    persist_activity(
                        writer,
                        task_id,
                        generation,
                        "tool_proposal",
                        json!({
                            "operation_digest": operation_digest,
                            "interaction_id": interaction_id
                        }),
                    );
                    let title = event
                        .raw
                        .pointer("/params/update/title")
                        .or_else(|| event.raw.pointer("/update/title"))
                        .or_else(|| event.raw.pointer("/message/content/0/name"))
                        .and_then(Value::as_str)
                        .unwrap_or("tool");
                    persist_activity(
                        writer,
                        task_id,
                        generation,
                        "warning",
                        json!({ "warning": format!("tool: {title}") }),
                    );
                }
                NormalizedKind::ProtocolError { code, message } => {
                    activity.flush(writer, task_id, generation);
                    persist_activity(
                        writer,
                        task_id,
                        generation,
                        "protocol_error",
                        json!({ "code": code, "message": message }),
                    );
                    if code.starts_with("jsonrpc_") || code == "provider_http" {
                        return FrameOutcome::Failed(message);
                    }
                }
                NormalizedKind::Terminal { state } => {
                    activity.flush(writer, task_id, generation);
                    return match state {
                        crate::domain::TaskState::Succeeded => FrameOutcome::Succeeded,
                        crate::domain::TaskState::Failed | crate::domain::TaskState::Cancelled => {
                            FrameOutcome::Failed(format!("provider stopped: {}", state.as_str()))
                        }
                        _ => FrameOutcome::Continue,
                    };
                }
                NormalizedKind::Usage {
                    input_tokens,
                    output_tokens,
                } => {
                    activity.flush(writer, task_id, generation);
                    persist_activity(
                        writer,
                        task_id,
                        generation,
                        "usage",
                        json!({
                            "input_tokens": input_tokens,
                            "output_tokens": output_tokens
                        }),
                    );
                }
                _ => {}
            }
        }
    }
    activity.flush(writer, task_id, generation);
    FrameOutcome::Continue
}

fn persist_warning(writer: &WriterHandle, task_id: &str, generation: i64, warning: &str) {
    let _ = writer.record_adapter_event(
        format!("warn:{task_id}:{generation}:{warning}"),
        task_id,
        generation,
        "warning",
        json!({ "warning": warning }),
        now_us(),
    );
}

fn succeed_task(writer: &WriterHandle, consumer_id: &str, task_id: &str, generation: i64) {
    let _ = writer.finalize(
        consumer_id,
        format!("ok:{task_id}:{generation}"),
        format!("ok:{task_id}:{generation}").into_bytes(),
        task_id,
        generation,
        "SUCCEEDED",
        format!("{:x}", Sha256::digest(b"succeeded")),
        now_us(),
    );
}

fn fail_task(
    writer: &WriterHandle,
    consumer_id: &str,
    task_id: &str,
    generation: i64,
    reason: &str,
) {
    persist_warning(writer, task_id, generation, reason);
    let _ = writer.finalize(
        consumer_id,
        format!("fail:{task_id}:{generation}"),
        format!("fail:{task_id}:{generation}:{reason}").into_bytes(),
        task_id,
        generation,
        "FAILED",
        format!("{:x}", Sha256::digest(reason.as_bytes())),
        now_us(),
    );
}

fn config_digest_from_instance(adapter_instance_id: &str) -> String {
    adapter_instance_id
        .rsplit(':')
        .next()
        .filter(|value| value.len() == 64)
        .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000")
        .to_owned()
}

fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_micros()).unwrap_or(0)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::default_settings;

    #[test]
    fn extra_env_is_empty_for_non_cli_adapters() {
        let settings = default_settings();
        assert!(extra_env("luna", &settings).is_empty());
        assert!(extra_env("pi", &settings).is_empty());
    }

    #[test]
    fn complete_spool_lines_hold_an_incomplete_tail() {
        let (lines, consumed) = complete_spool_lines("{\"a\":1}\n{\"b\":");
        assert_eq!(lines, vec!["{\"a\":1}"]);
        assert_eq!(consumed, "{\"a\":1}\n".len());
        let (none, zero) = complete_spool_lines("{\"incomplete\"");
        assert!(none.is_empty());
        assert_eq!(zero, 0);
    }

    #[test]
    fn extra_env_forwards_settings_proxy_to_grok() {
        let mut settings = default_settings();
        settings
            .settings
            .insert("forward_proxy".into(), json!("http://127.0.0.1:10808"));
        let env = extra_env("grok", &settings);
        assert!(
            env.iter()
                .any(|(key, value)| key == "HTTPS_PROXY" && value == "http://127.0.0.1:10808")
                || env.iter().any(|(key, _)| key == "HTTPS_PROXY"),
            "grok spawn must receive an HTTPS proxy, got {env:?}"
        );
    }
}
