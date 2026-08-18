//! Supervisor + fake-adapter crash/retry matrix.
//!
//! Cargo filters `crash_matrix` and `retry` must keep covering every cell in
//! `tests/process-fixtures/crash-matrix/required-cases.txt`. Automatic retry is
//! allowed only for `SAFE_PRE_DISPATCH` / `SAFE_PROVEN_NO_EFFECT`. Every
//! ambiguous post-dispatch case is `NEEDS_ATTENTION`.

#![allow(clippy::missing_panics_doc, clippy::too_many_lines)]

use crate::EffectClass;
use crate::ErrorCode;
use crate::LifecycleEvidence;
use crate::RetryClass;
use crate::approvals::{AppliedInteraction, ApprovalOrchestrator, InteractionAnswer};
use crate::canonicalize;
use crate::classify_retry;
use crate::classify_retry_for_attempt;
use crate::domain::{
    DispatchPhase, EffectProfile, InteractionCapabilityClass, InteractionResponseKind,
    RecoveryDecision,
};
use crate::reader::ReaderPool;
use crate::scheduler::{AdapterInstanceId, SchedulerLimits};
use crate::storage::{Attempt, AttemptSpec, DispatchOutcome, Interaction, StorageError};
use crate::supervisor::{
    CancelOutcome, ProcessSupervisor, ResumeGate, SpawnOutcome, SpawnRequest, SupervisedAttempt,
    SupervisorError,
};
use crate::writer::WriterHandle;
use mesh_win32::{process_id_is_active, process_identity_is_live};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::thread;
use std::time::Duration;

const DIGEST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const OPERATION_DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const POLICY_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CONFIG_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const REQUIRED_CASES_RELATIVE: &str =
    "../../tests/process-fixtures/crash-matrix/required-cases.txt";

const REQUIRED_CASES: &[&str] = &[
    "crash_matrix_required_case_catalog_matches_fixture",
    "crash_matrix_retry_classification_only_safe_pre_dispatch_or_proven_no_effect",
    "crash_matrix_abort_before_resume_is_retry_safe_no_marker",
    "crash_matrix_process_started_does_not_auto_retry",
    "crash_matrix_runtime_crash_needs_attention_no_retry",
    "crash_matrix_unknown_exit_needs_attention_no_retry",
    "crash_matrix_lost_session_needs_attention_no_retry",
    "crash_matrix_current_directory_after_start_needs_attention_no_retry",
    "crash_matrix_forwarded_approval_then_crash_needs_attention_no_retry",
    "crash_matrix_job_tree_kill_child_and_grandchild",
    "crash_matrix_cancel_committed_beats_later_exit_zero_no_retry",
];

fn aid() -> String {
    AdapterInstanceId::new("fake", "default", "default", DIGEST)
        .expect("adapter id")
        .encode()
}

fn default_spec() -> AttemptSpec {
    AttemptSpec {
        adapter_instance_id: aid(),
        config_digest: DIGEST.into(),
        ..AttemptSpec::default()
    }
}

fn current_directory_spec() -> AttemptSpec {
    AttemptSpec {
        effect_profile: EffectProfile::CurrentDirectory.as_str().into(),
        isolation_level: "BEST_EFFORT".into(),
        retry_class: "AMBIGUOUS_AFTER_DISPATCH".into(),
        adapter_instance_id: aid(),
        config_digest: DIGEST.into(),
        ..AttemptSpec::default()
    }
}

fn fake_adapter_exe() -> PathBuf {
    static EXE: OnceLock<PathBuf> = OnceLock::new();
    EXE.get_or_init(locate_or_build_fake_adapter).clone()
}

fn locate_or_build_fake_adapter() -> PathBuf {
    if let Some(path) = find_fake_adapter() {
        return path;
    }
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    let isolated = workspace.join("target").join("mesh-fake-adapter-test");
    let cargo = std::env::var_os("CARGO").map_or_else(|| PathBuf::from("cargo"), PathBuf::from);
    let status = Command::new(&cargo)
        .args(["build", "-p", "mesh-fake-adapter", "--offline"])
        .env("CARGO_TARGET_DIR", &isolated)
        .current_dir(&workspace)
        .status()
        .expect("spawn cargo to build mesh-fake-adapter");
    if !status.success() {
        let status = Command::new(cargo)
            .args(["build", "-p", "mesh-fake-adapter"])
            .env("CARGO_TARGET_DIR", &isolated)
            .current_dir(&workspace)
            .status()
            .expect("spawn cargo online");
        assert!(status.success(), "failed to build mesh-fake-adapter");
    }
    find_under(&isolated).expect("built mesh-fake-adapter")
}

fn find_fake_adapter() -> Option<PathBuf> {
    let name = "mesh-fake-adapter.exe";
    if let Ok(current) = std::env::current_exe() {
        let mut dir = current.parent()?.to_path_buf();
        for _ in 0..5 {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
            dir.pop();
        }
    }
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for root in [
        workspace.join("target"),
        workspace.join("target").join("mesh-fake-adapter-test"),
    ] {
        if let Some(path) = find_under(&root) {
            return Some(path);
        }
    }
    None
}

fn find_under(root: &Path) -> Option<PathBuf> {
    let name = "mesh-fake-adapter.exe";
    for profile in ["debug", "release"] {
        let candidate = root.join(profile).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn setup() -> (
    tempfile::TempDir,
    WriterHandle,
    ReaderPool,
    ProcessSupervisor,
) {
    let root = tempfile::tempdir().expect("tempdir");
    let writer =
        WriterHandle::start_portable(root.path().to_path_buf(), "install", 1).expect("writer");
    let reader = ReaderPool::open(root.path()).expect("reader");
    let supervisor = ProcessSupervisor::new(writer.clone());
    (root, writer, reader, supervisor)
}

fn submit_and_claim(
    writer: &WriterHandle,
    task_id: &str,
    spec: AttemptSpec,
    now_us: i64,
) -> Attempt {
    writer
        .submit_for_scheduling(
            "c",
            "submit",
            format!("k-{task_id}"),
            format!("body-{task_id}").into_bytes(),
            task_id,
            None,
            0,
            Some(&aid()),
            now_us,
        )
        .expect("submit");
    match writer
        .claim_dispatch_slot(
            format!("claim-{task_id}"),
            task_id,
            0,
            spec,
            SchedulerLimits::DEFAULT,
            now_us + 1,
        )
        .expect("claim")
    {
        DispatchOutcome::Dispatched(attempt) => attempt,
        DispatchOutcome::Blocked(blocked) => panic!("blocked: {blocked:?}"),
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_script(
    supervisor: &ProcessSupervisor,
    writer: &WriterHandle,
    root: &Path,
    task_id: &str,
    script: &str,
    gate: ResumeGate,
    spec: AttemptSpec,
    cwd: Option<PathBuf>,
) -> SpawnOutcome {
    let attempt = submit_and_claim(writer, task_id, spec, 10);
    let request = SpawnRequest {
        task_id: task_id.to_owned(),
        generation: 0,
        attempt_id: attempt.attempt_id,
        executable: fake_adapter_exe(),
        arguments: vec![OsString::from("--json"), OsString::from(script)],
        env_allowlist: Vec::new(),
        extra_env: Vec::new(),
        current_dir: cwd,
        data_root: root.to_path_buf(),
        spool_quota_bytes: 0,
        now_us: 20,
        consumer_id: "c".into(),
    };
    supervisor.spawn(request, gate).expect("spawn")
}

fn snapshot_state(reader: &ReaderPool, task_id: &str) -> (String, i64, Option<String>) {
    let snapshot = reader
        .snapshot(task_id, "c", Duration::from_secs(2))
        .expect("snapshot");
    let state = snapshot.task.value["state"]
        .as_str()
        .expect("state")
        .to_owned();
    let generation = snapshot.task.value["generation"]
        .as_i64()
        .expect("generation");
    let phase = snapshot.attempt.map(|attempt| attempt.dispatch_phase);
    (state, generation, phase)
}

fn retry_event_persisted(reader: &ReaderPool, task_id: &str) -> bool {
    let Ok(page) = reader.public_events_after(task_id, 0, 200, Duration::from_secs(2), Some("c"))
    else {
        return false;
    };
    page.events
        .iter()
        .any(|event| event.value["event_type"] == "retry_scheduled")
}

fn retry_was_scheduled(reader: &ReaderPool, task_id: &str) -> bool {
    let (state, generation, _) = snapshot_state(reader, task_id);
    state == "RETRY_WAIT" || generation > 0 || retry_event_persisted(reader, task_id)
}

fn assert_retry_scheduled(reader: &ReaderPool, task_id: &str) {
    let (state, generation, _) = snapshot_state(reader, task_id);
    assert_eq!(state, "RETRY_WAIT", "safe pre-dispatch must schedule retry");
    assert_eq!(generation, 1, "safe retry must advance generation");
    assert!(
        retry_event_persisted(reader, task_id),
        "retry_scheduled must be persisted for the safe cell"
    );
}

fn assert_needs_attention_without_retry(
    reader: &ReaderPool,
    task_id: &str,
    expected_phase: Option<&str>,
) {
    let (state, generation, phase) = snapshot_state(reader, task_id);
    if let Some(expected) = expected_phase {
        assert_eq!(
            phase.as_deref(),
            Some(expected),
            "ambiguous cell must keep the post-dispatch phase"
        );
    }
    assert_eq!(state, "NEEDS_ATTENTION");
    assert_eq!(generation, 0, "ambiguous recovery must not bump generation");
    assert!(
        !retry_was_scheduled(reader, task_id),
        "retry must not be scheduled after an ambiguous post-dispatch crash"
    );
}

fn started(outcome: SpawnOutcome) -> Box<SupervisedAttempt> {
    match outcome {
        SpawnOutcome::Started(attempt) => attempt,
        SpawnOutcome::AbortedBeforeResume { .. } => panic!("must resume"),
    }
}

fn wait_for_marker(path: &Path) {
    for _ in 0..100 {
        if path.is_file() {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("adapter marker was never written after resume");
}

fn wait_for_grandchild_pid(spool: &Path) -> u32 {
    for _ in 0..100 {
        if let Ok(text) = fs::read_to_string(spool)
            && let Some(pid) = text.lines().find_map(parse_grandchild_pid)
        {
            return pid;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("grandchild pid was not observed in the stdout spool");
}

fn parse_grandchild_pid(line: &str) -> Option<u32> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    if value.get("type")?.as_str()? == "spawn_grandchild" {
        value
            .get("pid")?
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok())
    } else {
        None
    }
}

fn wait_for_spool_line(spool: &Path, needle: &str) {
    for _ in 0..200 {
        if let Ok(text) = fs::read_to_string(spool)
            && text.contains(needle)
        {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("stdout spool never contained {needle}");
}

fn interaction_response_command(
    command_key: &str,
    task_id: &str,
    interaction_id: &str,
    generation: i64,
    nonce: &str,
    response: &serde_json::Value,
) -> (Vec<u8>, Vec<u8>) {
    let response_bytes = canonicalize(response)
        .expect("interaction response must be canonical")
        .into_bytes();
    let command = serde_json::json!({
        "version": 1,
        "kind": "command",
        "action": "interaction_response",
        "command_key": command_key,
        "task_id": task_id,
        "interaction_id": interaction_id,
        "generation": generation,
        "operation_digest": OPERATION_DIGEST,
        "policy_digest": POLICY_DIGEST,
        "config_digest": CONFIG_DIGEST,
        "nonce": nonce,
        "response": response,
    });
    let command_bytes = canonicalize(&command)
        .expect("interaction command must be canonical")
        .into_bytes();
    (command_bytes, response_bytes)
}

fn answer_for(interaction: &Interaction, command_key: &str, now_us: i64) -> InteractionAnswer {
    let response = serde_json::json!({"kind":"approve"});
    let (command, bytes) = interaction_response_command(
        command_key,
        &interaction.task_id,
        &interaction.interaction_id,
        interaction.generation,
        &interaction.nonce,
        &response,
    );
    InteractionAnswer {
        task_id: interaction.task_id.clone(),
        command_key: command_key.into(),
        canonical_command_bytes: command,
        interaction_id: interaction.interaction_id.clone(),
        nonce: interaction.nonce.clone(),
        generation: interaction.generation,
        operation_digest: OPERATION_DIGEST.into(),
        policy_digest: POLICY_DIGEST.into(),
        config_digest: CONFIG_DIGEST.into(),
        response_kind: InteractionResponseKind::Approve,
        canonical_response_bytes: bytes,
        now_us,
        spec: default_spec(),
        limits: SchedulerLimits::DEFAULT,
    }
}

fn catalog_names_from_fixture() -> Vec<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(REQUIRED_CASES_RELATIVE);
    fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing crash-matrix catalog at {}", path.display()))
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect()
}

#[test]
fn crash_matrix_required_case_catalog_matches_fixture() {
    let catalog = catalog_names_from_fixture();
    let expected: Vec<&str> = catalog.iter().map(String::as_str).collect();
    assert_eq!(expected, REQUIRED_CASES);
}

#[test]
fn crash_matrix_retry_classification_only_safe_pre_dispatch_or_proven_no_effect() {
    const EFFECTS: [EffectClass; 3] = [
        EffectClass::NoEffect,
        EffectClass::PossibleEffect,
        EffectClass::UnknownEffect,
    ];
    const EVIDENCE: [LifecycleEvidence; 4] = [
        LifecycleEvidence::BeforeProcessCreation,
        LifecycleEvidence::ProcessDeadNoEffectProof,
        LifecycleEvidence::AfterProcessCreation,
        LifecycleEvidence::Unknown,
    ];
    for effect in EFFECTS {
        for evidence in EVIDENCE {
            let class = classify_retry(ErrorCode::AdapterUnavailable, effect, evidence);
            let auto_retry = matches!(
                class,
                RetryClass::SafePreDispatch | RetryClass::SafeProvenNoEffect
            );
            let expected_auto = matches!(evidence, LifecycleEvidence::BeforeProcessCreation)
                || matches!(
                    (effect, evidence),
                    (
                        EffectClass::NoEffect,
                        LifecycleEvidence::ProcessDeadNoEffectProof
                    )
                );
            assert_eq!(
                auto_retry, expected_auto,
                "{effect:?} + {evidence:?} classified as {class:?}"
            );
        }
    }
    assert_eq!(
        classify_retry(
            ErrorCode::ValidationFailed,
            EffectClass::NoEffect,
            LifecycleEvidence::BeforeProcessCreation
        ),
        RetryClass::DeterministicFailure
    );
    assert_eq!(
        classify_retry(
            ErrorCode::ResponseUnknown,
            EffectClass::UnknownEffect,
            LifecycleEvidence::Unknown
        ),
        RetryClass::AmbiguousAfterDispatch
    );
    for evidence in [
        LifecycleEvidence::ProcessDeadNoEffectProof,
        LifecycleEvidence::AfterProcessCreation,
        LifecycleEvidence::Unknown,
    ] {
        assert_eq!(
            classify_retry_for_attempt(
                ErrorCode::AdapterUnavailable,
                EffectClass::NoEffect,
                evidence,
                EffectProfile::CurrentDirectory
            ),
            RetryClass::AmbiguousAfterDispatch,
            "CURRENT_DIRECTORY after start cannot be proven no-effect: {evidence:?}"
        );
    }
    assert_eq!(
        classify_retry_for_attempt(
            ErrorCode::AdapterUnavailable,
            EffectClass::UnknownEffect,
            LifecycleEvidence::BeforeProcessCreation,
            EffectProfile::CurrentDirectory
        ),
        RetryClass::SafePreDispatch
    );
    assert_eq!(
        classify_retry_for_attempt(
            ErrorCode::AdapterUnavailable,
            EffectClass::NoEffect,
            LifecycleEvidence::ProcessDeadNoEffectProof,
            EffectProfile::IsolatedWorktree
        ),
        RetryClass::SafeProvenNoEffect
    );
}

#[test]
fn crash_matrix_abort_before_resume_is_retry_safe_no_marker() {
    let (root, writer, reader, supervisor) = setup();
    let cwd = root.path().join("work");
    fs::create_dir_all(&cwd).expect("cwd");
    let marker = cwd.join("marker.txt");
    let outcome = spawn_script(
        &supervisor,
        &writer,
        root.path(),
        "cm-abort",
        r#"[{"type":"write_marker","path":"marker.txt"},{"type":"terminal","state":"SUCCEEDED"}]"#,
        ResumeGate::AbortBeforeResume,
        default_spec(),
        Some(cwd),
    );
    match outcome {
        SpawnOutcome::AbortedBeforeResume { receipt } => {
            assert!(!process_identity_is_live(&receipt).expect("live query"));
        }
        SpawnOutcome::Started(_) => panic!("must abort before resume"),
    }
    let (_, _, phase) = snapshot_state(&reader, "cm-abort");
    assert_eq!(phase.as_deref(), Some("SPAWN_PREPARED"));
    thread::sleep(Duration::from_millis(80));
    assert!(
        !marker.exists(),
        "adapter code must not run while the phase is still retry-safe"
    );
    let decisions = writer
        .reconcile_nonterminal("c", 80)
        .expect("reconcile abort");
    assert!(
        decisions
            .iter()
            .any(|(task_id, decision)| task_id == "cm-abort"
                && *decision == RecoveryDecision::RetrySafe),
        "SPAWN_PREPARED without resume must stay retry-safe: {decisions:?}"
    );
    assert_retry_scheduled(&reader, "cm-abort");
    let second = writer
        .reconcile_nonterminal("c", 81)
        .expect("reconcile abort again");
    assert!(
        second.is_empty(),
        "RETRY_WAIT must survive a second reconcile: {second:?}"
    );
    assert_retry_scheduled(&reader, "cm-abort");
    writer.shutdown().expect("shutdown");
}

#[test]
fn crash_matrix_process_started_does_not_auto_retry() {
    let (root, writer, reader, supervisor) = setup();
    let started = started(spawn_script(
        &supervisor,
        &writer,
        root.path(),
        "cm-started",
        r#"[{"type":"hang"}]"#,
        ResumeGate::Resume,
        default_spec(),
        None,
    ));
    let (_, _, phase) = snapshot_state(&reader, "cm-started");
    assert_eq!(phase.as_deref(), Some("PROCESS_STARTED"));
    drop(started);
    let forced = writer.schedule_safe_retry("force-retry-cm-started", "cm-started", 0, 200, 82);
    assert!(
        forced.is_err(),
        "PROCESS_STARTED must reject a forced safe retry: {forced:?}"
    );
    let decisions = writer
        .reconcile_nonterminal("c", 81)
        .expect("reconcile started");
    assert!(
        decisions.iter().any(|(task_id, decision)| {
            task_id == "cm-started" && *decision == RecoveryDecision::NeedsAttention
        }),
        "PROCESS_STARTED without resume proof must need attention: {decisions:?}"
    );
    assert_needs_attention_without_retry(&reader, "cm-started", Some("PROCESS_STARTED"));
    writer.shutdown().expect("shutdown");
}

#[test]
fn crash_matrix_runtime_crash_needs_attention_no_retry() {
    let (root, writer, reader, supervisor) = setup();
    let cwd = root.path().join("work");
    fs::create_dir_all(&cwd).expect("cwd");
    let marker = cwd.join("marker.txt");
    let mut live = started(spawn_script(
        &supervisor,
        &writer,
        root.path(),
        "cm-crash",
        r#"[{"type":"write_marker","path":"marker.txt"},{"type":"crash","code":17}]"#,
        ResumeGate::Resume,
        default_spec(),
        Some(cwd),
    ));
    assert_eq!(live.wait(Duration::from_secs(5)).expect("wait"), Some(17));
    wait_for_marker(&marker);
    drop(live);
    let decisions = writer
        .reconcile_nonterminal("c", 90)
        .expect("reconcile crash");
    assert!(
        decisions.iter().any(|(task_id, decision)| {
            task_id == "cm-crash" && *decision == RecoveryDecision::NeedsAttention
        }),
        "runtime crash after start is ambiguous: {decisions:?}"
    );
    assert_needs_attention_without_retry(&reader, "cm-crash", Some("PROCESS_STARTED"));
    writer.shutdown().expect("shutdown");
}

#[test]
fn crash_matrix_unknown_exit_needs_attention_no_retry() {
    let (root, writer, reader, supervisor) = setup();
    let mut live = started(spawn_script(
        &supervisor,
        &writer,
        root.path(),
        "cm-unknown",
        r#"[{"type":"lifecycle","state":"RUNNING"},{"type":"crash","code":1}]"#,
        ResumeGate::Resume,
        default_spec(),
        None,
    ));
    let code = live.wait(Duration::from_secs(5)).expect("wait");
    assert_eq!(code, Some(1));
    drop(live);
    let decisions = writer
        .reconcile_nonterminal("c", 91)
        .expect("reconcile unknown exit");
    assert!(
        decisions.iter().any(|(task_id, decision)| {
            task_id == "cm-unknown" && *decision == RecoveryDecision::NeedsAttention
        }),
        "unknown provider exit must not auto-retry: {decisions:?}"
    );
    assert_needs_attention_without_retry(&reader, "cm-unknown", Some("PROCESS_STARTED"));
    writer.shutdown().expect("shutdown");
}

#[test]
fn crash_matrix_lost_session_needs_attention_no_retry() {
    let (root, writer, reader, supervisor) = setup();
    let live = started(spawn_script(
        &supervisor,
        &writer,
        root.path(),
        "cm-lost",
        r#"[{"type":"hang"}]"#,
        ResumeGate::Resume,
        default_spec(),
        None,
    ));
    writer
        .record_dispatch_phase(
            "cm-lost-observed",
            "cm-lost",
            0,
            DispatchPhase::ProviderObserved,
            None,
            30,
        )
        .expect("observe provider without resume proof");
    let (_, _, phase) = snapshot_state(&reader, "cm-lost");
    assert_eq!(phase.as_deref(), Some("PROVIDER_OBSERVED"));
    drop(live);
    let decisions = writer
        .reconcile_nonterminal("c", 92)
        .expect("reconcile lost session");
    assert!(
        decisions.iter().any(|(task_id, decision)| {
            task_id == "cm-lost" && *decision == RecoveryDecision::NeedsAttention
        }),
        "lost write-capable session must need attention: {decisions:?}"
    );
    assert_needs_attention_without_retry(&reader, "cm-lost", Some("PROVIDER_OBSERVED"));
    writer.shutdown().expect("shutdown");
}

#[test]
fn crash_matrix_current_directory_after_start_needs_attention_no_retry() {
    let (root, writer, reader, supervisor) = setup();
    let cwd = root.path().join("work");
    fs::create_dir_all(&cwd).expect("cwd");
    let marker = cwd.join("cwd-marker.txt");
    let live = started(spawn_script(
        &supervisor,
        &writer,
        root.path(),
        "cm-cwd",
        r#"[{"type":"write_marker","path":"cwd-marker.txt"},{"type":"hang"}]"#,
        ResumeGate::Resume,
        current_directory_spec(),
        Some(cwd),
    ));
    wait_for_marker(&marker);
    drop(live);
    let decisions = writer
        .reconcile_nonterminal("c", 93)
        .expect("reconcile current-directory");
    assert!(
        decisions.iter().any(|(task_id, decision)| {
            task_id == "cm-cwd" && *decision == RecoveryDecision::NeedsAttention
        }),
        "CURRENT_DIRECTORY after start must not auto-retry: {decisions:?}"
    );
    assert_needs_attention_without_retry(&reader, "cm-cwd", Some("PROCESS_STARTED"));
    writer.shutdown().expect("shutdown");
}

#[test]
fn crash_matrix_forwarded_approval_then_crash_needs_attention_no_retry() {
    let (root, writer, reader, supervisor) = setup();
    let approvals = ApprovalOrchestrator::new(writer.clone(), reader.clone(), "c");
    let attempt = submit_and_claim(&writer, "cm-approve", default_spec(), 10);
    let mut live = started(
        supervisor
            .spawn(
                SpawnRequest {
                    task_id: "cm-approve".into(),
                    generation: 0,
                    attempt_id: attempt.attempt_id.clone(),
                    executable: fake_adapter_exe(),
                    arguments: vec![
                        OsString::from("--json"),
                        OsString::from(
                            r#"[{"type":"approval","operation":"write_file"},{"type":"hang"}]"#,
                        ),
                    ],
                    env_allowlist: Vec::new(),
                    extra_env: Vec::new(),
                    current_dir: None,
                    data_root: root.path().to_path_buf(),
                    spool_quota_bytes: 0,
                    now_us: 20,
                    consumer_id: "c".into(),
                },
                ResumeGate::Resume,
            )
            .expect("spawn"),
    );
    wait_for_spool_line(live.stdout_spool_path(), "\"type\":\"approval\"");
    let interaction = approvals
        .open_pending(
            "open-cm-approve",
            "cm-approve",
            &attempt.attempt_id,
            0,
            OPERATION_DIGEST,
            POLICY_DIGEST,
            CONFIG_DIGEST,
            InteractionCapabilityClass::Approval,
            1,
            1,
            10_000,
            21,
        )
        .expect("open");
    let applied = approvals
        .apply_response(answer_for(&interaction, "approve-cm", 22), Some(&mut live))
        .expect("forward approve");
    assert!(matches!(
        applied,
        AppliedInteraction::Runtime {
            forwarded: true,
            ..
        }
    ));
    drop(live);
    let decisions = writer
        .reconcile_nonterminal("c", 94)
        .expect("reconcile after forwarded approve");
    assert!(
        decisions.iter().any(|(task_id, decision)| {
            task_id == "cm-approve" && *decision == RecoveryDecision::NeedsAttention
        }),
        "crash after a forwarded approval must not auto-retry: {decisions:?}"
    );
    assert_needs_attention_without_retry(&reader, "cm-approve", Some("PROCESS_STARTED"));
    writer.shutdown().expect("shutdown");
}

#[test]
fn crash_matrix_job_tree_kill_child_and_grandchild() {
    let (root, writer, reader, supervisor) = setup();
    let live = started(spawn_script(
        &supervisor,
        &writer,
        root.path(),
        "cm-tree",
        r#"[{"type":"spawn_grandchild"},{"type":"hang"}]"#,
        ResumeGate::Resume,
        default_spec(),
        None,
    ));
    let stdout = live.stdout_spool_path().to_path_buf();
    let identity = live.identity().clone();
    let grandchild = wait_for_grandchild_pid(&stdout);
    drop(live);
    thread::sleep(Duration::from_millis(150));
    assert!(!process_identity_is_live(&identity).expect("parent dead"));
    assert!(
        !process_id_is_active(grandchild).unwrap_or(true),
        "job close must kill the grandchild"
    );
    let decisions = writer
        .reconcile_nonterminal("c", 95)
        .expect("reconcile tree kill");
    assert!(
        decisions.iter().any(|(task_id, decision)| {
            task_id == "cm-tree" && *decision == RecoveryDecision::NeedsAttention
        }),
        "killing the job tree after start must not auto-retry: {decisions:?}"
    );
    assert_needs_attention_without_retry(&reader, "cm-tree", Some("PROCESS_STARTED"));
    writer.shutdown().expect("shutdown");
}

#[test]
fn crash_matrix_cancel_committed_beats_later_exit_zero_no_retry() {
    let (root, writer, reader, supervisor) = setup();
    let mut live = started(spawn_script(
        &supervisor,
        &writer,
        root.path(),
        "cm-cancel",
        r#"[{"type":"wait_cancel"}]"#,
        ResumeGate::Resume,
        default_spec(),
        None,
    ));
    assert_eq!(
        live.cancel("first-cancel", Duration::from_secs(3), 140)
            .expect("cancel first"),
        CancelOutcome::Cancelled
    );
    let later_exit = live.finalize_exit(0, 141);
    assert!(
        matches!(later_exit, Err(SupervisorError::AlreadyTerminal)),
        "later exit-0 must not overwrite committed cancel: {later_exit:?}"
    );
    let overwritten = writer.finalize(
        "c",
        "late-success",
        b"late-success".to_vec(),
        "cm-cancel",
        0,
        "SUCCEEDED",
        DIGEST,
        142,
    );
    assert!(matches!(
        overwritten,
        Err(StorageError::TerminalImmutable | StorageError::StaleGeneration)
    ));
    let (state, generation, _) = snapshot_state(&reader, "cm-cancel");
    assert_eq!(state, "CANCELLED");
    assert_eq!(generation, 0);
    assert!(
        !retry_was_scheduled(&reader, "cm-cancel"),
        "committed cancel must not schedule retry when a later exit-0 arrives"
    );
    writer.shutdown().expect("shutdown");
}
