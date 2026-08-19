//! Production adapter registry: settings plus a live local probe.
//!
//! `list_agents` and the dispatcher share this projection. A role is
//! mesh-dispatchable only when it binds to a CLI family whose probe is
//! `ENABLED`. GPT bind targets such as `luna` are Codex-native: the
//! coordinator spawns its own subagent and this registry never probes a
//! CLI or invents a fallback.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::adapters::claude::{self, ClaudeProbeEvidence};
use crate::adapters::grok::{self, GrokProbeEvidence};
use crate::adapters::kimi::{self, KimiProbeEvidence};
use crate::adapters::{AdmissionRecord, AdmissionStatus};
use crate::settings::{SettingsDocument, SettingsStore, default_settings};

/// Per-command kill deadline. Cold Node CLIs can take a few seconds for `--version`.
/// Family probes are parallel, so 5s × 3 commands still fits in `LIST_AGENTS_TIMEOUT_MS`.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const CLI_FAMILIES: [&str; 4] = ["claude", "grok", "kimi", "pi"];
const CODEX_NATIVE: [&str; 1] = ["luna"];

/// Settings-backed probe of the three v0.1 local adapters.
#[derive(Clone)]
pub struct AdapterRegistry {
    settings: SettingsStore,
}

impl AdapterRegistry {
    #[must_use]
    pub fn new(settings: SettingsStore) -> Self {
        Self { settings }
    }

    #[must_use]
    pub fn settings_store(&self) -> &SettingsStore {
        &self.settings
    }

    /// Loads persisted settings or the bundled defaults when the file is absent.
    #[must_use]
    pub fn load_settings(&self) -> SettingsDocument {
        self.settings.load().unwrap_or_else(|_| default_settings())
    }

    /// Probes enabled families in parallel and returns public capability records.
    #[must_use]
    pub fn list_admissions(&self) -> Vec<AdmissionRecord> {
        let settings = self.load_settings();
        thread::scope(|scope| {
            let handles = CLI_FAMILIES
                .map(|family| (family, scope.spawn(|| probe_family(family, &settings))));
            handles
                .map(|(family, handle)| {
                    handle
                        .join()
                        .unwrap_or_else(|_| unavailable(family, "probe failed"))
                })
                .into()
        })
    }

    /// Schema-valid `adapter_capabilities` records for `list_agents`.
    #[must_use]
    pub fn list_protocol_values(&self) -> Vec<Value> {
        self.list_admissions()
            .into_iter()
            .filter_map(|record| record.to_protocol_value().ok().map(Value::Object))
            .collect()
    }

    /// The enabled adapter bound to `role`, if any.
    #[must_use]
    pub fn enabled_for_role(&self, role: &str) -> Option<AdmissionRecord> {
        let settings = self.load_settings();
        let family = role_family(role, &settings)?;
        if is_codex_native(family) {
            return None;
        }
        let record = probe_family(family, &settings);
        matches!(record.status, AdmissionStatus::Enabled).then_some(record)
    }

    /// Absolute executable used by an admission, when the file exists.
    #[must_use]
    pub fn executable_for(admission: &AdmissionRecord) -> Option<PathBuf> {
        let path = PathBuf::from(&admission.executable_path);
        path.is_file().then_some(path)
    }

    #[must_use]
    pub fn routing_projection(&self) -> Value {
        routing_projection(&self.load_settings())
    }
}

/// Writes a first-run config that enables each adapter whose default
/// executable is present. Existing documents are left untouched.
pub fn seed_detected_adapters(
    store: &SettingsStore,
    now_us: i64,
) -> Result<bool, crate::settings::SettingsError> {
    if store.path().is_file() {
        return Ok(false);
    }
    let mut document = default_settings();
    let mut any = false;
    for family in CLI_FAMILIES {
        let Some(path) = default_executable(family) else {
            continue;
        };
        if let Some(enabled) = document
            .settings
            .get_mut("enabled_adapters")
            .and_then(Value::as_object_mut)
        {
            enabled.insert(family.to_owned(), Value::Bool(true));
        }
        if let Some(paths) = document
            .settings
            .get_mut("executable_paths")
            .and_then(Value::as_object_mut)
        {
            paths.insert(
                family.to_owned(),
                Value::String(path.to_string_lossy().into_owned()),
            );
        }
        any = true;
    }
    if !any {
        return Ok(false);
    }
    document.config_version = 1;
    store.save(&document, now_us)?;
    Ok(true)
}

fn role_family(role: &str, settings: &SettingsDocument) -> Option<&'static str> {
    let bindings = settings.settings.get("role_bindings")?.as_object()?;
    let name = bindings
        .get(role)
        .and_then(Value::as_str)
        .or_else(|| (role == "freelancer").then_some("kimi"))?;
    CLI_FAMILIES
        .iter()
        .copied()
        .chain(CODEX_NATIVE.iter().copied())
        .find(|family| *family == name)
}

fn is_codex_native(name: &str) -> bool {
    CODEX_NATIVE.contains(&name)
}

fn routing_projection(settings: &SettingsDocument) -> Value {
    let roles = settings
        .settings
        .get("role_bindings")
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "implementation": "claude",
                "research": "grok",
                "review": "luna",
                "freelancer": "kimi"
            })
        });
    let models = settings
        .settings
        .get("native_models")
        .cloned()
        .unwrap_or_else(|| json!({ "luna": "gpt-5.6-luna" }));
    json!({
        "role_bindings": roles,
        "native_models": models,
        "coordinator_native": CODEX_NATIVE
    })
}

fn adapter_enabled(family: &str, settings: &SettingsDocument) -> bool {
    settings
        .settings
        .get("enabled_adapters")
        .and_then(Value::as_object)
        .and_then(|map| map.get(family))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn configured_path(family: &str, settings: &SettingsDocument) -> Option<PathBuf> {
    let value = settings
        .settings
        .get("executable_paths")
        .and_then(Value::as_object)
        .and_then(|map| map.get(family))?;
    match value {
        Value::String(path) if !path.trim().is_empty() => Some(PathBuf::from(path)),
        _ => None,
    }
}

/// Well-known per-user install locations used by the live contract harness.
#[must_use]
pub fn default_executable(family: &str) -> Option<PathBuf> {
    default_executable_candidates(family)
        .into_iter()
        .find(|path| path.is_file())
}

fn default_executable_candidates(family: &str) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
        let home = PathBuf::from(home);
        match family {
            "claude" => paths.push(home.join(".local").join("bin").join("claude.exe")),
            "grok" => paths.push(home.join(".grok").join("bin").join("grok.exe")),
            "kimi" => paths.push(home.join(".kimi-code").join("bin").join("kimi.exe")),
            "pi" => paths.push(home.join(".pi").join("bin").join("pi.exe")),
            _ => {}
        }
    }
    if family == "claude"
        && let Some(appdata) = std::env::var_os("APPDATA")
    {
        paths.push(
            PathBuf::from(appdata)
                .join("npm")
                .join("node_modules")
                .join("@anthropic-ai")
                .join("claude-code")
                .join("bin")
                .join("claude.exe"),
        );
    }
    paths
}

fn resolve_executable(family: &str, settings: &SettingsDocument) -> Option<PathBuf> {
    configured_path(family, settings)
        .filter(|path| path.is_file())
        .or_else(|| default_executable(family))
}

fn probe_family(family: &str, settings: &SettingsDocument) -> AdmissionRecord {
    let enabled = adapter_enabled(family, settings);
    let executable = resolve_executable(family, settings);
    if family == "pi" {
        let mut record = unavailable("pi", "pi has no admitted spawn surface");
        if let Some(path) = executable {
            record.executable_path = path.to_string_lossy().into_owned();
        }
        return record;
    }
    if !enabled {
        let mut record = unavailable(
            family,
            if executable.is_some() {
                "disabled in settings"
            } else {
                "executable not found"
            },
        );
        if let Some(path) = executable {
            record.executable_path = path.to_string_lossy().into_owned();
        }
        return record;
    }
    let Some(executable) = executable else {
        return unavailable(family, "executable not found");
    };
    let display = executable.to_string_lossy().into_owned();
    let version = capture_stdout(&executable, &["--version"]);
    let (help, extra_help) = if version.is_some() {
        (
            capture_stdout(&executable, &["--help"]),
            match family {
                "grok" => capture_stdout(&executable, &["agent", "stdio", "--help"]),
                "kimi" => capture_stdout(&executable, &["acp", "--help"]),
                _ => None,
            },
        )
    } else {
        (None, None)
    };
    match family {
        "claude" => claude::probe_claude(&ClaudeProbeEvidence {
            executable: executable.clone(),
            display_path: display,
            version_stdout: version,
            help_stdout: help,
            live_contract_passed: false,
            account: "local".into(),
            profile: "default".into(),
        }),
        "grok" => grok::probe_grok(&GrokProbeEvidence {
            executable: executable.clone(),
            display_path: display,
            version_stdout: version,
            help_stdout: help,
            agent_stdio_help_stdout: extra_help,
            live_contract_passed: false,
            account: "local".into(),
            profile: "default".into(),
        }),
        "kimi" => {
            kimi::probe_kimi(&KimiProbeEvidence {
                executable: executable.clone(),
                display_path: display,
                version_stdout: version,
                help_stdout: help,
                acp_help_stdout: extra_help,
                account: "local".into(),
                profile: "default".into(),
                live_contract_passed: false,
            })
            .admission
        }
        _ => unavailable(family, "unknown adapter"),
    }
}

fn unavailable(family: &str, reason: &str) -> AdmissionRecord {
    use crate::adapters::{AcpSidecarPolicy, AdapterTransport, PermissionHealth, zero_digest};
    AdmissionRecord {
        adapter: match family {
            "grok" => "grok",
            "kimi" => "kimi",
            "pi" => "pi",
            _ => "claude",
        },
        adapter_instance_id: format!("{family}:local:default:{}", "0".repeat(64)),
        status: AdmissionStatus::Unavailable,
        executable_path: format!("{family}.exe"),
        executable_digest: zero_digest().to_owned(),
        executable_version: "unproven".into(),
        transport: match family {
            "claude" => AdapterTransport::StreamJson,
            _ => AdapterTransport::Acp,
        },
        capabilities: Vec::new(),
        supported_interactions: Vec::new(),
        permission_health: PermissionHealth::Unsupported,
        degradation_reason: reason.into(),
        fixture_bundle_id: String::new(),
        acp_sidecar: AcpSidecarPolicy::DISABLED,
        live_contract_passed: false,
    }
}

fn capture_stdout(executable: &Path, args: &[&str]) -> Option<String> {
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command.spawn().ok()?;
    let mut stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return None;
        }
    };
    thread::scope(|scope| {
        let reader = scope.spawn(move || {
            let mut bytes = Vec::new();
            stdout.read_to_end(&mut bytes).ok()?;
            Some(bytes)
        });
        let deadline = Instant::now() + PROBE_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) | Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = reader.join();
                    return None;
                }
            }
        };
        let bytes = reader.join().ok()??;
        if !status.success() {
            return None;
        }
        String::from_utf8(bytes)
            .ok()
            .filter(|text| !text.trim().is_empty())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::SettingsDocument;
    use serde_json::json;

    fn settings_with(enabled: bool) -> SettingsDocument {
        SettingsDocument::from_record(json!({
            "version": 1,
            "kind": "config",
            "config_version": 1,
            "settings": {
                "enabled_adapters": { "claude": enabled, "grok": enabled, "kimi": enabled },
                "executable_paths": { "claude": null, "grok": null, "kimi": null },
                "transport_priority": {
                    "claude": ["native_json"],
                    "grok": ["acp"],
                    "kimi": ["acp"]
                },
                "role_bindings": {
                    "implementation": "claude",
                    "research": "grok",
                    "review": "kimi"
                },
                "concurrency": { "global": 3, "per_adapter": 1 },
                "quality": { "default": "standard", "allowed": ["standard"] },
                "effort": { "default": "medium", "allowed": ["medium"] },
                "review_chain": { "enabled": false, "reviewer": "kimi" },
                "retention": {
                    "acknowledged_result_days": 90,
                    "acknowledged_blob_terminal_days": 14,
                    "acknowledged_blob_post_ack_days": 7,
                    "successful_worktree_post_ack_days": 7,
                    "non_success_worktree_terminal_days": 30,
                    "metrics_days": 90
                },
                "improvement_enabled": false
            }
        }))
        .expect("settings")
    }

    #[test]
    fn missing_executable_is_unavailable() {
        let record = probe_family("claude", &settings_with(true));
        if default_executable("claude").is_none() {
            assert_eq!(record.status, AdmissionStatus::Unavailable);
            assert!(!record.degradation_reason.is_empty());
        }
    }

    #[test]
    fn disabled_settings_never_enable() {
        let record = probe_family("claude", &settings_with(false));
        assert_eq!(record.status, AdmissionStatus::Unavailable);
        if default_executable("claude").is_some() {
            assert_eq!(record.degradation_reason, "disabled in settings");
        }
    }

    #[test]
    fn role_bindings_select_the_configured_family() {
        let settings = settings_with(false);
        assert_eq!(role_family("implementation", &settings), Some("claude"));
        assert_eq!(role_family("research", &settings), Some("grok"));
        assert_eq!(role_family("review", &settings), Some("kimi"));
        assert_eq!(role_family("freelancer", &settings), Some("kimi"));
        assert_eq!(role_family("unknown", &settings), None);
    }

    #[test]
    fn bundled_defaults_bind_review_to_luna_and_freelancer_to_kimi() {
        let settings = default_settings();
        assert_eq!(role_family("implementation", &settings), Some("claude"));
        assert_eq!(role_family("research", &settings), Some("grok"));
        assert_eq!(role_family("review", &settings), Some("luna"));
        assert_eq!(role_family("freelancer", &settings), Some("kimi"));
    }

    #[test]
    fn review_can_be_rebound_away_from_luna() {
        let mut settings = default_settings();
        settings.settings["role_bindings"]["review"] = json!("kimi");
        assert_eq!(role_family("review", &settings), Some("kimi"));
        settings.settings["role_bindings"]["freelancer"] = json!("claude");
        assert_eq!(role_family("freelancer", &settings), Some("claude"));
    }

    #[test]
    fn luna_is_codex_native_and_never_probed_or_enabled() {
        assert!(is_codex_native("luna"));
        assert!(!is_codex_native("kimi"));
        let root = tempfile::tempdir().expect("tempdir");
        let registry = AdapterRegistry::new(SettingsStore::new(root.path()));
        let names: Vec<_> = registry
            .list_admissions()
            .into_iter()
            .map(|record| record.adapter.to_string())
            .collect();
        assert_eq!(names, ["claude", "grok", "kimi", "pi"]);
        assert!(registry.enabled_for_role("review").is_none());
        assert!(registry.enabled_for_role("implementation").is_none());
    }

    #[cfg(windows)]
    #[test]
    fn capture_stdout_kills_a_hanging_windows_command() {
        let system_root = std::env::var_os("SystemRoot")
            .unwrap_or_else(|| std::ffi::OsString::from(r"C:\Windows"));
        let ping = PathBuf::from(system_root).join("System32").join("ping.exe");
        let started = Instant::now();
        let output = capture_stdout(&ping, &["-n", "20", "127.0.0.1"]);
        let elapsed = started.elapsed();
        assert!(output.is_none());
        assert!(
            elapsed < Duration::from_secs(8),
            "hanging probe must die under the 20s ping, elapsed={elapsed:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    fn pi_and_disabled_families_are_unavailable_without_a_live_cli() {
        let comspec =
            std::env::var("COMSPEC").unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".to_owned());
        let mut settings = settings_with(false);
        settings.settings["enabled_adapters"] = json!({
            "claude": false,
            "grok": false,
            "kimi": false,
            "pi": true
        });
        settings.settings["executable_paths"] = json!({
            "claude": comspec,
            "grok": comspec,
            "kimi": comspec,
            "pi": comspec
        });
        let started = Instant::now();
        let claude = probe_family("claude", &settings);
        let grok = probe_family("grok", &settings);
        let kimi = probe_family("kimi", &settings);
        let pi = probe_family("pi", &settings);
        let elapsed = started.elapsed();
        assert_eq!(claude.status, AdmissionStatus::Unavailable);
        assert_eq!(claude.degradation_reason, "disabled in settings");
        assert_eq!(claude.executable_path, comspec);
        assert_eq!(grok.status, AdmissionStatus::Unavailable);
        assert_eq!(grok.degradation_reason, "disabled in settings");
        assert_eq!(grok.executable_path, comspec);
        assert_eq!(kimi.status, AdmissionStatus::Unavailable);
        assert_eq!(kimi.degradation_reason, "disabled in settings");
        assert_eq!(kimi.executable_path, comspec);
        assert_eq!(pi.status, AdmissionStatus::Unavailable);
        assert_eq!(pi.degradation_reason, "pi has no admitted spawn surface");
        assert_eq!(pi.executable_path, comspec);
        assert!(
            elapsed < Duration::from_secs(1),
            "disabled/pi probes must not spawn a hanging CLI, elapsed={elapsed:?}"
        );
    }

    #[test]
    fn claude_candidates_include_npm_appdata_install() {
        let paths = default_executable_candidates("claude");
        assert!(
            paths.iter().any(|path| path
                .components()
                .any(|component| component.as_os_str() == "@anthropic-ai")),
            "claude candidates must include the npm @anthropic-ai/claude-code path, got {paths:?}"
        );
    }
}
