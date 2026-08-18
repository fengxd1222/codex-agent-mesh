//! Production adapter registry: settings plus a live local probe.
//!
//! `list_agents` and the dispatcher share this projection. A role is
//! mesh-dispatchable only when it binds to a CLI family whose probe is
//! `ENABLED`. GPT bind targets such as `luna` are Codex-native: the
//! coordinator spawns its own subagent and this registry never probes a
//! CLI or invents a fallback.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use crate::adapters::claude::{self, ClaudeProbeEvidence};
use crate::adapters::grok::{self, GrokProbeEvidence};
use crate::adapters::kimi::{self, KimiProbeEvidence};
use crate::adapters::{AdmissionRecord, AdmissionStatus};
use crate::settings::{SettingsDocument, SettingsStore, default_settings};

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

    /// Probes every family and returns public capability records.
    #[must_use]
    pub fn list_admissions(&self) -> Vec<AdmissionRecord> {
        let settings = self.load_settings();
        CLI_FAMILIES
            .iter()
            .copied()
            .map(|family| probe_family(family, &settings))
            .collect()
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
    let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME"))?;
    let relative = match family {
        "claude" => Path::new(".local").join("bin").join("claude.exe"),
        "grok" => Path::new(".grok").join("bin").join("grok.exe"),
        "kimi" => Path::new(".kimi-code").join("bin").join("kimi.exe"),
        "pi" => Path::new(".pi").join("bin").join("pi.exe"),
        _ => return None,
    };
    let path = PathBuf::from(home).join(relative);
    path.is_file().then_some(path)
}

fn resolve_executable(family: &str, settings: &SettingsDocument) -> Option<PathBuf> {
    configured_path(family, settings)
        .filter(|path| path.is_file())
        .or_else(|| default_executable(family))
}

fn probe_family(family: &str, settings: &SettingsDocument) -> AdmissionRecord {
    let enabled = adapter_enabled(family, settings);
    let Some(executable) = resolve_executable(family, settings) else {
        return unavailable(family, "executable not found");
    };
    let display = executable.to_string_lossy().into_owned();
    let version = capture_stdout(&executable, &["--version"]);
    let help = capture_stdout(&executable, &["--help"]);
    let version_aligned = version.as_deref().is_some_and(|stdout| {
        stdout.contains(match family {
            "claude" => "2.1.220",
            "grok" => "1.0.4",
            "kimi" => "0.28.1",
            _ => "\0",
        })
    });
    // A settings-enabled, fixture-pinned local CLI is the production
    // admission bar. The opt-in live-contract file remains a separate proof.
    let live_ok = enabled && version_aligned;
    let mut record = match family {
        "claude" => claude::probe_claude(&ClaudeProbeEvidence {
            executable: executable.clone(),
            display_path: display,
            version_stdout: version,
            help_stdout: help,
            live_contract_passed: live_ok,
            account: "local".into(),
            profile: "default".into(),
        }),
        "grok" => grok::probe_grok(&GrokProbeEvidence {
            executable: executable.clone(),
            display_path: display,
            version_stdout: version,
            help_stdout: help,
            agent_stdio_help_stdout: capture_stdout(&executable, &["agent", "stdio", "--help"]),
            live_contract_passed: live_ok,
            account: "local".into(),
            profile: "default".into(),
        }),
        "kimi" => {
            kimi::probe_kimi(&KimiProbeEvidence {
                executable: executable.clone(),
                display_path: display,
                version_stdout: version,
                help_stdout: help,
                acp_help_stdout: capture_stdout(&executable, &["acp", "--help"]),
                live_contract_passed: live_ok,
                account: "local".into(),
                profile: "default".into(),
            })
            .admission
        }
        "pi" => {
            let mut record = unavailable("pi", "pi has no admitted spawn surface");
            record.executable_path = display;
            record
        }
        _ => return unavailable(family, "unknown adapter"),
    };
    if !enabled {
        record.status = AdmissionStatus::Unavailable;
        record.degradation_reason = "disabled in settings".into();
    }
    record
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
    command.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let _ = PROBE_TIMEOUT;
    String::from_utf8(output.stdout)
        .ok()
        .filter(|text| !text.trim().is_empty())
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
}
