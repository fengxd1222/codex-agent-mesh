//! Safe settings: schema-validated TOML under the data root, atomic
//! writes, versioned audit, hot-reload classification, and portable
//! secret-free export/import.
//!
//! The TOML document mirrors the v1 wire `config` record, so every write
//! is validated by the same strict schema the daemon already enforces.
//! Only the safe-settings allowlist exists on this surface; there is no
//! field for credentials, tokens, install identity, or model names.

#![allow(clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};

use crate::protocol_strict_json::parse_strict_json;
use crate::{ProtocolError, decode_v1};

/// File name of the settings document inside the data root.
pub const SETTINGS_FILE: &str = "config.toml";
/// File name of the append-only settings audit log.
pub const SETTINGS_AUDIT_FILE: &str = "config-audit.jsonl";
/// Largest accepted settings document (TOML bytes).
pub const MAX_SETTINGS_BYTES: usize = 64 * 1024;

/// Redaction-safe settings failure.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum SettingsError {
    #[error("settings document is invalid")]
    InvalidDocument,
    #[error("settings document exceeds the size bound")]
    TooLarge,
    #[error("settings storage is unavailable")]
    Storage,
    #[error("settings audit is unavailable")]
    Audit,
}

/// Schema-validated settings document plus its version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettingsDocument {
    pub config_version: i64,
    pub settings: Map<String, Value>,
}

impl SettingsDocument {
    /// Validates a full wire-shaped config record (`version`, `kind`,
    /// `config_version`, `settings`) against the strict v1 schema.
    pub fn from_record(value: Value) -> Result<Self, SettingsError> {
        decode_v1(value)
            .map_err(protocol_invalid)
            .and_then(|record| Self::from_validated(&record))
    }

    fn from_validated(record: &Map<String, Value>) -> Result<Self, SettingsError> {
        let config_version = record
            .get("config_version")
            .and_then(Value::as_i64)
            .ok_or(SettingsError::InvalidDocument)?;
        let settings = record
            .get("settings")
            .and_then(Value::as_object)
            .ok_or(SettingsError::InvalidDocument)?
            .clone();
        if settings.is_empty() {
            return Err(SettingsError::InvalidDocument);
        }
        Ok(Self {
            config_version,
            settings,
        })
    }

    /// Builds the wire-shaped record for schema validation and storage.
    #[must_use]
    pub fn to_record(&self) -> Value {
        json!({
            "version": 1,
            "kind": "config",
            "config_version": self.config_version,
            "settings": Value::Object(self.settings.clone()),
        })
    }

    /// Canonical content digest of the settings object.
    #[must_use]
    pub fn digest(&self) -> String {
        let canonical = Value::Object(self.settings.clone()).to_string();
        format!("{:x}", Sha256::digest(canonical.as_bytes()))
    }
}

fn protocol_invalid(_: ProtocolError) -> SettingsError {
    SettingsError::InvalidDocument
}

/// Parses one TOML settings document into a validated record.
pub fn parse_toml(source: &str) -> Result<SettingsDocument, SettingsError> {
    if source.len() > MAX_SETTINGS_BYTES {
        return Err(SettingsError::TooLarge);
    }
    let value: toml::Value = toml::from_str(source).map_err(|_| SettingsError::InvalidDocument)?;
    let mut json = toml_to_json(value).ok_or(SettingsError::InvalidDocument)?;
    normalize_toml_nulls(&mut json);
    SettingsDocument::from_record(json)
}

/// TOML cannot express null, and the schema's only nullable fields are the
/// CLI adapter executable paths: an omitted path key means null.
fn normalize_toml_nulls(record: &mut Value) {
    let Some(settings) = record.get_mut("settings").and_then(Value::as_object_mut) else {
        return;
    };
    let paths = settings
        .entry("executable_paths".to_owned())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if let Some(paths) = paths.as_object_mut() {
        for adapter in ["claude", "grok", "kimi"] {
            paths
                .entry(adapter.to_owned())
                .or_insert_with(|| Value::Null);
        }
    }
    let roles = settings
        .entry("role_bindings".to_owned())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if let Some(roles) = roles.as_object_mut() {
        roles
            .entry("freelancer".to_owned())
            .or_insert_with(|| json!("kimi"));
    }
    let models = settings
        .entry("native_models".to_owned())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if let Some(models) = models.as_object_mut() {
        models
            .entry("luna".to_owned())
            .or_insert_with(|| json!("gpt-5.6-luna"));
    }
}

/// Renders a validated document back to TOML. Null executable paths are
/// omitted (TOML has no null) and re-materialize as null on load.
pub fn render_toml(document: &SettingsDocument) -> Result<String, SettingsError> {
    let mut record = document.to_record();
    if let Some(settings) = record
        .pointer_mut("/settings")
        .and_then(Value::as_object_mut)
    {
        if let Some(paths) = settings
            .get_mut("executable_paths")
            .and_then(Value::as_object_mut)
        {
            paths.retain(|_, value| !value.is_null());
        }
        if settings
            .get("executable_paths")
            .and_then(Value::as_object)
            .is_some_and(serde_json::Map::is_empty)
        {
            settings.remove("executable_paths");
        }
    }
    let value = json_to_toml(record).ok_or(SettingsError::InvalidDocument)?;
    toml::to_string_pretty(&value).map_err(|_| SettingsError::InvalidDocument)
}

fn toml_to_json(value: toml::Value) -> Option<Value> {
    match value {
        toml::Value::String(text) => Some(Value::from(text)),
        toml::Value::Integer(number) => Some(Value::from(number)),
        toml::Value::Float(_) | toml::Value::Datetime(_) => None,
        toml::Value::Boolean(flag) => Some(Value::from(flag)),
        toml::Value::Array(items) => items
            .into_iter()
            .map(toml_to_json)
            .collect::<Option<Vec<_>>>()
            .map(Value::Array),
        toml::Value::Table(fields) => fields
            .into_iter()
            .map(|(key, nested)| toml_to_json(nested).map(|value| (key, value)))
            .collect::<Option<Map<String, Value>>>()
            .map(Value::Object),
    }
}

fn json_to_toml(value: Value) -> Option<toml::Value> {
    match value {
        Value::String(text) => Some(toml::Value::from(text)),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                toml::Value::try_from(integer).ok()
            } else {
                None
            }
        }
        Value::Bool(flag) => Some(toml::Value::from(flag)),
        Value::Array(items) => items
            .into_iter()
            .map(json_to_toml)
            .collect::<Option<Vec<_>>>()
            .and_then(|items| toml::Value::try_from(items).ok()),
        Value::Object(fields) => {
            let mut table = toml::map::Map::new();
            for (key, nested) in fields {
                table.insert(key, json_to_toml(nested)?);
            }
            Some(toml::Value::Table(table))
        }
        Value::Null => None,
    }
}

/// Which top-level settings keys hot-reload versus requiring a restart.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeClassification {
    pub hot_reload: Vec<String>,
    pub restart_required: Vec<String>,
}

/// Concurrency feeds the live scheduler limiter construction at startup;
/// every other safe-settings key hot-reloads through re-reading the file.
const RESTART_REQUIRED_KEYS: &[&str] = &["concurrency"];

#[must_use]
pub fn classify_changes(
    previous: &SettingsDocument,
    next: &SettingsDocument,
) -> ChangeClassification {
    let mut hot_reload = Vec::new();
    let mut restart_required = Vec::new();
    let mut keys: Vec<&String> = previous.settings.keys().collect();
    keys.extend(next.settings.keys());
    keys.sort();
    keys.dedup();
    for key in keys {
        if previous.settings.get(key) != next.settings.get(key) {
            if RESTART_REQUIRED_KEYS.contains(&key.as_str()) {
                restart_required.push(key.clone());
            } else {
                hot_reload.push(key.clone());
            }
        }
    }
    ChangeClassification {
        hot_reload,
        restart_required,
    }
}

/// Loads, validates, and audits the settings file under `root`, falling
/// back to the documented defaults when it does not exist yet.
#[derive(Clone)]
pub struct SettingsStore {
    root: PathBuf,
}

impl SettingsStore {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    #[must_use]
    pub fn path(&self) -> PathBuf {
        self.root.join(SETTINGS_FILE)
    }

    #[must_use]
    pub fn audit_path(&self) -> PathBuf {
        self.root.join(SETTINGS_AUDIT_FILE)
    }

    /// Reads and validates the persisted document.
    pub fn load(&self) -> Result<SettingsDocument, SettingsError> {
        let bytes = std::fs::read(self.path()).map_err(|_| SettingsError::Storage)?;
        if bytes.len() > MAX_SETTINGS_BYTES {
            return Err(SettingsError::TooLarge);
        }
        let source = std::str::from_utf8(&bytes).map_err(|_| SettingsError::InvalidDocument)?;
        parse_toml(source)
    }

    /// Atomically persists the next document version: validate, write a
    /// sibling temporary file, flush, replace, then append an audit line.
    /// The audit line is written best-effort after the durable replace.
    pub fn save(
        &self,
        document: &SettingsDocument,
        now_us: i64,
    ) -> Result<ChangeClassification, SettingsError> {
        use std::io::Write as _;
        // Re-validate through the schema before anything touches the disk.
        let record = document.to_record();
        decode_v1(record).map_err(protocol_invalid)?;
        let previous = self.load().ok();
        let rendered = render_toml(document)?;
        let staged = self.root.join(format!("{SETTINGS_FILE}.tmp"));
        write_and_flush(&staged, rendered.as_bytes())?;
        if std::fs::rename(&staged, self.path()).is_err() {
            let _ = std::fs::remove_file(&staged);
            return Err(SettingsError::Storage);
        }
        let classification = match &previous {
            Some(previous) => classify_changes(previous, document),
            None => ChangeClassification {
                hot_reload: document.settings.keys().cloned().collect(),
                restart_required: Vec::new(),
            },
        };
        let audit = json!({
            "kind": "settings_audit",
            "config_version": document.config_version,
            "digest": document.digest(),
            "now_us": now_us,
        });
        let mut line = audit.to_string();
        line.push('\n');
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.audit_path())
        {
            let _ = file.write_all(line.as_bytes());
            let _ = file.flush();
        }
        Ok(classification)
    }

    /// Loads, bumps the version, validates, and saves in one step.
    pub fn update(
        &self,
        mut next: SettingsDocument,
        now_us: i64,
    ) -> Result<ChangeClassification, SettingsError> {
        let current_version = match self.load() {
            Ok(document) => document.config_version,
            Err(_) => 0,
        };
        if next.config_version != current_version + 1 {
            next.config_version = current_version + 1;
        }
        self.save(&next, now_us)
    }

    /// Portable export: identical safe settings with absolute executable
    /// paths removed and no machine-specific values. There is nothing in
    /// the safe allowlist that can carry secrets, install identity, or
    /// tokens; the scrubber still defends in depth.
    #[must_use]
    pub fn portable_export(document: &SettingsDocument) -> Value {
        let mut settings = document.settings.clone();
        if let Some(paths) = settings
            .get_mut("executable_paths")
            .and_then(Value::as_object_mut)
        {
            for (_, value) in paths.iter_mut() {
                *value = Value::Null;
            }
        }
        json!({
            "kind": "settings_export",
            "config_version": document.config_version,
            "settings": Value::Object(settings),
        })
    }

    /// Validates a portable export back into a settings document. Paths
    /// stay null on import; the local machine fills its own.
    pub fn portable_import(value: &Value) -> Result<SettingsDocument, SettingsError> {
        let object = value.as_object().ok_or(SettingsError::InvalidDocument)?;
        if object.get("kind").and_then(Value::as_str) != Some("settings_export") {
            return Err(SettingsError::InvalidDocument);
        }
        let config_version = object
            .get("config_version")
            .and_then(Value::as_i64)
            .unwrap_or(1);
        let mut settings = object
            .get("settings")
            .and_then(Value::as_object)
            .ok_or(SettingsError::InvalidDocument)?
            .clone();
        if let Some(paths) = settings
            .get_mut("executable_paths")
            .and_then(Value::as_object_mut)
        {
            for (_, value) in paths.iter_mut() {
                *value = Value::Null;
            }
        }
        SettingsDocument::from_record(json!({
            "version": 1,
            "kind": "config",
            "config_version": config_version,
            "settings": Value::Object(settings),
        }))
    }
}

fn write_and_flush(path: &Path, bytes: &[u8]) -> Result<(), SettingsError> {
    use std::io::Write as _;
    let mut file = std::fs::File::create(path).map_err(|_| SettingsError::Storage)?;
    file.write_all(bytes).map_err(|_| SettingsError::Storage)?;
    file.flush().map_err(|_| SettingsError::Storage)?;
    file.sync_all().map_err(|_| SettingsError::Storage)?;
    Ok(())
}

/// The documented default settings document (config version 1).
///
/// # Panics
///
/// Panics if the bundled default TOML ever fails schema validation; that
/// is a build-time contract, not a runtime condition.
#[must_use]
pub fn default_settings() -> SettingsDocument {
    let source = include_str!("default-config.toml");
    parse_toml(source).expect("bundled default settings must validate")
}

/// Strictly validates a raw JSON settings record received over HTTP.
pub fn validate_http_settings(body: &[u8]) -> Result<SettingsDocument, SettingsError> {
    if body.len() > MAX_SETTINGS_BYTES {
        return Err(SettingsError::TooLarge);
    }
    let text = std::str::from_utf8(body).map_err(|_| SettingsError::InvalidDocument)?;
    let value: Value = parse_strict_json(text).map_err(|_| SettingsError::InvalidDocument)?;
    SettingsDocument::from_record(value)
}

#[cfg(test)]
mod settings_tests;
