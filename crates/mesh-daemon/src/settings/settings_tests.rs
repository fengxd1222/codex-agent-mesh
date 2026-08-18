//! Settings store tests: validation, TOML round-trip, atomic writes,
//! audit, classification, and portable export/import.

use super::{
    SettingsDocument, SettingsError, SettingsStore, classify_changes, default_settings, parse_toml,
    render_toml, validate_http_settings,
};
use serde_json::{Value, json};

#[test]
fn default_settings_validate_and_round_trip() {
    let document = default_settings();
    assert_eq!(document.config_version, 1);
    assert_eq!(document.settings["concurrency"]["global"], 3);
    assert_eq!(
        document.settings["role_bindings"]["implementation"],
        "claude"
    );
    assert_eq!(document.settings["role_bindings"]["research"], "grok");
    assert_eq!(document.settings["role_bindings"]["review"], "luna");
    assert_eq!(document.settings["role_bindings"]["freelancer"], "kimi");
    assert_eq!(document.settings["review_chain"]["reviewer"], "luna");
    assert_eq!(document.settings["native_models"]["luna"], "gpt-5.6-luna");
    let rendered = render_toml(&document).expect("render");
    let reparsed = parse_toml(&rendered).expect("reparse");
    assert_eq!(reparsed, document, "TOML round trip must be lossless");
}

#[test]
fn omitted_freelancer_binding_defaults_to_kimi() {
    let source = r#"
version = 1
kind = "config"
config_version = 1

[settings]
improvement_enabled = false

[settings.enabled_adapters]
claude = false
grok = false
kimi = false

[settings.transport_priority]
claude = ["native_json"]
grok = ["acp"]
kimi = ["acp"]

[settings.role_bindings]
implementation = "claude"
research = "grok"
review = "kimi"

[settings.concurrency]
global = 3
per_adapter = 1

[settings.quality]
default = "standard"
allowed = ["standard"]

[settings.effort]
default = "medium"
allowed = ["medium"]

[settings.review_chain]
enabled = false
reviewer = "kimi"

[settings.retention]
acknowledged_result_days = 90
acknowledged_blob_terminal_days = 14
acknowledged_blob_post_ack_days = 7
successful_worktree_post_ack_days = 7
non_success_worktree_terminal_days = 30
metrics_days = 90
"#;
    let document = parse_toml(source).expect("legacy settings without freelancer");
    assert_eq!(document.settings["role_bindings"]["freelancer"], "kimi");
    assert!(document.settings["enabled_adapters"].get("luna").is_none());
}

#[test]
fn toml_round_trip_preserves_null_executable_paths() {
    let mut document = default_settings();
    document
        .settings
        .get_mut("executable_paths")
        .expect("paths")
        .as_object_mut()
        .expect("paths object")
        .insert("claude".into(), Value::Null);
    let rendered = render_toml(&document).expect("render");
    assert!(
        !rendered.contains("[settings.executable_paths]"),
        "all-null paths omit the whole TOML section"
    );
    let reparsed = parse_toml(&rendered).expect("reparse");
    assert_eq!(reparsed, document, "omitted path returns as null");
}

#[test]
fn invalid_documents_are_rejected() {
    assert_eq!(
        parse_toml("not toml ][").unwrap_err(),
        SettingsError::InvalidDocument
    );
    assert_eq!(
        parse_toml("version = 1\nkind = \"event\"").unwrap_err(),
        SettingsError::InvalidDocument
    );
    // Extra fields fall outside the safe-settings allowlist.
    let mut extra = default_settings();
    extra.settings.insert("model".into(), json!("grok-4.6"));
    assert_eq!(
        SettingsDocument::from_record(extra.to_record()).unwrap_err(),
        SettingsError::InvalidDocument
    );
    let oversized = "x".repeat(super::MAX_SETTINGS_BYTES + 1);
    assert_eq!(parse_toml(&oversized).unwrap_err(), SettingsError::TooLarge);
    // Strict JSON over HTTP: duplicate keys are rejected before validation.
    let duplicated = format!(
        "{{\"version\":1,\"kind\":\"config\",\"config_version\":1,\"kind\":\"config\",\"settings\":{}}}",
        serde_json::to_string(&default_settings().settings).expect("settings json")
    );
    assert_eq!(
        validate_http_settings(duplicated.as_bytes()).unwrap_err(),
        SettingsError::InvalidDocument
    );
}

#[test]
fn save_is_atomic_with_audit_and_versions() {
    let root = tempfile::tempdir().expect("tempdir");
    let store = SettingsStore::new(root.path());
    assert!(store.load().is_err(), "no settings file yet");

    let first = store.update(default_settings(), 1_000).expect("first save");
    assert!(first.hot_reload.contains(&"concurrency".to_owned()));
    assert_eq!(store.load().expect("reload").config_version, 1);

    let mut changed = store.load().expect("loaded v1");
    changed.settings["concurrency"]["global"] = json!(2);
    let second = store.update(changed, 2_000).expect("second save");
    assert!(
        second.restart_required.contains(&"concurrency".to_owned()),
        "concurrency changes stage for restart: {second:?}"
    );
    let reloaded = store.load().expect("reload");
    assert_eq!(reloaded.config_version, 2);
    assert_eq!(reloaded.settings["concurrency"]["global"], 2);

    let mut hot = store.load().expect("loaded v2");
    hot.settings["improvement_enabled"] = json!(true);
    let third = store.update(hot, 3_000).expect("third save");
    assert!(
        third.hot_reload.contains(&"improvement_enabled".to_owned())
            && third.restart_required.is_empty()
    );

    let audit = std::fs::read_to_string(store.audit_path()).expect("audit");
    let lines: Vec<_> = audit.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(lines.len(), 3, "one audit line per save");
    for (index, line) in lines.iter().enumerate() {
        let value: Value = serde_json::from_str(line).expect("audit json");
        assert_eq!(value["kind"], "settings_audit");
        assert_eq!(value["config_version"], json!(index + 1));
        assert!(
            value["digest"]
                .as_str()
                .is_some_and(|digest| digest.len() == 64)
        );
    }
    // Classification is derivable without saving.
    let older = store.load().expect("loaded");
    let newer = SettingsDocument {
        config_version: 99,
        settings: older.settings.clone(),
    };
    assert!(classify_changes(&older, &newer).hot_reload.is_empty());
}

#[test]
fn portable_export_strips_paths_and_import_round_trips() {
    let mut document = default_settings();
    document
        .settings
        .get_mut("executable_paths")
        .expect("paths")
        .as_object_mut()
        .expect("paths object")
        .insert(
            "grok".into(),
            json!("C:\\Users\\someone\\.grok\\bin\\grok.exe"),
        );
    let export = SettingsStore::portable_export(&document);
    assert_eq!(export["kind"], "settings_export");
    assert!(
        export["settings"]["executable_paths"]["grok"].is_null()
            && export["settings"]["executable_paths"]["claude"].is_null(),
        "export never carries absolute paths"
    );
    assert!(
        !export.to_string().contains("someone"),
        "export must not leak machine paths"
    );
    let imported = SettingsStore::portable_import(&export).expect("import");
    assert!(imported.settings["executable_paths"]["grok"].is_null());
    assert_eq!(
        imported.settings["role_bindings"],
        document.settings["role_bindings"]
    );
    // Wrong export kind is rejected.
    assert_eq!(
        SettingsStore::portable_import(&json!({"kind": "config"})).unwrap_err(),
        SettingsError::InvalidDocument
    );
}

#[test]
fn http_settings_validation_accepts_schema_shape() {
    let record = default_settings().to_record();
    let body = serde_json::to_string(&record).expect("json body");
    let document = validate_http_settings(body.as_bytes()).expect("valid");
    assert_eq!(document, default_settings());
    assert_eq!(
        validate_http_settings(b"{\"kind\": \"config\"}").unwrap_err(),
        SettingsError::InvalidDocument
    );
}
