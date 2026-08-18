//! Strict command-line grammar for the single stable installation slot.
//!
//! Parsing is deliberately side-effect free. Production identity checks still
//! decide whether an internal bridge/daemon mode is running from the retained
//! executable rather than a plugin-cache copy.

use std::ffi::OsString;

use thiserror::Error;

pub const EXIT_SUCCESS: u8 = 0;
pub const EXIT_LIFECYCLE: u8 = 10;
pub const EXIT_TIMEOUT: u8 = 11;
pub const EXIT_RUNTIME: u8 = 12;

/// One admitted public or internal executable mode.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliMode {
    Setup,
    Status,
    Start,
    Remove { purge_data: bool },
    Follow { task_id: Option<String> },
    BridgeBootstrap,
    Bridge,
    Daemon,
}

/// Redaction-safe CLI grammar failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("invalid mesh-daemon command line")]
pub struct CliParseError;

/// Parses arguments after the executable name.
///
/// # Errors
///
/// Returns [`CliParseError`] for non-Unicode, unknown, duplicate, missing, or
/// mode-incompatible arguments. The only admitted slot value is `stable`.
pub fn parse_cli(arguments: impl IntoIterator<Item = OsString>) -> Result<CliMode, CliParseError> {
    let mut arguments = arguments.into_iter();
    let command = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or(CliParseError)?;
    let mut slot = None;
    let mut stdio = false;
    let mut purge_data = false;
    let mut task_id = None;
    while let Some(argument) = arguments.next() {
        let argument = argument.into_string().map_err(|_| CliParseError)?;
        match argument.as_str() {
            "--install-slot" if slot.is_none() => {
                let value = arguments
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or(CliParseError)?;
                if value != "stable" {
                    return Err(CliParseError);
                }
                slot = Some(());
            }
            "--task-id" if task_id.is_none() => {
                let value = arguments
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or(CliParseError)?;
                if !is_follow_task_id(&value) {
                    return Err(CliParseError);
                }
                task_id = Some(value);
            }
            "--stdio" if !stdio => stdio = true,
            "--purge-data" if !purge_data => purge_data = true,
            _ => return Err(CliParseError),
        }
    }
    if slot.is_none() {
        return Err(CliParseError);
    }
    match command.as_str() {
        "setup" if !stdio && !purge_data && task_id.is_none() => Ok(CliMode::Setup),
        "status" if !stdio && !purge_data && task_id.is_none() => Ok(CliMode::Status),
        "start" if !stdio && !purge_data && task_id.is_none() => Ok(CliMode::Start),
        "remove" if !stdio && task_id.is_none() => Ok(CliMode::Remove { purge_data }),
        "follow" if !stdio && !purge_data => Ok(CliMode::Follow { task_id }),
        "bridge-bootstrap" if stdio && !purge_data && task_id.is_none() => {
            Ok(CliMode::BridgeBootstrap)
        }
        "bridge" if stdio && !purge_data && task_id.is_none() => Ok(CliMode::Bridge),
        "daemon" if !stdio && !purge_data && task_id.is_none() => Ok(CliMode::Daemon),
        _ => Err(CliParseError),
    }
}

fn is_follow_task_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphanumeric()
        && value.len() <= 128
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<CliMode, CliParseError> {
        parse_cli(arguments.iter().map(OsString::from))
    }

    #[test]
    fn exact_public_and_internal_modes_are_admitted() {
        assert_eq!(
            parse(&["setup", "--install-slot", "stable"]),
            Ok(CliMode::Setup)
        );
        assert_eq!(
            parse(&["status", "--install-slot", "stable"]),
            Ok(CliMode::Status)
        );
        assert_eq!(
            parse(&["start", "--install-slot", "stable"]),
            Ok(CliMode::Start)
        );
        assert_eq!(
            parse(&["remove", "--install-slot", "stable"]),
            Ok(CliMode::Remove { purge_data: false })
        );
        assert_eq!(
            parse(&["remove", "--purge-data", "--install-slot", "stable"]),
            Ok(CliMode::Remove { purge_data: true })
        );
        assert_eq!(
            parse(&["bridge-bootstrap", "--stdio", "--install-slot", "stable"]),
            Ok(CliMode::BridgeBootstrap)
        );
        assert_eq!(
            parse(&["bridge", "--install-slot", "stable", "--stdio"]),
            Ok(CliMode::Bridge)
        );
        assert_eq!(
            parse(&["daemon", "--install-slot", "stable"]),
            Ok(CliMode::Daemon)
        );
        assert_eq!(
            parse(&["follow", "--install-slot", "stable"]),
            Ok(CliMode::Follow { task_id: None })
        );
        assert_eq!(
            parse(&["follow", "--install-slot", "stable", "--task-id", "task-1"]),
            Ok(CliMode::Follow {
                task_id: Some("task-1".into())
            })
        );
    }

    #[test]
    fn alternate_slots_unknown_and_duplicate_flags_fail_closed() {
        for arguments in [
            vec!["setup"],
            vec!["setup", "--install-slot", "other"],
            vec!["setup", "--install-slot", "stable", "--stdio"],
            vec!["bridge", "--install-slot", "stable"],
            vec!["daemon", "--stdio", "--install-slot", "stable"],
            vec![
                "remove",
                "--purge-data",
                "--purge-data",
                "--install-slot",
                "stable",
            ],
            vec![
                "status",
                "--install-slot",
                "stable",
                "--install-slot",
                "stable",
            ],
            vec!["unknown", "--install-slot", "stable"],
            vec!["setup", "--unknown", "--install-slot", "stable"],
            vec!["follow", "--install-slot", "stable", "--stdio"],
            vec!["follow", "--install-slot", "stable", "--task-id", ""],
        ] {
            assert_eq!(parse(&arguments), Err(CliParseError), "{arguments:?}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn non_unicode_arguments_are_rejected() {
        use std::os::windows::ffi::OsStringExt;

        let invalid = OsString::from_wide(&[0xd800]);
        assert_eq!(
            parse_cli([OsString::from("setup"), invalid]),
            Err(CliParseError)
        );
    }
}
