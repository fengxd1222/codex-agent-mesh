//! Scripted fake-adapter process used only by M4 process-ownership tests.
//!
//! This crate is not a production provider and is not packaged into the plugin
//! runtime. It speaks the shared `FakeAdapterEvent` JSON vocabulary plus a
//! few test-only extensions (`write_marker`, `spawn_grandchild`, `hang`,
//! `flood`, `wait_cancel`) so the supervisor can prove completion, crash,
//! hang, approval, and Job Object tree-kill.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use std::fs;
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

/// One scripted event. The `type` tag matches `FakeAdapterEvent` plus test hooks.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScriptEvent {
    Lifecycle {
        state: String,
    },
    Text {
        text: Option<String>,
        bytes: Option<u64>,
    },
    Terminal {
        state: String,
    },
    Approval {
        operation: String,
    },
    Cancelled,
    Delay {
        milliseconds: u64,
    },
    Raw {
        line: String,
    },
    Crash {
        code: i32,
    },
    WriteMarker {
        path: String,
    },
    SpawnGrandchild,
    Hang,
    Flood {
        bytes: u64,
    },
    WaitCancel,
}

/// How the scripted process should stop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScriptOutcome {
    Completed,
    Cancelled,
    Crashed(i32),
}

/// Parses a JSON array of events or an object with an `events` array.
pub fn parse_script(source: &str) -> Result<Vec<ScriptEvent>, String> {
    let value: Value =
        serde_json::from_str(source).map_err(|error| format!("script is not JSON: {error}"))?;
    let events = if let Some(array) = value.as_array() {
        array.clone()
    } else if let Some(array) = value.get("events").and_then(Value::as_array) {
        array.clone()
    } else {
        return Err("script must be a JSON array or an object with events".into());
    };
    events
        .into_iter()
        .map(|event| {
            serde_json::from_value(event).map_err(|error| format!("invalid script event: {error}"))
        })
        .collect()
}

/// Runs `events`, writing newline-delimited JSON to `stdout`.
///
/// Approval and `wait_cancel` events read one stdin line. A line containing
/// `cancel` (or `{"type":"cancel"}`) ends the script as [`ScriptOutcome::Cancelled`].
pub fn run_script(
    events: &[ScriptEvent],
    stdout: &mut impl Write,
    stdin: &mut impl BufRead,
    current_exe: &Path,
    current_dir: Option<&Path>,
) -> io::Result<ScriptOutcome> {
    for event in events {
        match event {
            ScriptEvent::Delay { milliseconds } => {
                thread::sleep(Duration::from_millis(*milliseconds));
            }
            ScriptEvent::Crash { code } => return Ok(ScriptOutcome::Crashed(*code)),
            ScriptEvent::Hang => loop {
                thread::sleep(Duration::from_mins(1));
            },
            ScriptEvent::WaitCancel => {
                if read_cancel(stdin)? {
                    emit(stdout, &json!({"type":"cancelled"}))?;
                    return Ok(ScriptOutcome::Cancelled);
                }
            }
            ScriptEvent::Approval { operation } => {
                emit(stdout, &json!({"type":"approval","operation":operation}))?;
                if read_cancel(stdin)? {
                    emit(stdout, &json!({"type":"cancelled"}))?;
                    return Ok(ScriptOutcome::Cancelled);
                }
            }
            ScriptEvent::WriteMarker { path } => {
                let destination = resolve_marker_path(path, current_dir);
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(destination, b"ran\n")?;
            }
            ScriptEvent::SpawnGrandchild => {
                let mut command = Command::new(current_exe);
                command
                    .arg("--hang")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                if let Some(dir) = current_dir {
                    command.current_dir(dir);
                }
                let child = command.spawn()?;
                emit(stdout, &json!({"type":"spawn_grandchild","pid":child.id()}))?;
            }
            ScriptEvent::Flood { bytes } => {
                write_flood(stdout, *bytes)?;
            }
            ScriptEvent::Raw { line } => {
                stdout.write_all(line.as_bytes())?;
                if !line.ends_with('\n') {
                    stdout.write_all(b"\n")?;
                }
                stdout.flush()?;
            }
            ScriptEvent::Lifecycle { state } => {
                emit(stdout, &json!({"type":"lifecycle","state":state}))?;
            }
            ScriptEvent::Text { text, bytes } => {
                if let Some(count) = *bytes {
                    write_flood(stdout, count)?;
                } else {
                    emit(stdout, &json!({"type":"text","text":text}))?;
                }
            }
            ScriptEvent::Terminal { state } => {
                emit(stdout, &json!({"type":"terminal","state":state}))?;
            }
            ScriptEvent::Cancelled => {
                emit(stdout, &json!({"type":"cancelled"}))?;
                return Ok(ScriptOutcome::Cancelled);
            }
        }
    }
    Ok(ScriptOutcome::Completed)
}

fn emit(stdout: &mut impl Write, value: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *stdout, value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

fn write_flood(stdout: &mut impl Write, bytes: u64) -> io::Result<()> {
    let chunk = [b'x'; 4096];
    let mut remaining = bytes;
    while remaining > 0 {
        let take = usize::try_from(remaining.min(4096)).unwrap_or(4096);
        stdout.write_all(&chunk[..take])?;
        remaining -= u64::try_from(take).unwrap_or(0);
    }
    stdout.flush()
}

fn read_cancel(stdin: &mut impl BufRead) -> io::Result<bool> {
    let mut line = String::new();
    let read = stdin.read_line(&mut line)?;
    if read == 0 {
        return Ok(true);
    }
    let trimmed = line.trim();
    Ok(trimmed.eq_ignore_ascii_case("cancel")
        || trimmed.contains("\"type\":\"cancel\"")
        || trimmed.contains("\"type\": \"cancel\""))
}

fn resolve_marker_path(path: &str, current_dir: Option<&Path>) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        candidate
    } else if let Some(dir) = current_dir {
        dir.join(candidate)
    } else {
        candidate
    }
}

/// Reads a script file from disk. The path is a caller-supplied test fixture.
pub fn load_script_file(path: &Path) -> Result<Vec<ScriptEvent>, String> {
    let source = fs::read_to_string(path).map_err(|error| format!("read script: {error}"))?;
    parse_script(&source)
}

/// Parses argv after the executable name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CliRequest {
    ScriptFile(PathBuf),
    Json(String),
    Hang,
}

pub fn parse_args<I, S>(arguments: I) -> Result<CliRequest, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut request = None;
    let mut arguments = arguments.into_iter();
    while let Some(argument) = arguments.next() {
        match argument.as_ref() {
            "--script" => {
                let path = arguments
                    .next()
                    .ok_or_else(|| "missing --script path".to_owned())?;
                request = Some(CliRequest::ScriptFile(PathBuf::from(path.as_ref())));
            }
            "--json" => {
                let json = arguments
                    .next()
                    .ok_or_else(|| "missing --json payload".to_owned())?;
                request = Some(CliRequest::Json(json.as_ref().to_owned()));
            }
            "--hang" => request = Some(CliRequest::Hang),
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    request.ok_or_else(|| "one of --script, --json, or --hang is required".into())
}

/// Process entry used by `main` and by in-crate tests.
#[must_use]
pub fn run_request(request: &CliRequest) -> i32 {
    let events = match request {
        CliRequest::Hang => vec![ScriptEvent::Hang],
        CliRequest::Json(source) => match parse_script(source) {
            Ok(events) => events,
            Err(_) => return 2,
        },
        CliRequest::ScriptFile(path) => match load_script_file(path) {
            Ok(events) => events,
            Err(_) => return 2,
        },
    };
    let stdin = io::stdin();
    let mut locked_stdin = BufReader::new(stdin.lock());
    let mut stdout = io::stdout().lock();
    let current_exe =
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("mesh-fake-adapter"));
    let current_dir = std::env::current_dir().ok();
    match run_script(
        &events,
        &mut stdout,
        &mut locked_stdin,
        &current_exe,
        current_dir.as_deref(),
    ) {
        Ok(ScriptOutcome::Completed | ScriptOutcome::Cancelled) => 0,
        Ok(ScriptOutcome::Crashed(code)) => code,
        Err(_) => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parses_shared_vocabulary_and_extensions() {
        let events = parse_script(
            r#"[{"type":"lifecycle","state":"RUNNING"},{"type":"delay","milliseconds":25},{"type":"terminal","state":"SUCCEEDED"}]"#,
        )
        .expect("parse");
        assert_eq!(events.len(), 3);
        assert!(matches!(events[2], ScriptEvent::Terminal { .. }));
    }

    #[test]
    fn run_script_emits_ndjson_and_honors_crash() {
        let events =
            parse_script(r#"[{"type":"lifecycle","state":"RUNNING"},{"type":"crash","code":137}]"#)
                .expect("parse");
        let mut stdout = Vec::new();
        let mut stdin = Cursor::new(Vec::<u8>::new());
        let outcome = run_script(
            &events,
            &mut stdout,
            &mut stdin,
            Path::new("mesh-fake-adapter"),
            None,
        )
        .expect("run");
        assert_eq!(outcome, ScriptOutcome::Crashed(137));
        let text = String::from_utf8(stdout).expect("utf8");
        assert!(text.contains(r#""type":"lifecycle""#));
        assert!(!text.contains("137"));
    }

    #[test]
    fn approval_cancel_line_stops_before_terminal() {
        let events = parse_script(
            r#"[{"type":"approval","operation":"write_file"},{"type":"terminal","state":"SUCCEEDED"}]"#,
        )
        .expect("parse");
        let mut stdout = Vec::new();
        let mut stdin = Cursor::new(b"{\"type\":\"cancel\"}\n".to_vec());
        let outcome = run_script(
            &events,
            &mut stdout,
            &mut stdin,
            Path::new("mesh-fake-adapter"),
            None,
        )
        .expect("run");
        assert_eq!(outcome, ScriptOutcome::Cancelled);
        let text = String::from_utf8(stdout).expect("utf8");
        assert!(text.contains("approval"));
        assert!(text.contains("cancelled"));
        assert!(!text.contains("SUCCEEDED"));
    }

    #[test]
    fn parse_args_accepts_script_json_and_hang() {
        assert_eq!(parse_args(["--hang"]).expect("hang"), CliRequest::Hang);
        assert!(matches!(
            parse_args(["--json", "[{\"type\":\"cancelled\"}]"]).expect("json"),
            CliRequest::Json(_)
        ));
        assert!(parse_args(["--nope"]).is_err());
    }
}
