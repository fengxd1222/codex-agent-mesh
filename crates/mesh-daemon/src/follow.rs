//! Read-only terminal follow: durable events as a scrolling log.
//!
//! This is not a provider TTY. It reprints the same persisted events that
//! `wait_task` and the dashboard already read.

use std::io::{self, IsTerminal, Write};

use std::thread;
use std::time::Duration;

use serde_json::Value;
use thiserror::Error;

use crate::install_record::InstallRecordStore;
use crate::install_store::StableInstallRecordStore;
use crate::reader::{PublicEvent, ReaderPool, TaskSummary};
use crate::storage::StorageError;

const POLL: Duration = Duration::from_millis(200);
const PAGE: usize = 50;
const READ_TIMEOUT: Duration = Duration::from_secs(2);
const INITIAL_BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(2);

/// Redaction-safe follow failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FollowError {
    #[error("stable installation is absent")]
    Absent,
    #[error("follow target was not found")]
    NotFound,
    #[error("follow storage is unavailable")]
    Storage,
    #[error("follow output is closed")]
    Output,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FollowReadClass {
    Transient,
    Missing,
    Permanent,
}

/// Follows one task, or the newest task when `task_id` is omitted.
///
/// # Errors
///
/// Returns [`FollowError::Absent`] when no stable install exists,
/// [`FollowError::NotFound`] when the task id is missing, and
/// [`FollowError::Storage`] when the event log cannot be read.
pub fn run_follow(task_id: Option<&str>) -> Result<(), FollowError> {
    let (reader, consumer_id) = open_reader()?;
    let task_id = match task_id {
        Some(task_id) => task_id.to_owned(),
        None => newest_task_id(&reader)?,
    };
    let mut stdout = io::stdout();
    let color = color_enabled(&stdout);
    if color {
        mesh_win32::enable_stdout_virtual_terminal();
    }
    follow_loop(
        &ReaderFollow {
            reader: &reader,
            consumer_id: &consumer_id,
        },
        &task_id,
        &mut stdout,
        color,
    )
}

fn color_enabled(stdout: &io::Stdout) -> bool {
    stdout.is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

fn open_reader() -> Result<(ReaderPool, String), FollowError> {
    let store = StableInstallRecordStore::open().map_err(|_| FollowError::Storage)?;
    let record = store
        .load()
        .map_err(|_| FollowError::Storage)?
        .ok_or(FollowError::Absent)?;
    let relative = record
        .data_relative_path
        .as_ref()
        .ok_or(FollowError::Absent)?;
    let local = mesh_win32::current_user_local_app_data().map_err(|_| FollowError::Storage)?;
    let data_root = local.join("codex-agent-mesh").join(relative.as_str());
    let reader = ReaderPool::open(data_root).map_err(|_| FollowError::Storage)?;
    Ok((reader, record.consumer_id.as_str().to_owned()))
}

fn newest_task_id(reader: &ReaderPool) -> Result<String, FollowError> {
    let tasks = reader
        .task_summaries(1, READ_TIMEOUT)
        .map_err(|_| FollowError::Storage)?;
    tasks
        .into_iter()
        .next()
        .map(|task| task.task_id)
        .ok_or(FollowError::NotFound)
}

trait FollowFeed {
    fn events(&self, task_id: &str, after_seq: i64) -> Result<Vec<PublicEvent>, StorageError>;
    fn terminal(&self, task_id: &str) -> Result<bool, StorageError>;
}

struct ReaderFollow<'a> {
    reader: &'a ReaderPool,
    consumer_id: &'a str,
}

impl FollowFeed for ReaderFollow<'_> {
    fn events(&self, task_id: &str, after_seq: i64) -> Result<Vec<PublicEvent>, StorageError> {
        self.reader
            .public_events_after(
                task_id,
                after_seq,
                PAGE,
                READ_TIMEOUT,
                Some(self.consumer_id),
            )
            .map(|page| page.events)
    }

    fn terminal(&self, task_id: &str) -> Result<bool, StorageError> {
        let tasks = self.reader.task_summaries(200, READ_TIMEOUT)?;
        match tasks.into_iter().find(|task| task.task_id == task_id) {
            Some(task) => Ok(is_terminal(&task)),
            None => Err(StorageError::InvalidRequest),
        }
    }
}

fn classify_follow_storage(error: &StorageError) -> FollowReadClass {
    match error {
        StorageError::QueryDeadline | StorageError::ReaderSaturated => FollowReadClass::Transient,
        StorageError::InvalidRequest => FollowReadClass::Missing,
        _ => FollowReadClass::Permanent,
    }
}

fn next_follow_backoff(current: Duration) -> Duration {
    current.saturating_mul(2).min(MAX_BACKOFF)
}

fn follow_loop<S: FollowFeed, W: Write>(
    source: &S,
    task_id: &str,
    output: &mut W,
    color: bool,
) -> Result<(), FollowError> {
    let mut stream = FollowStream {
        color,
        ..FollowStream::default()
    };
    writeln!(
        output,
        "{}",
        stream.paint(Tone::Dim, &format!("follow  {task_id}"))
    )
    .map_err(|_| FollowError::Output)?;
    let _ = output.flush();
    let mut after_seq = 0_i64;
    let mut backoff = INITIAL_BACKOFF;
    loop {
        match source.events(task_id, after_seq) {
            Ok(events) => {
                backoff = INITIAL_BACKOFF;
                for event in &events {
                    if let Some(piece) = follow_piece(event) {
                        stream
                            .write(output, event.seq, &piece)
                            .map_err(|_| FollowError::Output)?;
                    }
                    after_seq = event.seq;
                }
                let _ = output.flush();
                match source.terminal(task_id) {
                    Ok(true) if events.is_empty() => {
                        stream.finish(output).map_err(|_| FollowError::Output)?;
                        return Ok(());
                    }
                    Ok(_) => {
                        if events.is_empty() {
                            thread::sleep(POLL);
                        }
                    }
                    Err(error) => match classify_follow_storage(&error) {
                        FollowReadClass::Transient => {
                            thread::sleep(backoff);
                            backoff = next_follow_backoff(backoff);
                        }
                        FollowReadClass::Missing => return Err(FollowError::NotFound),
                        FollowReadClass::Permanent => return Err(FollowError::Storage),
                    },
                }
            }
            Err(error) => match classify_follow_storage(&error) {
                FollowReadClass::Transient => {
                    thread::sleep(backoff);
                    backoff = next_follow_backoff(backoff);
                }
                FollowReadClass::Missing => return Err(FollowError::NotFound),
                FollowReadClass::Permanent => return Err(FollowError::Storage),
            },
        }
    }
}

fn is_terminal(task: &TaskSummary) -> bool {
    matches!(
        task.state.as_str(),
        "SUCCEEDED" | "FAILED" | "CANCELLED" | "NEEDS_ATTENTION"
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LineKind {
    Meta,
    Tool,
    Result,
    Warn,
    Error,
    DoneOk,
    DoneBad,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Tone {
    Dim,
    Tool,
    Warn,
    Error,
    Ok,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FollowPiece {
    Stream { channel: &'static str, text: String },
    Line { kind: LineKind, display: String },
}

struct Fold {
    channel: &'static str,
    seq: i64,
    buf: String,
    live: bool,
}

struct FollowStream {
    channel: Option<&'static str>,
    color: bool,
    fold: Option<Fold>,
    text_hold: Option<(i64, String)>,
}

impl Default for FollowStream {
    fn default() -> Self {
        Self {
            channel: None,
            color: false,
            fold: None,
            text_hold: None,
        }
    }
}

impl FollowStream {
    fn write(&mut self, output: &mut impl Write, seq: i64, piece: &FollowPiece) -> io::Result<()> {
        match piece {
            FollowPiece::Stream { channel, text } if *channel == "think" => {
                self.write_fold(output, seq, "think", text)
            }
            FollowPiece::Stream { channel, text } => self.write_stream(output, seq, channel, text),
            FollowPiece::Line { kind, display } => {
                self.flush_text(output)?;
                self.flush_fold(output)?;
                if self.channel.take().is_some() {
                    self.end_stream(output)?;
                    writeln!(output)?;
                }
                let gutter = self.paint(Tone::Dim, &format!("{seq:>5}  "));
                writeln!(output, "{gutter}{}", self.paint_line(*kind, display))
            }
        }
    }

    fn write_stream(
        &mut self,
        output: &mut impl Write,
        seq: i64,
        channel: &'static str,
        text: &str,
    ) -> io::Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        if channel != "text" {
            self.flush_text(output)?;
            if self.channel != Some(channel) {
                self.flush_fold(output)?;
                if self.channel.take().is_some() {
                    self.end_stream(output)?;
                    writeln!(output)?;
                }
                self.channel = Some(channel);
                write!(output, "{}", self.paint(Tone::Dim, &format!("{seq:>5}  ")))?;
            }
            write!(output, "{text}")?;
            return output.flush();
        }
        self.flush_fold(output)?;
        if self.channel.take().is_some() {
            self.end_stream(output)?;
            writeln!(output)?;
        }
        match &mut self.text_hold {
            Some((_, buf)) => {
                if needs_space(buf, text) {
                    buf.push(' ');
                }
                buf.push_str(text);
            }
            None => self.text_hold = Some((seq, text.to_owned())),
        }
        Ok(())
    }

    fn write_fold(
        &mut self,
        output: &mut impl Write,
        seq: i64,
        channel: &'static str,
        text: &str,
    ) -> io::Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        if self.channel.take().is_some() {
            self.end_stream(output)?;
            writeln!(output)?;
        }
        if self
            .fold
            .as_ref()
            .is_none_or(|fold| fold.channel != channel)
        {
            self.flush_text(output)?;
            self.flush_fold(output)?;
            self.fold = Some(Fold {
                channel,
                seq,
                buf: String::new(),
                live: false,
            });
        }
        if let Some(fold) = &mut self.fold {
            if needs_space(&fold.buf, text) {
                fold.buf.push(' ');
            }
            fold.buf.push_str(text);
        }
        if self.color {
            self.repaint_fold(output)?;
        }
        Ok(())
    }

    fn flush_fold(&mut self, output: &mut impl Write) -> io::Result<()> {
        let Some(fold) = self.fold.take() else {
            return Ok(());
        };
        let line = self.fold_line(&fold);
        if fold.live {
            write!(output, "\x1b[2K\r{line}\n")?;
        } else {
            writeln!(output, "{line}")?;
        }
        output.flush()
    }

    fn repaint_fold(&mut self, output: &mut impl Write) -> io::Result<()> {
        let Some(fold) = &self.fold else {
            return Ok(());
        };
        let line = self.fold_line(fold);
        if let Some(fold) = &mut self.fold {
            fold.live = true;
        }
        write!(output, "\x1b[2K\r{line}")?;
        output.flush()
    }

    fn fold_line(&self, fold: &Fold) -> String {
        let gutter = self.paint(Tone::Dim, &format!("{:>5}  ", fold.seq));
        let tag = self.paint(Tone::Dim, "think  ");
        let preview = self.paint(Tone::Dim, &fold_preview(&fold.buf));
        format!("{gutter}{tag}{preview}")
    }

    fn finish(&mut self, output: &mut impl Write) -> io::Result<()> {
        self.flush_text(output)?;
        self.flush_fold(output)?;
        if self.channel.take().is_some() {
            self.end_stream(output)?;
            writeln!(output)?;
        }
        Ok(())
    }

    fn flush_text(&mut self, output: &mut impl Write) -> io::Result<()> {
        let Some((seq, body)) = self.text_hold.take() else {
            return Ok(());
        };
        if should_fold_text(&body) {
            let gutter = self.paint(Tone::Dim, &format!("{seq:>5}  "));
            let tag = self.paint(Tone::Dim, "text   ");
            let preview = self.paint(Tone::Dim, &fold_preview(&body));
            return writeln!(output, "{gutter}{tag}{preview}");
        }
        self.write_wrapped(output, seq, &body)
    }

    fn write_wrapped(&self, output: &mut impl Write, seq: i64, text: &str) -> io::Result<()> {
        const WIDTH: usize = 88;
        let gutter = self.paint(Tone::Dim, &format!("{seq:>5}  "));
        let indent = " ".repeat(7);
        let mut col = 0_usize;
        let mut started = false;
        for ch in text.chars() {
            if ch == '\n' {
                writeln!(output)?;
                col = 0;
                continue;
            }
            if col == 0 {
                if started {
                    write!(output, "{indent}")?;
                } else {
                    write!(output, "{gutter}")?;
                    started = true;
                }
                col = 7;
            }
            if col >= WIDTH {
                writeln!(output)?;
                write!(output, "{indent}")?;
                col = 7;
            }
            write!(output, "{ch}")?;
            col += 1;
        }
        if started || !text.is_empty() {
            writeln!(output)?;
        }
        output.flush()
    }

    fn end_stream(&self, output: &mut impl Write) -> io::Result<()> {
        if self.color {
            write!(output, "{}", ansi::RESET)?;
        }
        Ok(())
    }

    fn paint(&self, tone: Tone, text: &str) -> String {
        if self.color {
            format!("{}{text}{}", tone.code(), ansi::RESET)
        } else {
            text.to_owned()
        }
    }

    fn paint_line(&self, kind: LineKind, display: &str) -> String {
        let tone = match kind {
            LineKind::Meta | LineKind::Result => Tone::Dim,
            LineKind::Tool => Tone::Tool,
            LineKind::Warn => Tone::Warn,
            LineKind::Error | LineKind::DoneBad => Tone::Error,
            LineKind::DoneOk => Tone::Ok,
        };
        self.paint(tone, display)
    }
}

mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const DIM: &str = "\x1b[2m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const CYAN: &str = "\x1b[36m";
}

impl Tone {
    const fn code(self) -> &'static str {
        match self {
            Self::Dim => ansi::DIM,
            Self::Tool => ansi::CYAN,
            Self::Warn => ansi::YELLOW,
            Self::Error => ansi::RED,
            Self::Ok => ansi::GREEN,
        }
    }
}

/// One scrolling line for a persisted public event. Unknown kinds are skipped.
#[must_use]
pub fn format_follow_line(event: &PublicEvent) -> Option<String> {
    match follow_piece(event)? {
        FollowPiece::Stream { text, .. } => Some(text),
        FollowPiece::Line { display, .. } => Some(display),
    }
}

fn follow_piece(event: &PublicEvent) -> Option<FollowPiece> {
    let event_type = event.value.get("event_type")?.as_str()?;
    let payload = event.value.get("payload")?;
    match event_type {
        "text_delta" => payload
            .get("text")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(|text| FollowPiece::Stream {
                channel: "text",
                text: text.to_owned(),
            }),
        "state_changed" => payload
            .get("state")
            .and_then(Value::as_str)
            .map(|state| line(LineKind::Meta, format!("[{state}]"))),
        "dispatch_phase" => payload
            .get("phase")
            .and_then(Value::as_str)
            .map(|phase| line(LineKind::Meta, format!("[{phase}]"))),
        "attempt_started" => Some(line(LineKind::Meta, "[attempt started]")),
        "warning" => payload
            .get("warning")
            .and_then(Value::as_str)
            .and_then(activity_piece),
        "protocol_error" => payload
            .get("message")
            .and_then(Value::as_str)
            .map(|message| line(LineKind::Error, format!("[error] {message}"))),
        "usage" => {
            let input = payload.get("input_tokens").and_then(Value::as_u64)?;
            let output = payload.get("output_tokens").and_then(Value::as_u64)?;
            Some(line(
                LineKind::Meta,
                format!("[usage] in={input} out={output}"),
            ))
        }
        "terminal" => payload.get("state").and_then(Value::as_str).map(|state| {
            let kind = if state == "SUCCEEDED" {
                LineKind::DoneOk
            } else {
                LineKind::DoneBad
            };
            line(kind, format!("[done] {state}"))
        }),
        _ => None,
    }
}

fn activity_piece(warning: &str) -> Option<FollowPiece> {
    if is_noise_warning(warning) {
        return None;
    }
    if let Some(rest) = warning.strip_prefix("thinking: ") {
        return Some(FollowPiece::Stream {
            channel: "think",
            text: rest.to_owned(),
        });
    }
    if let Some(rest) = warning.strip_prefix("tool: ") {
        return Some(line(LineKind::Tool, tool_label(rest)));
    }
    if let Some(rest) = warning.strip_prefix("tool result: ") {
        return Some(line(
            LineKind::Result,
            format!("out    {}", fold_preview(rest)),
        ));
    }
    if let Some(rest) = warning.strip_prefix("status: ") {
        return Some(line(LineKind::Meta, format!("status {rest}")));
    }
    Some(line(LineKind::Warn, format!("warn   {warning}")))
}

fn tool_label(rest: &str) -> String {
    let mut parts = rest.splitn(2, char::is_whitespace);
    let name = parts.next().unwrap_or("tool");
    let detail = parts.next().unwrap_or("").trim();
    let tag = if name.eq_ignore_ascii_case("bash") {
        "bash"
    } else {
        "tool"
    };
    if detail.is_empty() {
        tag.to_owned()
    } else {
        format!("{tag:<6}{}", fold_preview(detail))
    }
}

fn is_noise_warning(warning: &str) -> bool {
    let trimmed = warning.trim();
    trimmed == "Adapter reported a deterministic warning."
        || trimmed.eq_ignore_ascii_case("[redacted]")
        || trimmed.eq_ignore_ascii_case("redacted")
}

fn needs_space(buf: &str, next: &str) -> bool {
    let Some(prev) = buf.chars().last() else {
        return false;
    };
    let Some(first) = next.chars().next() else {
        return false;
    };
    prev.is_ascii_alphanumeric() && first.is_ascii_alphanumeric()
}

fn should_fold_text(body: &str) -> bool {
    let pathish = body
        .split_whitespace()
        .filter(|token| looks_like_path(token))
        .count();
    if pathish >= 3 {
        return true;
    }
    !body.contains('\n') && body.chars().count() > 160 && body.contains(['/', '\\'])
}

fn looks_like_path(token: &str) -> bool {
    token.contains('/')
        || token.contains('\\')
        || token.ends_with(".rs")
        || token.ends_with(".md")
        || token.ends_with(".toml")
        || token.ends_with(".json")
        || token.ends_with(".js")
        || token.ends_with(".mjs")
        || token.ends_with(".exe")
}

fn fold_preview(body: &str) -> String {
    let flat: String = body.split_whitespace().collect::<Vec<_>>().join(" ");
    const LIMIT: usize = 56;
    let count = flat.chars().count();
    if count == 0 {
        return "(empty)".into();
    }
    if count <= LIMIT {
        return flat;
    }
    let mut preview: String = flat.chars().take(LIMIT).collect();
    preview.push('…');
    preview
}

fn line(kind: LineKind, display: impl Into<String>) -> FollowPiece {
    FollowPiece::Line {
        kind,
        display: display.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(event_type: &str, payload: &Value) -> PublicEvent {
        PublicEvent {
            event_id: "e1".into(),
            task_id: "t1".into(),
            seq: 1,
            generation: 0,
            committed_at_us: 1,
            value: json!({
                "version": 1,
                "kind": "event",
                "event_id": "e1",
                "task_id": "t1",
                "seq": 1,
                "occurred_at_ms": 1,
                "event_type": event_type,
                "payload": payload
            }),
        }
    }

    #[test]
    fn follow_lines_print_text_and_lifecycle_without_raw_json() {
        assert_eq!(
            format_follow_line(&event("text_delta", &json!({"text": "ok"}))).as_deref(),
            Some("ok")
        );
        assert_eq!(
            format_follow_line(&event("state_changed", &json!({"state": "RUNNING"}))).as_deref(),
            Some("[RUNNING]")
        );
        assert_eq!(
            format_follow_line(&event("terminal", &json!({"state": "SUCCEEDED"}))).as_deref(),
            Some("[done] SUCCEEDED")
        );
        assert_eq!(
            format_follow_line(&event(
                "dispatch_phase",
                &json!({"phase": "PROCESS_STARTED"})
            ))
            .as_deref(),
            Some("[PROCESS_STARTED]")
        );
        assert!(
            format_follow_line(&event("tool_proposal", &json!({"operation_digest": "x"})))
                .is_none()
        );
        assert_eq!(
            format_follow_line(&event(
                "warning",
                &json!({"warning": "thinking: look at README"})
            ))
            .as_deref(),
            Some("look at README")
        );
        assert_eq!(
            format_follow_line(&event("warning", &json!({"warning": "tool: Bash ls"}))).as_deref(),
            Some("bash  ls")
        );
        assert_eq!(
            format_follow_line(&event(
                "warning",
                &json!({"warning": "tool result: a.rs b.rs c.rs d.rs e.rs"})
            ))
            .as_deref(),
            Some("out    a.rs b.rs c.rs d.rs e.rs")
        );
        assert!(
            format_follow_line(&event(
                "warning",
                &json!({"warning": "Adapter reported a deterministic warning."})
            ))
            .is_none()
        );
        assert!(format_follow_line(&event("warning", &json!({"warning": "[redacted]"}))).is_none());
    }

    #[test]
    fn follow_stream_concatenates_deltas_and_breaks_on_tools() {
        let mut stream = FollowStream::default();
        let mut out = Vec::new();
        stream
            .write(
                &mut out,
                1,
                &FollowPiece::Stream {
                    channel: "text",
                    text: "归".into(),
                },
            )
            .unwrap();
        stream
            .write(
                &mut out,
                2,
                &FollowPiece::Stream {
                    channel: "text",
                    text: "一".into(),
                },
            )
            .unwrap();
        stream
            .write(&mut out, 3, &line(LineKind::Tool, "bash  ls"))
            .unwrap();
        stream
            .write(
                &mut out,
                4,
                &FollowPiece::Stream {
                    channel: "think",
                    text: "look ".into(),
                },
            )
            .unwrap();
        stream
            .write(
                &mut out,
                5,
                &FollowPiece::Stream {
                    channel: "think",
                    text: "around".into(),
                },
            )
            .unwrap();
        stream.finish(&mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "    1  归一\n    3  bash  ls\n    4  think  look around\n"
        );
    }

    #[test]
    fn follow_stream_color_is_quiet_ansi_and_resets() {
        let mut stream = FollowStream {
            color: true,
            ..FollowStream::default()
        };
        let mut out = Vec::new();
        stream
            .write(&mut out, 7, &line(LineKind::Tool, "bash  ls"))
            .unwrap();
        let painted = String::from_utf8(out).unwrap();
        assert!(painted.contains("\u{1b}[36mbash  ls\u{1b}[0m"));
        assert!(painted.contains("\u{1b}[2m    7  \u{1b}[0m"));
        assert!(!painted.contains("\u{1b}[1m"), "no bold");
        assert!(!painted.contains("\u{1b}[5m"), "no blink");
    }

    #[test]
    fn tool_result_folds_to_one_preview_line() {
        let long = format!(
            "tool result: {}",
            (0..40)
                .map(|i| format!("file{i}.rs"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        let line = format_follow_line(&event("warning", &json!({ "warning": long }))).unwrap();
        assert!(line.starts_with("out    file0.rs"));
        assert!(line.ends_with('…'));
        assert_eq!(line.lines().count(), 1);
        assert!(line.chars().count() < 80);
    }

    #[test]
    fn assistant_path_dump_folds_instead_of_printing_the_wall() {
        let mut stream = FollowStream::default();
        let mut out = Vec::new();
        stream
            .write(
                &mut out,
                38,
                &FollowPiece::Stream {
                    channel: "text",
                    text: "以下文件包含文本 role_bindings：.trellis/spec/backend/durable-control-plane.md AGENTS.md crates/mesh-daemon/src/adapters/registry.rs crates/mesh-daemon/src/settings/default-config.toml".into(),
                },
            )
            .unwrap();
        stream.finish(&mut out).unwrap();
        let painted = String::from_utf8(out).unwrap();
        assert!(painted.starts_with("   38  text   "));
        assert_eq!(painted.lines().count(), 1);
        assert!(!painted.contains("default-config.toml"));
    }

    struct ScriptedFeed {
        pages: std::sync::Mutex<std::collections::VecDeque<Result<Vec<PublicEvent>, StorageError>>>,
        terminals: std::sync::Mutex<std::collections::VecDeque<Result<bool, StorageError>>>,
        afters: std::sync::Mutex<Vec<i64>>,
    }

    impl FollowFeed for ScriptedFeed {
        fn events(&self, _task_id: &str, after_seq: i64) -> Result<Vec<PublicEvent>, StorageError> {
            self.afters.lock().expect("afters").push(after_seq);
            self.pages
                .lock()
                .expect("pages")
                .pop_front()
                .expect("scripted page")
        }

        fn terminal(&self, _task_id: &str) -> Result<bool, StorageError> {
            self.terminals
                .lock()
                .expect("terminals")
                .pop_front()
                .expect("scripted terminal")
        }
    }

    struct FailWrite;

    impl Write for FailWrite {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn classify_follow_storage_retries_deadlines_not_corruption() {
        assert_eq!(
            classify_follow_storage(&StorageError::QueryDeadline),
            FollowReadClass::Transient
        );
        assert_eq!(
            classify_follow_storage(&StorageError::ReaderSaturated),
            FollowReadClass::Transient
        );
        assert_eq!(
            classify_follow_storage(&StorageError::InvalidRequest),
            FollowReadClass::Missing
        );
        assert_eq!(
            classify_follow_storage(&StorageError::BlobCorruption("x".into())),
            FollowReadClass::Permanent
        );
    }

    #[test]
    fn follow_backoff_doubles_up_to_two_seconds() {
        assert_eq!(
            next_follow_backoff(Duration::from_millis(50)),
            Duration::from_millis(100)
        );
        assert_eq!(
            next_follow_backoff(Duration::from_secs(2)),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn follow_retries_transient_storage_and_exits_on_empty_terminal_page() {
        let feed = ScriptedFeed {
            pages: std::sync::Mutex::new([Err(StorageError::QueryDeadline), Ok(Vec::new())].into()),
            terminals: std::sync::Mutex::new([Ok(true)].into()),
            afters: std::sync::Mutex::new(Vec::new()),
        };
        let mut out = Vec::new();
        follow_loop(&feed, "task-1", &mut out, false).expect("follow");
        assert_eq!(feed.afters.lock().expect("afters").as_slice(), &[0, 0]);
        assert!(
            String::from_utf8(out)
                .expect("utf8")
                .contains("follow  task-1")
        );
    }

    #[test]
    fn follow_keeps_cursor_across_transient_errors() {
        let page = vec![event("text_delta", &json!({"text": "hi"}))];
        let feed = ScriptedFeed {
            pages: std::sync::Mutex::new(
                [Ok(page), Err(StorageError::ReaderSaturated), Ok(Vec::new())].into(),
            ),
            terminals: std::sync::Mutex::new([Ok(false), Ok(true)].into()),
            afters: std::sync::Mutex::new(Vec::new()),
        };
        let mut out = Vec::new();
        follow_loop(&feed, "t1", &mut out, false).expect("follow");
        assert_eq!(feed.afters.lock().expect("afters").as_slice(), &[0, 1, 1]);
    }

    #[test]
    fn follow_permanent_storage_error_does_not_retry() {
        let feed = ScriptedFeed {
            pages: std::sync::Mutex::new(
                [Err(StorageError::BlobCorruption("events".into()))].into(),
            ),
            terminals: std::sync::Mutex::new(std::collections::VecDeque::new()),
            afters: std::sync::Mutex::new(Vec::new()),
        };
        let mut out = Vec::new();
        assert_eq!(
            follow_loop(&feed, "task-1", &mut out, false),
            Err(FollowError::Storage)
        );
    }

    #[test]
    fn follow_missing_task_is_not_retried() {
        let feed = ScriptedFeed {
            pages: std::sync::Mutex::new([Err(StorageError::InvalidRequest)].into()),
            terminals: std::sync::Mutex::new(std::collections::VecDeque::new()),
            afters: std::sync::Mutex::new(Vec::new()),
        };
        let mut out = Vec::new();
        assert_eq!(
            follow_loop(&feed, "missing", &mut out, false),
            Err(FollowError::NotFound)
        );
    }

    #[test]
    fn follow_output_disconnect_is_not_a_storage_error() {
        let feed = ScriptedFeed {
            pages: std::sync::Mutex::new(std::collections::VecDeque::new()),
            terminals: std::sync::Mutex::new(std::collections::VecDeque::new()),
            afters: std::sync::Mutex::new(Vec::new()),
        };
        let mut out = FailWrite;
        assert_eq!(
            follow_loop(&feed, "task-1", &mut out, false),
            Err(FollowError::Output)
        );
    }
}
