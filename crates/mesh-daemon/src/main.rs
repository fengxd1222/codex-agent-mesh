//! Strict process entry point for the single Windows runtime artifact.

#![forbid(unsafe_code)]

use std::{
    env,
    ffi::OsString,
    io::{self, Write},
    process::ExitCode,
};

use mesh_daemon::{
    cli::{self, CliMode},
    windows_control::{self, ControlCommandOutput, ControlDispatchResult},
    windows_runtime::{self, WindowsRuntimeError},
};

fn main() -> ExitCode {
    ExitCode::from(run(env::args_os().skip(1)))
}

fn run(arguments: impl IntoIterator<Item = OsString>) -> u8 {
    let Ok(mode) = cli::parse_cli(arguments) else {
        write_stderr("invalid command line");
        return cli::EXIT_LIFECYCLE;
    };

    match mode {
        CliMode::Setup => write_control(&setup()),
        CliMode::Status => finish_control(windows_control::dispatch_status()),
        CliMode::Start => finish_control(windows_control::dispatch_start()),
        CliMode::Remove { purge_data } => {
            finish_control(windows_control::dispatch_remove(purge_data))
        }
        CliMode::BridgeBootstrap => match windows_runtime::run_bridge_bootstrap() {
            Ok(exit_code) => exit_code,
            Err(error) => write_runtime_error(error),
        },
        CliMode::Bridge => match windows_runtime::run_stable_bridge() {
            Ok(()) => cli::EXIT_SUCCESS,
            Err(error) => write_runtime_error(error),
        },
        CliMode::Daemon => match windows_runtime::run_daemon() {
            Ok(()) => cli::EXIT_SUCCESS,
            Err(error) => write_runtime_error(error),
        },
        CliMode::Follow { task_id } => match mesh_daemon::follow::run_follow(task_id.as_deref()) {
            Ok(()) => cli::EXIT_SUCCESS,
            Err(error) => {
                write_stderr(error.to_string().as_str());
                cli::EXIT_LIFECYCLE
            }
        },
    }
}

#[cfg(any(debug_assertions, feature = "unsigned-development"))]
fn setup() -> ControlCommandOutput {
    windows_control::setup_unsigned_development()
}

#[cfg(not(any(debug_assertions, feature = "unsigned-development")))]
fn setup() -> ControlCommandOutput {
    windows_control::setup_official()
}

fn finish_control(dispatch: ControlDispatchResult) -> u8 {
    let mut stdout = io::stdout().lock();
    finish_control_to(dispatch, &mut stdout)
}

fn finish_control_to(dispatch: ControlDispatchResult, output: &mut impl Write) -> u8 {
    match dispatch {
        ControlDispatchResult::Local(result) => write_control_to(&result, output),
        ControlDispatchResult::ForwardedExit(exit_code) => exit_code,
    }
}

fn write_control(output: &ControlCommandOutput) -> u8 {
    let mut stdout = io::stdout().lock();
    write_control_to(output, &mut stdout)
}

fn write_control_to(output: &ControlCommandOutput, destination: &mut impl Write) -> u8 {
    let exit_code = output.exit_code;
    let encoded = output.to_json_bytes();
    if destination
        .write_all(&encoded)
        .and_then(|()| destination.write_all(b"\n"))
        .and_then(|()| destination.flush())
        .is_err()
    {
        write_stderr("control output failed");
        return cli::EXIT_RUNTIME;
    }
    exit_code
}

fn write_runtime_error(error: WindowsRuntimeError) -> u8 {
    write_stderr(error.message());
    error.exit_code()
}

fn write_stderr(message: &str) {
    let mut stderr = io::stderr().lock();
    let _ = stderr
        .write_all(b"mesh-daemon: ")
        .and_then(|()| stderr.write_all(message.as_bytes()))
        .and_then(|()| stderr.write_all(b"\n"))
        .and_then(|()| stderr.flush());
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn local_control_writes_exactly_one_json_line_and_preserves_exit() {
        let output = ControlCommandOutput {
            exit_code: cli::EXIT_LIFECYCLE,
            body: json!({
                "kind": "control_result",
                "operation": "status",
                "ok": false
            }),
        };
        let mut bytes = Vec::new();
        assert_eq!(
            finish_control_to(ControlDispatchResult::Local(output), &mut bytes),
            cli::EXIT_LIFECYCLE
        );
        assert_eq!(
            bytes,
            b"{\"kind\":\"control_result\",\"ok\":false,\"operation\":\"status\"}\n"
        );
    }

    #[test]
    fn forwarded_control_exit_never_emits_a_second_stdout_object() {
        let mut bytes = Vec::new();
        assert_eq!(
            finish_control_to(ControlDispatchResult::ForwardedExit(17), &mut bytes),
            17
        );
        assert!(bytes.is_empty());
    }

    #[test]
    fn output_failure_overrides_a_nominal_control_success() {
        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
                Err(io::Error::other("injected output failure"))
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::other("injected output failure"))
            }
        }

        let output = ControlCommandOutput {
            exit_code: cli::EXIT_SUCCESS,
            body: json!({"kind": "control_result", "ok": true}),
        };
        assert_eq!(
            write_control_to(&output, &mut FailingWriter),
            cli::EXIT_RUNTIME
        );
    }
}
