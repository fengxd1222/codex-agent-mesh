//! Test-only fake adapter process. Not part of the plugin runtime allowlist.

#![forbid(unsafe_code)]

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments: Vec<String> = env::args().skip(1).collect();
    let Ok(request) = mesh_fake_adapter::parse_args(&arguments) else {
        return ExitCode::from(2);
    };
    let code = mesh_fake_adapter::run_request(&request);
    if code == 0 {
        ExitCode::SUCCESS
    } else {
        std::process::exit(code);
    }
}
