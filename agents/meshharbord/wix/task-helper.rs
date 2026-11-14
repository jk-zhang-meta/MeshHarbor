// SPDX-License-Identifier: MPL-2.0
//! Statically linked, std-only pre-install helper. No VC++/media/daemon runtime.
#![cfg_attr(windows, windows_subsystem = "windows")]
#[path = "../src/msi_task_transaction.rs"]
mod transaction;
fn main() -> std::process::ExitCode {
    #[cfg(windows)]
    match transaction::run_if_requested() {
        Some(Ok(())) => return std::process::ExitCode::SUCCESS,
        Some(Err(error)) => eprintln!("{error}"),
        None => eprintln!("MSI task transaction command required"),
    }
    std::process::ExitCode::FAILURE
}
