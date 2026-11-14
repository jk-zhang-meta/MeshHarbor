// SPDX-License-Identifier: MPL-2.0
//! MSI-only entrypoint, before daemon initialization. The new MSI embeds this
//! executable so old updaters need no knowledge of the task transaction.
const SCRIPT: &str = include_str!("../wix/task-transaction.ps1");

fn valid_request(args: &[String]) -> bool {
    args.len() == 4
        && args[1] == "msi-task-transaction"
        && matches!(
            args[2].as_str(),
            "snapshot" | "restore-or-create" | "rollback" | "start-if-enabled"
        )
        && args[3].len() == 38
        && args[3].bytes().enumerate().all(|(i, b)| match i {
            0 => b == b'{',
            37 => b == b'}',
            9 | 14 | 19 | 24 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        })
}

#[cfg(windows)]
pub fn run_if_requested() -> Option<std::io::Result<()>> {
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    use std::process::Stdio;
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("msi-task-transaction") {
        return None;
    }
    Some((|| {
        if !valid_request(&args) {
            return Err(std::io::Error::other(
                "invalid MSI task transaction request",
            ));
        }
        let script = format!("{SCRIPT}\nInvoke-TaskTransaction $env:MH_MSI_OPERATION $env:MH_MSI_PRODUCT $env:MH_MSI_EXE\n");
        let powershell = std::path::PathBuf::from(
            std::env::var_os("SystemRoot")
                .ok_or_else(|| std::io::Error::other("SystemRoot missing"))?,
        )
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        // Fixed command; script travels over a pipe rather than a command line
        // (avoids Windows' 32K command-line limit and quoting/injection issues).
        let mut child = std::process::Command::new(powershell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                "$code=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($code))",
            ])
            .env("MH_MSI_OPERATION", &args[2])
            .env("MH_MSI_PRODUCT", &args[3])
            .env("MH_MSI_EXE", std::env::current_exe()?)
            .stdin(Stdio::piped())
            .creation_flags(0x0800_0000)
            .spawn()?;
        let write = child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(script.as_bytes());
        let status = child.wait()?;
        write?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "MSI task transaction {} failed: {status}; recovery material retained",
                args[2]
            )));
        }
        Ok(())
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transaction_accepts_only_closed_operations_and_product_identity() {
        let mut args = vec![
            "daemon".into(),
            "msi-task-transaction".into(),
            "snapshot".into(),
            "{1F2D7B1C-8B2F-4D2E-B1A3-6B1E2C7E4D91}".into(),
        ];
        assert!(valid_request(&args));
        args[2] = "delete".into();
        assert!(!valid_request(&args));
        args[2] = "rollback".into();
        args[3] = "../../state".into();
        assert!(!valid_request(&args));
    }
    #[test]
    fn snapshot_script_has_no_localized_error_or_password_fallback() {
        assert!(SCRIPT.contains("-2147024894"));
        assert!(SCRIPT.contains("$logon -eq 1 -or $logon -eq 6"));
        assert!(SCRIPT.contains("GetSecurityDescriptor(7)"));
    }
}
