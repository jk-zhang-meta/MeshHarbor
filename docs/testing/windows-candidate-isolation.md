# Isolated Windows candidate fixtures

Before running a candidate daemon on Surface, use a dedicated native build:

```powershell
cargo build --locked -p meshharbord --bin meshharbord --features full-hw,meshharbor-node-core/test-fixtures
$env:MESHHARBORD_TEST_STATE_ROOT = 'C:\path\to\private-task\isolated-state'
```

Bind the executable hash to that exact source/build receipt. Set the override
for enrollment and every daemon process, before any appdirs resolution. Use a
new absolute task directory; a relative override fails closed. APPDATA and
LOCALAPPDATA overrides alone do not isolate Windows KnownFolders.

The existing `test-fixtures` feature enables this override. Ordinary builds
ignore it. It covers per-user directories, machine-global directories and
the SYSTEM worker's profile-relative store; legacy migrations are skipped.
Keep candidate config, logs, browser state and secrets in private task runtime.

Before enrollment, run `scripts/windows-candidate-state.ps1 -Mode Snapshot
-SnapshotRoot <absolute-private-snapshot-dir>` as the same Windows user whose
interactive session will own the candidate. This saves the current and legacy
per-person keep-busy files and their hashes, timestamps and ACLs. After stopping
the candidate, run the same script with `-Mode Compare`. A difference fails the
round and retains the backups; never guess a previous policy or overwrite a
concurrent user change. Archive only the comparison receipt, not policy bytes.

The old RC R6 coordinator and X1 helper are historical evidence. Future Surface
candidate runs must use this feature/root and the before/after guard, in
addition to their existing exact-task/process/firewall cleanup and authorization.
