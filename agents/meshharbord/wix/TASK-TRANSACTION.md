# Per-user MSI task preservation

The new MSI owns this compatibility path, including when an old 0.4.154/157
updater launches it. It does not depend on a new updater already being installed.
No conversion to an SCM service or another account is performed.

## Build

Before candle/light, run `build-task-helper.ps1 -Output
<staging>\target\release\meshharbor-msi-task-helper.exe` in the x64 MSVC developer
environment. It uses pinned Rust 1.95.0 and `+crt-static`. The std-only helper
shares `src/msi_task_transaction.rs` with the daemon but links no daemon, codec,
VC++ or async runtime. Snapshot/rollback can therefore execute before the
application and its bundled CRT DLLs exist. Restore/start use the installed
`meshharbor_agent_exe` FileKey, preserving custom installation directories.

## Transaction

1. Immediate snapshot before InstallInitialize captures both current and legacy
   named tasks, full task XML, principal, enabled/running states, and actual
   task-file owner/group/DACL. Only ERROR_FILE_NOT_FOUND means absence.
2. Rollback is scheduled after InstallInitialize. MajorUpgrade runs
   **afterInstallExecute**, so the rollback script exists before the old product
   runs its task-deletion custom action. Component identities remain unchanged.
   The former afterInstallInitialize schedule cannot host script-generating
   rollback actions before RemoveExistingProducts (MSI ICE63).
3. After old-product removal, restore existing definitions through Task Scheduler
   COM, or call normal `service install` only if no task existed. Read back XML,
   enabled state and the real task-file ACL before reporting success.
4. Commit starts enabled tasks only. Disabled tasks remain disabled. Rollback
   restores original definitions, or removes the fresh task when originally
   absent; it restarts only originally running, enabled tasks.

State is under the installing user's LocalAppData MeshHarbor/InstallerTransactions:
SID-bound JSON in a random private directory; an MSI ProductCode pointer contains
its nonce and hash. No public MSI property supplies a recovery path. An unfinished
transaction is not overwritten. Start/restore failure retains recovery material.
Existing path components are checked root-to-leaf for reparse points before
creation or ACL changes; pointer/journal links are rejected before reading or
cleanup. Recovery reads do not rewrite the base directory ACL. These are
fail-closed checks for existing links, not a new same-user privilege boundary.
After confirming no MSI operation is active, an operator can use the **new**
helper's `msi-task-transaction rollback {ProductCode}` for a retained transaction.
Never delete the only recovery material merely to retry an installation.

Task Scheduler's scripting security descriptor omits DACL protection and may
synthesize a principal read ACE. Consequently the helper also reads the documented
backing task-file ACL; it never edits that file directly. Only Scheduler COM
registers/restores the task. Unreadable ACLs, password-backed logon, and noncanonical
mixed-deny ACLs fail closed before removal. XML comparison excludes only the
SecurityDescriptor registration metadata inserted by Scheduler, while the actual
ACL is independently compared. All-Allow ACEs may reorder; mixed deny/allow order,
ACE flags, owner/group and DACL protection remain checked. SACL/auditing is not
claimed by these DACL checks.

## Evidence and limits

`test-task-transaction.ps1` creates a random **disabled** task: custom WScript
command, PT1M repetition, nondefault settings and protected mixed-deny ACL. It
checks restoration, rollback, absent-task cleanup, password rejection and access
failure rejection; no GUI or task action is launched.

A task-runtime MSI fixture additionally executes old-product removal, success,
and injected failure/rollback using independent Product/Upgrade/Component GUIDs.
This demonstrates MSI sequencing and task restoration, not a production-package
0.4.154/157 upgrade. Actual old production MSI canary, daemon-online verification,
and any enabled-task running-state test remain separate rollout acceptance gates.
