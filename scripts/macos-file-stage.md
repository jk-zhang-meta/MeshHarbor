# Mac four-object file phase (not an installer)

This helper owns only these already installed objects:

| Role | Kind | Target |
|---|---|---|
| daemon | signed bundle | `/Library/MeshHarbor/meshharbord.app` |
| desktop | signed bundle | `/Applications/MeshHarbor.app` |
| cli | regular executable | `/usr/local/bin/mh` |
| daemon_link | symlink | `/usr/local/bin/meshharbord` |

It never invokes `installer`, `launchctl`, `open`, TCC APIs/databases, package
receipts, account enrollment, an update feed, or a GUI. It does not copy configs,
plists or registration state. Root orchestration must first preserve and quiesce
the exact existing LaunchAgents/updater, prevent other writers, and later restore
the same running/disabled scope. `--jobs-quiesced` is an explicit caller assertion,
**not** a claim that the helper proved jobs stopped. Do not run this over a managed
session whose process will be stopped. The same requirement applies to rollback.

## Prepare an approved local plan

Obtain candidate files from the separately verified package/build. File copying
is not package installation; package receipt reconciliation and runtime acceptance
remain outside this helper. Candidate ownership/permissions must already be correct
for installation: they are preserved, never silently rewritten by the helper.

Use `python3 scripts/macos-file-stage.py hash /absolute/object` for each original
and candidate. Review and freeze the resulting plan; a helper-computed hash is an
exact-byte/metadata gate, not an independent signature trust decision. Plan schema:

```json
{
  "objects": {
    "daemon": {"kind":"bundle","target":"/Library/MeshHarbor/meshharbord.app","candidate":"/private/approved/meshharbord.app","old_sha":"...","new_sha":"..."},
    "desktop": {"kind":"bundle","target":"/Applications/MeshHarbor.app","candidate":"/private/approved/MeshHarbor.app","old_sha":"...","new_sha":"..."},
    "cli": {"kind":"file","target":"/usr/local/bin/mh","candidate":"/private/approved/mh","old_sha":"...","new_sha":"..."},
    "daemon_link": {"kind":"symlink","target":"/usr/local/bin/meshharbord","candidate":"/private/approved/meshharbord","old_sha":"...","new_sha":"..."}
  }
}
```

The signed bundles must pass native `codesign --verify --deep --strict` before
backup, after native `ditto --rsrc --extattr --acl` copying, and after replacement
or rollback. This verifies integrity, **not** notarization, distribution identity,
Gatekeeper acceptance or TCC continuity. Top-level symlinks use native `cp -pP`
because `ditto` follows a top-level link. Symlinks inside bundles are preserved.

Tree hashes cover every relative filename, file bytes, link text, mode, UID/GID,
mtime, flags, native ACL entries and all xattr bytes (including resource forks).
Atime, ctime, inode and birthtime are deliberately excluded because reading or
copying creates/changes them. No promise is made to preserve inode identity.
Any unsupported file kind, ancestor symlink, unexpected target kind or tree drift
fails closed. Original/candidate/transaction trees may not overlap live targets.

## File transaction

```sh
python3 scripts/macos-file-stage.py apply \
  --plan /absolute/private/reviewed-plan.json \
  --transaction /absolute/private/new-transaction \
  --jobs-quiesced
```

The transaction is new and private (0700). Exact original and candidate trees,
frozen helper, plan and independent `ROLLBACK.sh` are persisted before first
replacement. Native macOS `renamex_np(RENAME_SWAP)` exchanges a same-filesystem
staged object and its destination atomically; there is no missing `.app` window.
The target CAS is repeated after staging/signature verification and immediately
before exchange. A per-operator persistent lock serializes **this helper only**;
quiescence must also cover other updaters/operators. This is not an OS transaction
against a hostile concurrent writer.

On partial failure, all remaining targets and baseline backups must match known
old/new hashes before rollback starts. Every individual restore repeats CAS after
copying. Third-state objects are preserved and produce `manual_recovery_required`,
not blind overwrite. Failed exchanges retain a private sibling stage path for
explicit inspection; it can hold a retired original and must not be swept blindly.
Successful phases remove only their checked retired object.

```sh
/absolute/private/new-transaction/ROLLBACK.sh --jobs-quiesced
```

Rollback uses the frozen transaction helper and recorded Python interpreter, not
the source checkout. It restores all four original object hashes and signed bundle
verification. It does not stop/start jobs, restore receipt databases, reset TCC,
or undo unrelated writes. Result JSON explicitly says `runtime_verified:false`.
Real same-agent/config identity and user-facing feature checks belong to the root
rollout after restoring the intended launch state.

## Isolated native validation

```sh
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-macos-file-stage.py
```

Mac-only tests create **user-owned synthetic** bundles below
`~/.agent-work/runtime/meshharbor-personal-device-20261114/mac-file-fixtures/`.
They compile a tiny console-only `puts` program, ad-hoc sign it, attach a fixture
ACL/custom xattr and CLI resource fork, and test all four replacements plus the
actual generated rollback. No application is opened, registered or run as a GUI.
No installed MeshHarbor object, launch job, config, TCC entry or password is touched.
Fixtures include second-exchange failure recovery, signature tampering, hash drift,
transaction overlap rejection and third-writer preservation after staging.
