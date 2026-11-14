# Reviewed local Linux binary replacement

`linux-inplace-upgrade.py` is an explicit local-artifact transaction, **not an
installer or the signed automatic updater**. It never downloads, publishes,
enrolls, installs/enables a unit, invokes self-update, or changes install scope.
A supplied SHA is an exact-byte gate, not an artifact trust/signature source.
The operator must obtain both hashes from the approved build/audit separately.

## Preconditions

- Run from independent OS SSH or a console, not a command in the daemon's
  systemd cgroup: stopping that service would kill the upgrade controller.
- Python 3.11+ (`tomllib`), or Python 3.8+ with the reviewed pure wheel
  `tomli-2.2.1-py3-none-any.whl` on `PYTHONPATH`. Its official PyPI SHA256 is
  `cb55c73c5f4408779d0cf3eef9f762b9c9f147a77de7b258bef0a5628adc85cc` (MIT).
  No dependency is installed/downloaded automatically. An actual `tomli` import
  from any other source fails closed. Apply copies the verified wheel into the
  private transaction; generated rollback validates its SHA before import and
  sets its own `PYTHONPATH`, so the original staging path is no longer needed.
  Do not install packages globally for this script.
- Existing running service and LocalAPI must answer. The script binds MainPID,
  `/proc/PID/exe` hash, process UID, actual `--config`, and LocalAPI PID, active
  config, agent/tenant identity and privilege scope. A supervisor/old version
  that does not expose that exact contract is refused, not guessed.
- Exact supported scopes:
  - User: run **as the current non-root owner**, binary
    `$HOME/.local/bin/meshharbord`, `systemctl --user` unit `meshharbor.service`,
    config `$HOME/.config/meshharbor/siat-{63,228,45}/config.toml`.
  - System: root, `/usr/bin/meshharbord`, `/etc/meshharbor/config.toml`, existing
    system unit `meshharbord.service`.
- No symlink aliases, ephemeral enrollments, or overlapping per-target
  transactions. A persistent private `.meshharbord-upgrade.lock` inode beside
  the binary serializes this script only; it does not isolate automatic updaters
  or other writers and is never a new service. Hashes are checked again after
  stop immediately before replacement, including during rollback. This is a
  fail-closed check, not an OS transaction against a hostile concurrent writer.

## Apply (substitute audited paths and hashes)

```sh
python3 scripts/linux-inplace-upgrade.py apply \
  --scope user \
  --binary "$HOME/.local/bin/meshharbord" \
  --config "$HOME/.config/meshharbor/siat-63/config.toml" \
  --candidate /absolute/private/stage/meshharbord \
  --old-sha OLD_SHA256 --new-sha APPROVED_NEW_SHA256 \
  --config-sha AUDITED_CONFIG_SHA256 \
  --transaction /absolute/private/runtime/unique-upgrade-transaction
```

Use the exact system paths and `--scope system` for root installations. Never
run the user command under sudo, never switch it to `--system` to work around
an error. The transaction directory must not already exist; it is created 0700
and contains credential-bearing config backups. Keep it private and on durable
local storage. No config content or token is printed.

Before stop, exact old/new/config SHA gates and a unit-definition fingerprint
must pass. Full binary/config and existing `temporary.json`/`invites.json`
backups, the manifest, frozen script and standalone `ROLLBACK.sh` are persisted.
Binary replacement is atomic and preserves UID/GID/mode/xattrs. Only stop/start
of the same existing unit is used.

The daemon legally rewrites config on shutdown/startup. TOML formatting is
ignored, and **only** these audited top-level bookkeeping fields may change:
`last_run_unhealthy`, `crash_count`, `last_crash_unix`, `rollback_attempted`,
`last_known_good_version`, `config_schema_version`. Every other field, including
all nested organizations, keys, identity, tokens and permission settings, must
remain semantically identical; invitation sidecars must remain byte-identical.
New schema-default fields are not silently exempted: review the actual semantic
difference before retrying. Existing `auto_update` settings remain unchanged;
normal automatic checks on service startup are existing behavior, not a claim
that this procedure disables networking or publishes a candidate feed.

## Failure and independent rollback

```sh
/absolute/private/runtime/unique-upgrade-transaction/ROLLBACK.sh
```

Rollback uses the frozen sibling script, recorded interpreter and (when needed)
verified bundled TOML wheel, not the repository checkout, candidate download or
original `PYTHONPATH`. Only the recorded old/new installed
hashes are accepted. It restores pristine binary bytes and original binary
ownership/permissions/xattrs, then verifies the same service/LocalAPI identity.
It does **not** overwrite config or invitation records. Legitimate runtime
bookkeeping remains. Unknown binary bytes, changed protected config, changed
service definition or changed metadata require explicit operator recovery;
backups are retained rather than clobbering another writer's changes.

A failed activation attempts the same guarded recovery automatically, exits
nonzero even if recovery succeeds, and records `rolled_back` or
`recovery_required` in private `result.json`. Successful apply means only
`activated`, not fleet acceptance: inspect the actual device from the intended
remote client and test its requested features before marking deployment complete.

## Isolated validation

```sh
TOMLI_TEST_WHEEL=/absolute/private/tomli-2.2.1-py3-none-any.whl \
  PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-linux-inplace-upgrade.py
```

Tests use disposable files and an injected in-process service fixture; they
never call host systemd or a network. They execute a real shell artifact with
the same input before/after/rollback, test failure recovery, hash/CAS gates,
protected versus runtime config changes, invitation sidecars, xattrs/modes,
per-target locks, and LocalAPI identity predicates. Real systemd restart and
remote functional acceptance remain deployment-time checks.

For a prepared Python 3.10 host, prepend only the local verified wheel for apply:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/absolute/private/tomli-2.2.1-py3-none-any.whl \
  /usr/bin/python3 scripts/linux-inplace-upgrade.py apply ...
```

The generated `ROLLBACK.sh` needs no inherited `PYTHONPATH`. The dependency
fixture removes its original wheel copy and clears that environment before
executing the generated shell verbatim with an isolated service adapter; it
also verifies that a tampered transaction wheel is refused before import.
