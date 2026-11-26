# FR-141 — A session outlives its transport: SSH survives network drops and daemon updates; remote desktop reconnects through a restart

## Status

In progress — claimed 2026-11-26.

## Context

An interactive SSH session or remote desktop session should survive transient network drops, DERP failover, and target `meshharbord` restarts/self-updates without killing what is running remotely, and automatically reattach once the target returns — ending only when the user explicitly terminates it (`~.`), the shell exits, its lifetime expires, or access is revoked.

### Why it fails prior to FR-141

1. The SSH server runs in-process over the daemon's overlay netstack (`agents/meshharbord/src/ssh.rs`), so TCP and SSH state exist only in daemon memory.
2. Interactive PTYs are owned directly by `meshharbord` (`pty/unix.rs` kills the process group on drop; `pty/windows.rs` owns the `KILL_ON_JOB_CLOSE` job handle).
3. Linux systemd units (`meshharbord.service`, `meshharbor.service`) use the default `KillMode=control-group`, reaping even `setsid` descendants when the daemon exits for an update or restart.
4. Windows MSI `/qn` runs Restart Manager and shuts down any process holding the install-directory executable.
5. `mh ssh` execs system OpenSSH with a single-use grant key (`-F none`), with no keepalive and no resume path.
6. Remote desktop sends no restart-specific end notice before exit; viewers treat the disconnect as a generic drop and prompt consent / 2FA again when reconnecting.

## Architecture & Invariants

1. **Out-of-process PTY host (`meshharbord ssh-pty-host`)**: Only state outside the daemon survives a daemon restart. Each persistent SSH session runs in a detached host process owning the PTY/ConPTY, a 4 MiB byte-offset output ring buffer, a `vt100` screen tracker, timers (deadline, detach TTL, 10 min orphan TTL), and a sealed session descriptor.
   - **Linux systemd**: spawned into a dedicated scope via `systemd-run --scope` (`--user` for per-user units) and verified by reading `/proc/self/cgroup`.
   - **Linux non-systemd / macOS**: detached via `setsid` (and verified via `pgid != daemon_pgid`; containers where daemon is PID 1 report `persist.survives_restart = false`).
   - **Windows**: staged binary copy outside the MSI install directory, spawned with `spawn_detached_no_inherit` and a named Job Object (`Global\MeshHarbor.ssh.<sid>` / `Local\MeshHarbor.ssh.<sid>`).
2. **Zero secrets in host; stateless HKDF/HMAC resume auth**: A device-local 32-byte master key (`ssh-resume.key`, `0600` / protected ACL, never on the wire or in `DesiredConfig`) seals descriptors (`HKDF(master, "", "fr141/seal/v1")`) and derives `resume_secret = HKDF(master, salt=sid, info="fr141/resume/v1" || SHA256(D))`. Resume attaches over a fresh SSH connection (`ConnClass::ResumeOnly { sid }`, strict default-deny for all other SSH verbs) using mutual nonce HMAC proofs verified in constant time.
3. **Complete explicit revocation**: Because hosts survive netstack teardown, every implicit kill path (`close_all_and_wait`, `rc:goodbye`, `drop_runtime_slot`, secondary-org leave, `rc:ssh.revoke`, exit 7, uninstall) explicitly terminates matching hosts via frozen IPC frame `0x00 Terminate` plus OS scope/pgid/job kill. Hosts independently enforce deadline, detach TTL, and 10 min orphan TTL (fail-closed if daemon is lost or downgraded).
4. **Eternal Terminal + Mosh hybrid (`meshharbor-pty@v1`)**: Byte-exact lossless replay within the 4 MiB ring buffer, automatic `vt100` screen snapshot fallback (with dim gap marker, scrollback tail, ANSI/UTF-8 ground-state suffix, and alt-screen SIGWINCH redraw) when offline output exceeds 4 MiB, and cumulative ACK + exactly-once client-to-server input deduplication.
5. **Human-friendly built-in `mh ssh`**: Uses `russh` + `crossterm` + a client-side shadow `vt100` for interactive shells (`mh ssh <dev>`, `mh ssh -t <dev> <cmd>`), with fast dead-link detection (2 s ping, 6 s make-before-break suspect redial), a non-corrupting top-row recovery banner (`SSH 会话恢复中...` / `reconnecting...`) cleanly repainted from shadow state on reattach, `~d` detach / `~.` terminate / double `Ctrl-C` local detach when disconnected, local `0600` session store (`--sessions`, `--resume`, `--kill`, `--ephemeral`), classic `pty-req + shell` fallback on the same connection for older daemons, and unchanged OpenSSH exec for forwarding/file-transfer flags (`-L/-R/-D/-W/-J/-N/-A/-X/-o`, `scp`, `sftp`, `--no-resume`).
6. **Remote Desktop restart continuity**: Before exiting for restart/update, the agent sends `rc:ended { reason: "agent_disconnect", limit: "restart", eta_ms, to_version }` and writes a 120 s single-use sealed `rc-continuity.json`. The server validates `continues_from` and tags `rc:request.continues` for `RcContinue`-capable agents; the device auto-grants without consent/2FA re-prompt while keeping viewer indicator and notification; the Web viewer keeps the last frame, shows a soft updating/reconnecting banner, and reconnects immediately on `device:presence` online.

## P0 Spike Measurements

- **2026-11-26 (Linux root systemd & per-user systemd)**: Verified `systemd-run --scope` works without D-Bus issues on root systemd (`0::/system.slice/mh-p0-probe-*.scope`) and per-user systemd (`0::/user.slice/user-<uid>.slice/user@<uid>.service/app.slice/mh-p0-probe.scope`), isolating child scopes outside the daemon service cgroup.

## Acceptance Criteria

- [ ] AC1: Interactive `mh ssh <dev>` session survives target `meshharbord` restart/self-update and network interruptions with lossless byte-exact replay (<= 4 MiB) and snapshot recovery (> 4 MiB), without duplicating queued keystrokes.
- [ ] AC2: Disconnected `mh ssh` displays a non-corrupting top-row recovery status bar and OSC 2 title, repaints the original top row cleanly on reattach, and supports `~d`, `~.`, and double-`Ctrl-C` local detach.
- [ ] AC3: Explicit revocation (`CloseAccess`, `rc:ssh.revoke`, org removal, agent deletion, deadline, orphan TTL) terminates surviving PTY hosts cleanly with zero leaked daemon fds.
- [ ] AC4: Older daemons (< 0.4.219) fall back to classic `pty-req + shell` on the same authenticated connection without triggering a second grant/consent/2FA prompt; OpenSSH forwarding/scp/sftp paths remain unchanged.
- [ ] AC5: Remote desktop sessions survive target restarts via `limit: "restart"` + 120 s single-use sealed `rc-continuity.json` without re-prompting consent/2FA or kicking the viewer off the RC page.
- [ ] AC6: All unit, integration (`ssh_persist`), server composition, UI, and clippy checks pass with zero warnings.
