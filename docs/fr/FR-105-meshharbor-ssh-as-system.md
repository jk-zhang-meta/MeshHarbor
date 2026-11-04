# FR-105: MeshHarbor SSH runs as SYSTEM through the device's service — the SSH transport terminates in session 0

**Issue:** [#2148](https://github.com/jk-zhang-meta/MeshHarbor/issues/2148) · **Status:** **closed 2026-10-14**: all six criteria field-verified, on the 0.4.136 candidate and again on the released 0.4.136 (§8 rows 1–16) · **Owner:**
network (grants, the routing, the audit), fleet (the anchor credential), the Windows agent (the service's
SSH endpoint, the worker's splice) · **Anchors:** master `94a2032c6` · **Builds on:** FR-94 (decision 5:
"route SSH sessions through the service as a follow-up FR"), meshharbor SSH (`docs/meshharbor-ssh.md`), FR-83
(grant acks)

## 1. Goal

On an anchored Windows device, `meshharbor ssh <device>` runs as **SYSTEM** in session 0, or as **the signed-in
user** when the policy says `console_user`. That makes it the same identity as Fleet RPC after FR-94, on
every install type. `console_user` works on attended installs for the first time.

FR-94's invariant holds for SSH: **nothing the signed-in user can write may decide what SYSTEM runs, or read
what a SYSTEM session shows.**

## 2. Evidence (master `94a2032c6`)

**MeshHarbor SSH runs entirely in the console-session worker.** The path is:
- `agents/meshharbord/src/ssh.rs` `maybe_intercept` L188;
- `SplitTun::wrap` (`crates/tunnel-core/src/overlay/split_tun.rs` L120: **one** port; `is_intercepted` L224; `listen` L189), on `DEFAULT_SSH_PORT = 2222` (`crates/modules/network/src/routes/agent_ssh.rs` L531–535);
- `accept_loop` L260;
- `serve_conn` L2232 → `russh::server::run_stream`.

**On an attended install the worker is the signed-in user.**
- `daemon` runs as that user (`pty/windows.rs` `spawn_attached` L638).
- `console_user` is refused, because only SYSTEM may call `WTSQueryUserToken` (`pty/windows.rs` L692–721).
- `docs/meshharbor-ssh.md`'s table (L321–325) still says `daemon` = SYSTEM on Windows, and the ConPTY paragraph (L307–314) blames "not a perMachine service install". Both are wrong on a perMachine attended install.

**Every input the SSH path reads is user-writable there:**
- the grant table: pushed over the worker's control socket as `ServerMsg::SshGrant` (`crates/remote_control/src/signaling.rs` L2582), and recorded in the worker's memory (`ssh.rs` `record_grant` L2365);
- the host key (`AgentConfig::ssh_host_key` in `%APPDATA%`, published by the worker's hello: `agents/meshharbord/src/signaling.rs` L1285, L5469), which the caller pins (`agents/meshharbor-cli/src/sshcmd.rs`);
- `ssh_authorized_keys`, `ssh_account_mode`, `ssh_max_privilege`, `forward_acl`, the consent sentinels, and the WireGuard key that gate 0 ("carrier identity") rests on.

**Why that matters.** Today each of these yields only the user's own identity. Once SSH runs as SYSTEM, each becomes an escalation.

## 3. Design (FR-94's D1' applied to SSH)

### 3a. The transport terminates in the service; the worker forwards ciphertext

- `SplitTun` intercepts a small fixed set of ports, `{2222, 2223}`. `Netstack::listen(port)` already takes any port.
- Port **2223** is spliced, byte for byte, into a new owner-checked pipe, `\\.\pipe\meshharbor-ssh-service`.
  - It uses the doorbell's SDDL (`agents/meshharbord/src/exec_service.rs` L1032, `first_pipe_instance`, `reject_remote_clients`).
  - The worker refuses a pipe SYSTEM does not own (`pipe_owned_by_system` L1388). Squatting costs only availability.
- The service runs `russh::server::run_stream` over the pipe stream with **its own** host key.
  - The worker sees only ciphertext: it can drop or delay bytes, but not read or inject (SSH's MACs).
- The pipe carries frames — `DATA`, `CONSENT_REQ`, `CONSENT_ANSWER`, `CLOSE` — so the service can ask the worker for consent (§3d).
- **The server chooses the port and the key per grant**, because the worker cannot route by inspection: the SSH user name is encrypted. The grant response already says where to dial and what key will answer. **`meshharbor ssh` needs no change.** `meshharbor proxy` (`sshcmd.rs` L164) is checked to take the grant's port.

### 3b. The grant is pulled, never relayed

- For a via-service grant, `decide` (`agent_ssh.rs` L344) persists the grant in a TTL'd `ssh_pending` store. It pushes the worker only `rc:ssh.grant { grant_id, via_service: true }`.
- The worker rings the service with the id. The service claims the grant with `POST /api/agent/service/ssh/{grant_id}/claim` (`AuthAgentService`: single use, this device only, within the grant's 60 s) and records it in its own table.
- **The claim is the ack.** It resolves `ssh_grant_acks` (`crates/modules/network/src/ssh_grant_acks.rs` `deliver`) on this pod, or through the row from another pod.
  - A worker's own `rc:ssh.grant_ack` for a via-service grant counts only as a **refusal**. The person's `ssh_enabled` off is still theirs to say.
- The service port is a shared constant in `remote_control::models::ssh_limits` (L1701).

### 3c. The host key is the service's

- The service generates its host key into the anchor directory, under the same owner and DACL checks (`check_private`).
- It publishes the public half with `PUT /api/agent/service/ssh-host-key` → `Agent.ssh_service_host_pubkey`.
- A via-service grant returns that key with port 2223. A worker-published key can never stand in for it.

### 3d. Routing, gates and accounts

- **`routes_ssh_via_service`**, all required:
  - a Windows device;
  - `exec_anchor` set;
  - a published `ssh_service_host_pubkey`;
  - the device advertising **`ssh-system`**, equality-matched (`ssh` is its prefix, as it is of `ssh-consent`);
  - `rc.ssh_via_service`.

  A worker lying about the word gains nothing: the client pins a key only the real service holds.
- **The anchor gains an SSH ceiling**, `ssh: off | console_user | system`, set by `meshharbord anchor ssh <…>` (elevated) and **default `off`**. An existing exec anchor never silently gains SYSTEM SSH.
  - The person's `ssh_enabled` is still checked by the worker before it rings, so either half can refuse.
  - `console_user_unsupported` (`agent_ssh.rs` L875) refuses `console_user` up front on a Windows device with no service path.
- **Accounts in the service:**
  - `daemon` → SYSTEM in session 0;
  - `console_user` → the signed-in user (`spawn_attached_as_console_user`, already SYSTEM-callable);
  - nobody signed in → refused, naming why.
- **Consent stays the person's.** The service sends `CONSENT_REQ`, and the worker answers through its existing `await_consent` (`ssh.rs` L1813). A faked approval only lets a server-authorized grant proceed: the FR-94 position.
- **Refused on the SYSTEM port in v1**, because their inputs are user-writable:
  - key-list sessions (`ssh_authorized_keys`);
  - `direct-tcpip` (`forward_acl`).
  - `sftp` runs as the session's identity.
- **Audit.** `ssh_audit` gains `ran_as` (`system` / `console_user` / `worker`), the server's decision.

```mermaid
flowchart LR
  C["meshharbor ssh (caller)"] -- "grant request" --> S[server]
  S -- "rc:ssh.grant {grant_id, via_service}" --> W["worker (session 1, the user)"]
  W -- "ring: grant_id" --> V["service (session 0, SYSTEM)"]
  V -- "claim (anchor credential)" --> S
  S -- "port 2223 + the service's host key" --> C
  C -- "SSH over the overlay, port 2223" --> W
  W -- "ciphertext, framed, over the SYSTEM-owned pipe" --> V
  V -- "shell as SYSTEM or the console user" --> P[(ConPTY)]
```

## 4. Phases

| P | Scope | Kill switch | Status |
|---|---|---|---|
| P0 | This spec, the issue and the registry row. Docs truth first: `meshharbor-ssh.md`'s identity table and the P4b ConPTY paragraph; the stale `pty/windows.rs` L846 test comment. vmtest RED: SSH identity on attended (the user), SystemContext (SYSTEM in session 1), `console_user` refused on attended | docs only | spec #2149; docs truth #2155; vmtest RED §8 rows 1–3 and 12 |
| P1 | Server: `ssh_pending`, the claim route, the claim-as-ack resolver; the host-key route; `routes_ssh_via_service`; port and key per grant; `ssh_audit.ran_as`; the composition baseline | `rc.ssh_via_service = false` | merged (#2166) |
| P2 | Service: the anchor's `ssh` ceiling and `meshharbord anchor ssh`; the service host key and its publication; the SSH pipe server; russh over the pipe with its own grant table; daemon → SYSTEM, console_user; key-list and `direct-tcpip` refused | the anchor's `ssh = off` (default) | #2179 (merged as `f7e7f8a12`), one PR with P3 (neither half can be field-tested without the other); field-verified on the 0.4.136 candidate (§8) |
| P3 | Worker: the `ssh-system` word (from the service's health reply); 2223 → the pipe; the via-service grant ring; the consent frames | `MESHHARBORD_SSH_VIA_SERVICE=0` | #2179, with P2 (merged) |
| P4 | UI (`ran_as` in the SSH audit, the device's SSH identity); docs; field | — | this PR: the audit's *As* chip and the policy dialog read `ran_as` and `ssh-system` (`ui/src/utils/sshIdentity.ts`); `meshharbor-ssh.md` § Through the device's SYSTEM service; field §8 |

P1 as built (`crates/modules/network/src/routes/agent_ssh.rs`):
- **The service publishes its ceiling with its key.** `PUT /api/agent/service/ssh-host-key {host_pubkey, ceiling}`, with the service credential, stores `Agent.ssh_service {host_pubkey, ceiling, anchor_id, published_at}`. The write is filtered on the row still carrying that anchor, so a publish racing a re-anchor writes nothing (401).
- **Routing needs the endpoint to name the CURRENT anchor.** A re-anchor, an un-anchor or a removal therefore retires it with no cleanup, and the grant goes back to the worker until the service publishes again.
- **The ceiling decides per grant.** `system` permits `daemon` and `console_user`; `console_user` permits only that. Outside the ceiling, the grant takes the worker path exactly as before, not a refusal.
- **The claim window is the caller's wait** (`GRANT_ACK_TIMEOUT_SECS`). After the bound, the row is withdrawn; if it cannot be withdrawn because the claim won the race, that counts as confirmed. A refusal from the worker, or a failed push, withdraws it too. A refused claim is a 404 and an `ssh_audit` row `claim_refused` with no user.
- **Deferred:** refusing `console_user` up front on Windows with no service path. A SystemContext worker runs as SYSTEM and *can* serve it, and the server cannot yet tell that worker from an attended one. An attended worker accepts the grant and refuses when the session starts, naming why (`WTSQueryUserToken … only a process running as SYSTEM may`, §8 row 2), not through the grant ack.
- A P1-era agent binds `via_service` and refuses such a grant (`Other`). It never advertises `ssh-system`, so no server sends it one.

P2 and P3 as built (`agents/meshharbord/src/ssh_service.rs`, `exec_service.rs`, `ssh.rs`):
- **The ceiling is the anchor's.** `Anchor.ssh` (serde default `off`, so every FR-94 anchor reads as off), set elevated with `meshharbord anchor ssh <off|console_user|system>` or `anchor create --ssh`. Re-anchoring the SAME device keeps it; any other device starts off. `Anchor.extra` keeps keys a newer build wrote, so this build's save (a renewal, `anchor exec`) never erases them.
- **The host key** is `ssh_host_ed25519_key` beside the anchor, written and read with the anchor's rules (private directory, file DACL set before the rename, owner and DACL checked on the handle read from). The service or `anchor ssh` makes it when missing.
- **The publisher** compares every 60 s and puts `{host_pubkey, ceiling}` when the anchor, the ceiling or the key changed, or after 6 h. A failure waits 5 min. Without an anchor it publishes nothing: the server's record names the anchor it came under.
- **The SSH pipe** `\\.\pipe\meshharbor-ssh-service` has the doorbell's DACL, is created first-instance-only, and serves at most 8 sessions. The worker opens it with the doorbell's SYSTEM-owner check.
- **Frames**: a kind byte, a big-endian `u32` length, the payload. `Hello{peer}` (the worker's claim, logged only), `Data` (≤ 64 KiB, ciphertext), `Eof`, `Ask{id, sentinel, caller, what, timeout_secs}`, `Answer{id, granted, reason}` (≤ 4 KiB, JSON). Oversized, unknown or malformed frames end the connection unread.
- **The service's server** (`sshd::Ctx::for_service`, built per connection from the anchor as it stands then): no key list, forwards refused (`forward_refusal`, and an allowlist that is off besides), and the ceiling applied after the grant resolves, refusing rather than downgrading (`within_service_ceiling`).
- **Consent**: `ssh::Asker` is `Here` (the broker and the panel) or `Worker(ConsentRelay)`. The service asks through the relay; the worker answers with the same `ask_here` its own sessions use, and validates the sentinel as a grant id first, since it becomes a file name. Reasons reach the caller's terminal stripped of control characters and capped.
- **The grant**: the worker refuses a via-service grant when `ssh_enabled` is off, the kill switch is set, or `ssh_max_privilege = console_user` meets a `daemon` grant. Otherwise it rings `DoorbellRequest::SshGrant` off the read loop; the service claims with its own credential (8 s, inside the server's 10 s window) and records the grant in its own table. A failed ring is answered to the server as a refusal.
- **The word**: the doorbell's health reply carries `ssh` (the ceiling while the SSH pipe is up). The worker advertises `ssh-system` when the service serves SSH for exactly this device, above off, `ssh_enabled` is on and the kill switch is unset, and re-announces on the heartbeat when that changes.
- **The port**: `SplitTun::wrap_ports` intercepts 2223 beside the node's own SSH port, unless the kill switch is set or `ssh_port` is 2223. Each connection is carried to the pipe and never served by the worker.

## 5. Acceptance criteria

- [x] **AC1:** on an anchored attended device with `ssh = system`, `meshharbor ssh <dev> -- whoami` prints `NT AUTHORITY\SYSTEM`, session 0. Red first: the same device unanchored prints the signed-in user. *(§8: red rows 1 and 3, the user in session 1 unanchored and anchored on 0.4.135; green row 5, SYSTEM in session 0, `ran_as = system`. SystemContext too: rows 12–13, session 1 → session 0.)*
- [x] **AC2:** `console_user` on an attended install runs as the signed-in user through the service (refused before this FR). With nobody signed in, it is refused, naming why. *(§8: red row 2, the worker's `err 1314`; green row 6, the user at Medium integrity, `ran_as = console_user`. Nobody signed in: row 14, on SystemContext, the only install whose worker, and so whose mesh, outlives the sign-out; an attended device is offline then, D3.)*
- [x] **AC3 (the invariant, on a standard-user device):** *(§8 rows 7–9. Every probe ran with the signed-in user's limited token, Medium integrity, and none used elevation. The account is a local administrator, so this is the standard user's power exactly: their own config, the doorbell's user access, their own host key.)*
  - (i) the user adding their own key to `ssh_authorized_keys` gets no session on 2223; *(row 7: the same key opens 2222 as the user and gets `Permission denied` on 2223)*
  - (ii) a forged grant-id ring is refused at the claim and audited; *(row 8: `claimed: false`, and an `ssh_audit` row `service-claim` / `claim_refused` with no user)*
  - (iii) the user republishing a worker host key changes nothing a client pins for 2223; *(row 9: 2222's key changed, 2223's did not, and grants to 2223 still pinned the service's key)*
  - (iv) no session plaintext reaches any user process. *(rows 7 and 9: port 2223 presents the service's host key, the one `anchor status` prints, whose private half is SYSTEM + Administrators only, so the SSH transport ends in the service; the worker's carry loop moves `Data` frames it cannot decrypt)*
- [x] **AC4:** revocation. Un-anchoring, or the anchor's `ssh = off`, sends grants back to the worker identity, and the audit says `worker`. *(§8 row 10: `ssh = off` → the word withdrawn in 22 s, `ran_as = worker`; a server-side un-anchor → the very next grant to the worker, while the device still advertised `ssh-system`)*
- [x] **AC5:** a claim landing on the other pod still confirms the grant (integration with two servers, then prod, staged). *(`ssh_service_tests::a_claim_on_the_other_pod_still_confirms_the_grant`, #2166; §8 row 11: prod, staged, 4 of 4 runs)*
- [x] **AC6:** docs: *(this PR)*
  - `docs/meshharbor-ssh.md` with the identity per install type and this FR's routing and pipe diagrams;
  - `docs/fleet-rpc.md`'s anchor section (the SSH ceiling);
  - linked from `docs/README.md`.

## 6. Open decisions

1. **The ceiling's default.** Recommended: `off`. FR-104's wizard checkbox, or `meshharbord anchor ssh system`, turns it on.
2. **The v1 refusals on the SYSTEM port.** Recommended: key lists and `direct-tcpip`. An anchor-owned key list and forward ACL can follow.
3. **`ssh_activity` from the service.** Recommended: a later phase, posted with the anchor credential.

## 7. Out of scope

- D3: the service owning the socket and the WireGuard key.
- Standard-user installs whose overlay is down (no Wintun without admin). They stay unreachable by SSH until D3 or a netstack fallback.
- macOS and Linux, whose daemons are already root.

## 8. Field-verification log

2026-10-14, prod. The released agent is 0.4.135; the candidate is 0.4.136 from rehearsal run 38557954696, which is #2179's head (`005b79905`) plus the version bump. The caller was a vmtest Ubuntu root daemon in the same org, running `meshharbor ssh <device> -- <a PowerShell who-am-I>`. Every row is from that caller, with the audit row the server wrote.

| # | Cell | Host | Result |
|---|---|---|---|
| 1 | RED: `daemon`, released, unanchored | vmtest Win11, attended (`daemon-machine`) | `VMTEST-WIN\vmtest`, session 1, High; `ran_as = worker` |
| 2 | RED: `console_user`, released | the same | the server grants; the worker refuses at session start: "cannot obtain the console user's token (`WTSQueryUserToken(1)` failed (err 1314)): only a process running as SYSTEM may …" |
| 3 | RED: `daemon`, released, **anchored** (`exec-system` advertised) | the same | still `VMTEST-WIN\vmtest`, session 1; `ran_as = worker`. The anchor alone changes nothing for SSH |
| 4 | Upgrade to the candidate; the FR-94 anchor as it was | the same | `anchor status`: `ssh: OFF`. The device advertises `exec-system` but not `ssh-system`, and `daemon` still runs as the user (`ran_as = worker`): no anchor gains SYSTEM SSH by updating |
| 5 | GREEN AC1: `meshharbord anchor ssh system` | the same | `ssh-system` advertised within 23 s; `daemon` → `NT AUTHORITY\SYSTEM`, session 0, System integrity; `ran_as = system` |
| 6 | GREEN AC2: `console_user` | the same | `VMTEST-WIN\vmtest`, session 1, Medium; `ran_as = console_user` |
| 7 | AC3(i): the user lists their own key (limited token) and restarts | the same | `ssh-keyscan`: 2222 presents the worker's key, 2223 the service's (`SHA256:kYeI…Vyas`, as `anchor status` prints). With the user's key, stock `ssh` on 2222 runs `whoami` as `vmtest-win\vmtest`; on 2223: `Permission denied`. (The first 2222 attempt timed out while the overlay re-handshook after the restart; the retry is the row.) |
| 8 | AC3(ii): a forged `SshGrant` ring from the user's limited token | the same | `{"t":"rang","claimed":false,"error":"the server has no such SSH grant pending for this device"}`; `ssh_audit`: `src = service-claim`, `denied = claim_refused`, the forged id, no user |
| 9 | AC3(iii): the user deletes the worker's host key from their config (service stopped, so the clean-shutdown save cannot restore it) | the same | 2222 now presents a new key (`SHA256:NR/8…` → `SHA256:xlU0…`); 2223 still `SHA256:kYeI…`; `daemon` → SYSTEM, session 0 |
| 10 | AC4: `anchor ssh off`; then a server-side un-anchor (`DELETE …/exec-anchor`) | the same | `ssh-system` withdrawn in 22 s → `daemon` runs as the user, `ran_as = worker`, pinning the worker's NEW key (row 9). Re-raised to `system`, then un-anchored from the server: the very next grant went to the worker while the device still advertised `ssh-system` |
| 11 | AC5: the service's origin re-anchored to a loopback port tunnelled to the OTHER pod | prod, both pods | the grant was issued on the org's pod; the claim `POST …/claim` returned 200 on the other one; the caller's pod confirmed about 390 ms later (its 400 ms row poll); SYSTEM, session 0. **4 of 4** runs: 1 on the attended guest, 3 on the SystemContext guest |
| 12 | RED: released, SystemContext | vmtest Win11, SystemContext (`daemon-system`), renamed `FR105SYS` | `daemon` → `NT AUTHORITY\SYSTEM`, **session 1** (the worker); `console_user` → `FR105SYS\vmtest` through the worker; both `ran_as = worker` |
| 13 | GREEN: the candidate, `anchor create --ssh system` in one step | the same | `daemon` → SYSTEM, **session 0**, `ran_as = system`; `console_user` → `FR105SYS\vmtest`, session 1, Medium, `ran_as = console_user` |
| 14 | AC2: nobody signed in (`logoff`; the console is session 2, no user) | the same | `console_user` → refused, naming why: "console session 2 has no user token (nobody is signed in at the console); nothing to run as"; `daemon` → SYSTEM, session 0 |
| 15 | Consent through the relay: policy `prompt`, nobody signed in | the same | "waiting up to 30s for approval at the device…", then "nobody approved this session at the device within 30s", and the same words on the worker path (`ssh = off`, `ran_as = worker`) |
| 16 | **The released 0.4.136**, 22:08Z, after publication. The target is a fresh guest, attended, installed from the served script, `anchor create --ssh system`; the caller is the vmtest Ubuntu lane cell on 0.4.136 | vmtest Win11, attended, and prod `hosted-20261014-b4e2263` | `ssh-system` advertised. `daemon` → `NT AUTHORITY\SYSTEM`, session 0, System, `ran_as = system`; `console_user` → the signed-in user, session 1, Medium, `ran_as = console_user` |

**Wrong turn, recorded.** At 12:12:17Z another session's vmtest Win11 clone revived the attended guest's device row and replaced its connection. Every clone is `VMTEST-WIN`, and `machine_id` hashes the host name with the config path. That cell's cleanup then deleted the row. Row 11's first run had finished; its next two failed ("no device named …"). The SystemContext guest was renamed before it enrolled, and the vmtest lane is gaining a unique name per clone.

## 9. Related

- FR-94 (§5a, decision 5).
- `docs/meshharbor-ssh.md` (P3a grants, P6a host keys, FR-83 acks).
- FR-104 (the wizard can set the ceiling at install).
- #2133.
