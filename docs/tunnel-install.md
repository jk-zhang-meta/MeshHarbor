# MeshHarbor tunnels — install, setup, and test (corporate environment)

A MeshHarbor tunnel connection has three sides:

| Side | What it does | Where it runs |
|---|---|---|
| **Tunnel-client** (`mh`) | Listens on a local TCP port on the operator's machine. Each incoming connection rides a **QUIC** stream to the agent by default (transparently falling back to a WebRTC data channel if QUIC setup fails). | Operator's laptop (Win11 / Linux / macOS) |
| **Agent** (`meshharbord`) | Receives the forward request, dials the destination from inside the corp network, and pumps bytes back. | A host inside the corp network with route to the destination |
| **Server** (`meshharbor.itachi.fans`) | Issues JWTs, enforces the tenant ACL policy, relays SDP / ICE between the two peers (it never sees the payload). | MeshHarbor-managed |

This guide walks through the Win11-on-both-sides flavour. Linux and macOS commands are inline where they diverge.

> **Enrolling one machine into several organisations** (a contractor's laptop, a
> shared jump host): a second `enroll` against a different tenant now APPENDS an
> org instead of rebinding the daemon. See [`multi-org.md`](./multi-org.md) §3
> for the `[[orgs]]` config and the `mh org ls|rm|enable|disable|set-primary`
> verbs — and §4.4 for the one thing that is still primary-only: the overlay
> mesh.

---

## Transport: QUIC by default, WebRTC fallback

Since `mh` / `meshharbord` **0.3.0-rc.118**, the data plane defaults to **QUIC** (`quic-v1`, via [quinn](https://github.com/quinn-rs/quinn)) and falls back to the original **WebRTC data channel** (`webrtc-dc-v1`) only if QUIC can't be set up. Tuned QUIC is faster than WebRTC on a relayed path and reaches the same hard networks. Choose explicitly with `--transport`:

| `--transport` | Behaviour |
|---|---|
| `auto` *(default)* | Try QUIC; transparently re-open over WebRTC if QUIC setup fails. |
| `quic` | Force QUIC; error out if it can't be established (no fallback). |
| `webrtc` | Force the proven WebRTC data-channel path. |

**Reaching hard networks** — QUIC has no ICE, so it walks its own connectivity tiers in priority order, reusing the same coturn cluster as WebRTC:

1. **Direct** — dial the agent's host / server-reflexive candidates (best latency, no relay).
2. **QUIC-over-TURN (UDP relay, "Tier 2")** — when direct fails but UDP egress to coturn works.
3. **QUIC-over-TURNS/TCP (TLS relay, "Tier 3")** — when UDP is fully blocked (corporate firewall). Same reach as WebRTC.

The forward logs which path it took (`tunnel established transport=quic-v1 path=relay|direct …`); the relay allocation logs the UDP-vs-TLS sub-tier.

**Mixed fleets** — the server negotiates `quic-v1` only when the target **agent's version supports it** (≥ rc.104); against an older agent it transparently uses `webrtc-dc-v1`, so `--transport auto` is always safe.

---

## 0. Prerequisites

- A MeshHarbor tenant with an admin account
- Two Win11 machines:
  - **`AGENT-CORP`** — joined to the corp network, with TCP reachability to your DB / service
  - **`OPERATOR-LAPTOP`** — the operator's machine, where local clients (psql, ssh, RDP, …) will connect to `127.0.0.1`
- Outbound HTTPS to `meshharbor.itachi.fans` from both machines (port 443)
- Outbound UDP/3478, UDP/443 (or TCP/443 TURNS fallback) to the MeshHarbor coturn cluster from both machines

The same machine can play both roles for smoke-testing — see §8.

---

## 1. Install the agent on `AGENT-CORP`

The agent is the existing `meshharbord` MSI. Download from your MeshHarbor server (proxied through `meshharbor.itachi.fans` so corp AV trusts it — no `github.com` fetch in the user's network path):

**Win11 (PowerShell as Administrator only if you choose perMachine):**

```powershell
# perUser flavour — installs to %LOCALAPPDATA%, no UAC prompt
Invoke-WebRequest `
  "https://meshharbor.itachi.fans/api/agent/installer/peruser?version=latest" `
  -OutFile "$env:USERPROFILE\Downloads\meshharbord.msi"
msiexec /i "$env:USERPROFILE\Downloads\meshharbord.msi"
```

For unattended / fleet installs (boot-time, runs as `LocalSystem`):

```powershell
Invoke-WebRequest `
  "https://meshharbor.itachi.fans/api/agent/installer/permachine?version=latest" `
  -OutFile "$env:USERPROFILE\Downloads\meshharbord-permachine.msi"
# Run elevated:
msiexec /i "$env:USERPROFILE\Downloads\meshharbord-permachine.msi"
```

**Linux (.deb):**

```bash
curl -fsSL -o /tmp/meshharbord.deb \
  "https://meshharbor.itachi.fans/api/agent/installer/peruser?version=latest&os=linux"
sudo dpkg -i /tmp/meshharbord.deb
```

**macOS (.pkg):**

```bash
curl -fsSL -o /tmp/meshharbord.pkg \
  "https://meshharbor.itachi.fans/api/agent/installer/peruser?version=latest&os=macos"
sudo installer -pkg /tmp/meshharbord.pkg -target /
```

---

## 2. Enroll the agent

In the MeshHarbor admin UI:

1. **Admin → Tenant → Agents**.
2. Click **"Issue enrollment token"**. A 10-minute single-use JWT appears with a copy-pasteable `meshharbord enroll …` command.
3. Run that command on `AGENT-CORP` (the enrollment token is single-use, embedded in the command):

```powershell
meshharbord enroll `
  --server https://meshharbor.itachi.fans `
  --token <jwt-from-admin-ui> `
  --name "AGENT-CORP"
```

4. Start the agent. Either foreground for testing:

```powershell
meshharbord run
```

…or register as an auto-start service for production:

```powershell
meshharbord service install               # perUser scheduled task
# or:
meshharbord service install --as-service  # SCM service, runs as LocalSystem (requires the perMachine MSI)
```

Verify in **Admin → Tenant → Agents** that the row turned green (`status: online`).

---

## 3. Install the tunnel-client on `OPERATOR-LAPTOP`

**Win11:**

```powershell
Invoke-WebRequest `
  "https://meshharbor.itachi.fans/api/tunnel/installer/windows-x86_64?version=latest" `
  -OutFile "$env:USERPROFILE\Downloads\meshharbor-cli.zip"
Expand-Archive "$env:USERPROFILE\Downloads\meshharbor-cli.zip" `
  -DestinationPath "$env:LOCALAPPDATA\meshharbor-cli"
# RETIRED-NAME-ANCHOR(4): the ARCHIVE directory keeps the meshharbor-tunnel
# prefix by contract (release-tunnel.yml). Only the binary inside it was
# renamed to `meshharbor`.
# Optional — add to PATH:
[Environment]::SetEnvironmentVariable(
  "Path",
  "$env:Path;$env:LOCALAPPDATA\meshharbor-cli\meshharbor-tunnel-0.3.0-rc.46-x86_64-pc-windows-msvc",
  "User"
)
```

**Linux (.deb):**

```bash
curl -fsSL -o /tmp/meshharbor-cli.deb \
  "https://meshharbor.itachi.fans/api/tunnel/installer/linux-deb?version=latest"
sudo dpkg -i /tmp/meshharbor-cli.deb
# `mh` is now on $PATH at /usr/bin/mh
```

> **On an arm64 host** (FR-97 P7b) the same two downloads are
> `linux-deb-aarch64` and `linux-aarch64`. A release built before P7b has no
> aarch64 CLI, and the proxy answers 404 for it rather than hand over the
> x86_64 one. `install.sh --role tunnel` picks the arch by itself
> (`scripts/install.sh:682-686`), and the aarch64 wizard asks for
> `linux-aarch64`. The arm64 build is made on Ubuntu 22.04, so it needs glibc
> 2.35 or later, as the x86_64 agent does.

> ⚠️ **On Debian 12 and Ubuntu 22.04 this `.deb` cannot install** (#2472).
> `tunnel-v0.3.0-rc.266` depends on `libssl3t64`, the name Debian 13 and
> Ubuntu 24.04 use; these two call it `libssl3`. `dpkg -i` leaves the package
> unconfigured, and `apt-get -f install` removes it again. Use the plain tarball
> below. `install.sh --role tunnel` checks that `meshharbor` runs and falls back
> to the tarball on its own. The CLI now declares both names
> (`agents/meshharbor-cli/Cargo.toml`), so from tunnel-v0.4.149 on, the `.deb` is
> built to install on both generations.

**Linux (plain tarball):**

```bash
curl -fsSL -o /tmp/meshharbor-cli.tar.gz \
  "https://meshharbor.itachi.fans/api/tunnel/installer/linux-x86_64?version=latest"
# RETIRED-NAME-ANCHOR(2): archive directory name, frozen (see above).
mkdir -p ~/.local/opt && tar -C ~/.local/opt -xzf /tmp/meshharbor-cli.tar.gz
ln -sf ~/.local/opt/meshharbor-tunnel-*-x86_64-unknown-linux-gnu/meshharbor ~/.local/bin/
```

**macOS (universal tarball):**

```bash
curl -fsSL -o /tmp/meshharbor-cli.tar.gz \
  "https://meshharbor.itachi.fans/api/tunnel/installer/macos?version=latest"
# RETIRED-NAME-ANCHOR(2): archive directory name, frozen (see above).
mkdir -p ~/.local/opt && tar -C ~/.local/opt -xzf /tmp/meshharbor-cli.tar.gz
ln -sf ~/.local/opt/meshharbor-tunnel-*-universal-apple-darwin/meshharbor ~/.local/bin/
```

Verify:

```powershell
mh --version   # → meshharbor 0.4.16
```

---

## 4. Enroll the tunnel-client

In the admin UI:

1. **Admin → Tenant → Tunnels**.
2. Click **"Issue enrollment token"**. A 10-minute single-use JWT appears with a copy-pasteable `mh enroll …` command.
3. Paste-and-run on `OPERATOR-LAPTOP`:

```powershell
mh enroll `
  --server https://meshharbor.itachi.fans `
  --token <jwt-from-admin-ui> `
  --name "Operator laptop"
```

<!-- RETIRED-NAME-ANCHOR(5): the CLI resolves its config through
     ProjectDirs::from("ai", "meshharbor", "meshharbor-tunnel"). That segment is
     frozen: it holds the ENROLLED credential on tunnel only hosts, and
     renaming it strands every one of them. agents/meshharbor-cli/src/config.rs -->
This writes the long-lived `TunnelClient` JWT to:

- Windows: `%APPDATA%\meshharbor\meshharbor-tunnel\config.toml`
- Linux: `~/.config/meshharbor-tunnel/config.toml`
- macOS: `~/Library/Application Support/meshharbor-tunnel/config.toml`

Verify in **Admin → Tenant → Tunnels** that the row appears.

---

## 5. Create a tunnel ACL policy

Server-side ACL is **default-deny** — without a matching policy, every `TcpForwardRequest` is rejected with `acl_denied`. Define what each subject (user / role / specific tunnel-client) is allowed to reach via which agents.

**Admin → Tenant → Tunnel ACL → New policy.**

For an "ops team reaches the prod Postgres" policy:

| Field | Value |
|---|---|
| Name | `ops-prod-postgres` |
| Subjects | `Role ID` → `<your ops role hex>`, plus optionally `User ID` for specific users |
| Targets | `Agent ID` → `<AGENT-CORP hex from Admin → Agents>` |
| Allowlist | `Exact` `db.intranet.corp` ports `5432–5432`<br>(or `Wildcard` `*.intranet.corp` ports `5432–5432`<br>or `CIDR` `10.0.0.0/24` ports `1–65535`) |
| Max concurrent flows | leave blank, or `64` for tight JDBC-pool bounds |
| Max bytes / session | leave blank, or e.g. `10737418240` for 10 GiB cap |

Click **Create policy**. The row appears in the table and goes live immediately — there's no policy cache in front of MongoDB; every `TcpForwardRequest` reads the live set.

For a tenant-wide catch-all (everyone → every agent → anywhere) **for testing only**:

| Field | Value |
|---|---|
| Subjects | `All users` |
| Targets | `All agents` |
| Allowlist | `Wildcard` `*` ports `1–65535` |

Do not ship that to production — it disables the policy gate.

---

## 6. Open a forward + test

In a regular (non-elevated) PowerShell on `OPERATOR-LAPTOP`:

```powershell
mh forward `
  --agent <AGENT-CORP-hex from Admin → Agents> `
  --local 5432 `
  --remote db.intranet.corp:5432
```

Expected output:

```
INFO connecting websocket   ws_base=wss://meshharbor.itachi.fans/ws
INFO websocket connected
INFO rc:tunnel.opened   session_id=… transport=quic-v1 ice_servers=N quic=true
INFO QUIC: server provided TURN creds — establishing QUIC-over-TURN (relay)
INFO QUIC client: TURN relay allocated   relay_addr=…
INFO tunnel established   transport=quic-v1 path=relay remote=…
INFO listening for local TCP connections (quic-v1)   local=127.0.0.1:5432
```

(On a directly-reachable agent you'll see `path=direct` and no relay line. If the agent is older than rc.104 or QUIC setup fails, `--transport auto` falls back and you'll instead see `transport=webrtc-dc-v1`, `DC pool fully open (8 channels)`, and the WebRTC path.)

In a second shell, test with the real client:

```powershell
psql -h 127.0.0.1 -p 5432 -U <db-user> -d <db-name>
# Or any TCP service: curl http://127.0.0.1:8080/ , ssh -p 22 user@127.0.0.1 , etc.
```

The forward stays up until you press Ctrl-C. Each new `psql` connection opens a new flow to the agent — a fresh QUIC bidirectional stream (or, on the WebRTC fallback path, a `flow_id` over the existing DC pool) — with no per-connection ICE / relay setup.

### Declared routes (daemon-supervised — P6)

A foreground `forward` dies with its terminal, and even `forward --daemon`
(an ephemeral daemon flow) is gone when the device service restarts. A
**declared route** is persisted in the daemon's config
(`[[tunnel_routes]]`) and reconciled back into a live flow on every
daemon start — the set-and-forget form of the same forward:

```powershell
# Requires a local meshharbord (the device service) running on this host.
mh route add --agent <AGENT-CORP-hex> --local 5432 --remote db.intranet.corp:5432
mh route ls          # ID / KIND / NODE / LOCAL / REMOTE / TRANSPORT / STATE
mh route disable pg  # keep it declared, stop the listener
mh route enable pg   # also clears a terminal `failed` state
mh route rm pg       # remove entirely
```

Omit `--remote` for a supervised SOCKS5 listener toward the node. The
`STATE` column tells the truth about the local port — `active` is a
**bound, serving listener** and nothing less (#1685):

| `route ls` shows | Meaning | Listener on `127.0.0.1:<local>` |
|---|---|---|
| `pending` | declared; the reconciler has not created its flow yet | no |
| `connecting (fl-N)` | the flow exists; its first tunnel session toward the node is being opened | no |
| `active (fl-N)` | the tunnel session is up and the listener is bound | **yes** |
| `retrying (fl-N, attempt K, next in Ss): <error>` | the session failed K times in a row — the node is offline, the daemon's control connection is down, or the transport setup failed; `<error>` is the last attempt's | no |
| `backoff Ss: <error>` | the flow itself could not be created — its local port is taken (`route still cannot bind its local port` in the log names the holder) | no |
| `FAILED: <reason>` | terminal — a failure that cannot heal by retrying (enrollment revoked, cross-tenant); fix the cause and `route enable` | no |
| `disabled` | declared, not supervised | no |

⚠️ Before #1685 `active` meant "a hub flow exists for this route", so a
route to a switched-off machine read `active (fl-N)` with **no** listener
and every connect refused, indistinguishable from a healthy one; its
daemon log looped `tunnel session failed; retrying flow=fl-N`. A
`meshharbor` or companion older than the fix reading a newer daemon shows such
a route as `pending` / `backoff Ss: <error>` — true, less specific — because
the wire keeps its state words and only adds fields. The desktop app's
**Routes** page shows and manages the same list, appending `· device
offline` when the Devices data already knows why.

Notes:
- The daemon writes the routes into its own `config.toml`; on
  perMachine/SYSTEM installs that file lives under `%PROGRAMDATA%`, and
  any *interactive* user of the host can manage routes through the
  LocalAPI (same trust boundary as the existing ephemeral
  `forward --daemon` / consent verbs — the logged-in user of an enrolled
  host is its operator).
- On Linux fleet hosts where `meshharbord` runs as a root systemd unit, the
  LocalAPI socket is root-owned — prefix the CLI with `sudo`
  (`sudo mh route ls`).
- Routes do not survive a crash-loop auto-rollback to a pre-P6 daemon
  build (the older binary rewrites the config without the field).

---

## 6b. SOCKS5 — one proxy instead of N forwards

A forward maps one destination; a SOCKS5 proxy maps *everything the agent can
reach* (still policy-gated per destination, TCP **and** UDP):

```powershell
# Exit through one agent:
mh socks5 --agent <AGENT-CORP-hex> --local 127.0.0.1:1080

# Mesh mode — omit --agent: one proxy for the whole tenant.
# Address an agent by NAME (or 24-hex id) as the SOCKS hostname,
# and LAN IPs route to whichever agent advertises that subnet:
mh socks5 --local 127.0.0.1:1080
curl --socks5-hostname 127.0.0.1:1080 http://agent-corp:8080/
```

Point a browser, `curl --socks5-hostname`, or any SOCKS-capable app at it. Every
flow shows up in the same audit trail as forwards. Concepts (UDP ASSOCIATE,
longest-prefix LAN routing, transports): [tunnels.md](tunnels.md).

<!-- RETIRED-NAME-ANCHOR(4): this note EXISTS to explain the retired name, so
     the name has to appear in it. FR-21 D6. -->
> Naming note: the standalone binary is `mh` (a `meshharbor-tunnel` alias is
> still shipped); on daemon hosts `mh` is a shim into `meshharbord cli` —
> same commands either way.

---

## 7. Audit + diagnostics

**Admin → Tenant → Tunnels → click a tunnel-client → Audit** lists every `PeerOpen` / `TcpAccept` / `TcpReject` / `TcpDialFailed` / `TcpClosed` with timestamps, bytes-in/out, destination, and reject reason.

**Per-flow debug logs on the tunnel-client:**

```powershell
# RETIRED-NAME-ANCHOR: names the tracing target of pre-FR-21 builds. Renaming
# a lib renames its target, so an operator on an older CLI needs the old one.
$env:RUST_LOG = "meshharbor_cli=debug,tunnel_core=info"   # pre-FR-21 builds: meshharbor_tunnel=debug
mh forward --agent … --local 5432 --remote db.intranet:5432
```

**Per-flow debug logs on the agent**: tail the existing log file:

- Windows: `%LOCALAPPDATA%\meshharbor\meshharbor\data\logs\meshharbord.log.<date>`
- Linux: `~/.local/share/meshharbor/logs/meshharbord.log.<date>` (root daemon: `/root/.local/share/meshharbor/logs/`; `journalctl -u meshharbor` works too)

| Symptom | Likely cause | Fix |
|---|---|---|
| `forward request timed out` after 10 s | agent offline, or no matching ACL policy | Check `Admin → Agents` shows agent online; check `Admin → Tunnel ACL` has a matching policy |
| `acl_denied` from the server | policy gate rejected the (subject × target × destination) tuple | Edit the policy to include the destination, or add subject/target |
| `dial_failed` from the agent | destination unreachable from inside corp | Check from the agent host directly: `Test-NetConnection db.intranet -Port 5432` |
| `cross_tenant` | tunnel-client and agent belong to different tenants | Re-enroll one of them in the correct tenant |
| Never connects (no `tunnel established` / `DC pool fully open` line) | UDP blocked end-to-end **and** the TURNS/TCP (`:443`) relay also failing | Ensure outbound TCP/443 to the coturn cluster from both hosts; check `RUST_LOG=tunnel_core=debug,webrtc_ice=debug` |

---

## 8. Same-Win11-box smoke test (no corp network)

If you want to validate the wire end-to-end before involving the corp network:

```powershell
# Shell 1 — start a TCP listener on the local machine
python -m http.server 9999
# Shell 2 — agent (already installed + enrolled per §2)
meshharbord run
# Shell 3 — tunnel-client (already installed + enrolled per §4)
mh forward --agent <same-machine agent hex> --local 8000 --remote 127.0.0.1:9999
# Shell 4 — test
curl.exe http://127.0.0.1:8000/
```

The HTTP listing from python's server should appear via the tunnel. Bytes flow: curl → 127.0.0.1:8000 (tunnel-client) → wss://meshharbor.itachi.fans (signalling only) → WebRTC DC → agent dial → 127.0.0.1:9999 (python).

---

## 9. Tear down / revoke

**Stop the forward**: Ctrl-C on `mh forward`. The agent's side closes automatically; audit row recorded.

**Revoke a tunnel-client** (operator left the team, laptop lost, etc.): **Admin → Tenant → Tunnels → click client → Revoke**. The next WS read on that client gets a `rc:tunnel.revoked` message and the WS closes; further enrollment attempts with the same `machine_id` are rejected.

**Revoke an agent**: **Admin → Tenant → Agents → click agent → Revoke**. Same mechanism.

**Soft-delete a policy**: **Admin → Tenant → Tunnel ACL → click delete on the row**. Live tunnel sessions keep working until they close naturally; new `TcpForwardRequest`s that relied on that policy alone start being rejected with `acl_denied` from the next request onward.

---

## 10. Keeping the CLI current

**Tunnel-only hosts** (installed just the `mh` CLI — the tunnel-client role,
no daemon MSI) self-update in place:

```
mh self-update            # download + verify + swap the running exe
mh self-update --check    # report the latest version without installing
```

It polls `meshharbor.itachi.fans/api/tunnel/latest-release` and downloads the matching build
through the same corp-AV-friendly proxy. Before it swaps anything it checks two
things (FR-97 P6b):

- **The signature.** The artifact's detached `.asc` must verify against the
  release key **pinned in the binary** (tunnel-core's `pgp_verify`, the same check
  the agent's updater makes), on every OS. The manifest's SHA-256 is checked too,
  but it comes from the same server as the download, so it proves the transport,
  not the origin.
- **The version.** A Linux or macOS archive must name, inside its signed bytes,
  the version it was offered as: the tarball's top-level dir, the `.deb`'s control
  `Version`. So an older signed release cannot be passed off as the newest.

Then it installs by host:

| Host | Installs |
|---|---|
| Windows | the zip's `mh.exe` replaces the running exe |
| macOS, and Linux where no package owns the binary | the tarball's `mh`, written beside the running binary and renamed over it, so the swap is atomic |
| Linux where the binary came from the `.deb` (`install.sh --role tunnel` on Debian and Ubuntu) | `dpkg -i` of the verified `.deb`, so dpkg's record names the version on disk |

A binary in a root-owned directory needs root to replace, and `dpkg -i` always
does: run `sudo mh self-update`. Under `sudo` it reads the server from your
own config, not root's (which has no enrollment), unless `--config` names one. The
Linux and macOS install works from tunnel-v0.4.149, the first tunnel release after
P6b (field-verified on it: a tarball, a `.deb` and a Mac); an older CLI there, such as
rc.266, points at the manual download.
This is the single updater for tunnel-only hosts.

**Daemon hosts** (installed a "be-accessed" role — the agent MSI) do NOT need
this: since the node-stack unification the daemon MSI *carries* `mh.exe`, so
the daemon's own auto-update refreshes the CLI alongside `meshharbord` on every MSI
upgrade. `mh self-update` there is refused, and names `meshharbord self-update`
instead: that `mh` is a shim over the daemon, and the MSI is the source of
truth.
