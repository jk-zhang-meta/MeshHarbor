# Use Cases

What people run MeshHarbor for — in plain language, scenario by scenario — followed
by the key flows (permissions, lifecycles) that make those scenarios work.
Scenarios first, no engineering background required; technical flows second, for
operators and developers.

## 🖥️ 1 · Desktop sharing & remote control

<p align="center">
  <img src="assets/remote-desktop.svg" alt="A laptop anywhere showing the live desktop of an office PC inside a browser tab" width="720">
</p>

### Remote support with consent

Help a family member or a colleague: they enroll their PC once (a 10-minute
token), you connect from a browser tab. The session is consent-gated on their
side and every event is audit-logged. What that means in practice: **only the
person at the desk can let you in**, and there is always a record of who
controlled what, when.

```mermaid
sequenceDiagram
    participant H as Helper (browser)
    participant S as meshharbor.itachi.fans
    participant O as Owner's PC (meshharbord + tray)

    H->>S: Connect (Devices → their PC)
    S->>O: session request
    O->>O: tray prompt "Allow H to control?" (30 s)
    O->>S: approved
    S-->>H: session ready
    H->>O: WebRTC P2P — screen + input (E2E-encrypted)
    Note over S: sees only signalling + audit events
```

### Unattended access to your own machines

Your office PC from home, headless cloud servers (virtual-desktop mode gives them
a screen), a GPU workstation driven from a thin laptop over a hardware-encoded,
low-latency stream. On Windows the SystemContext service controls the lock
screen, UAC prompts, and pre-logon — a reboot doesn't lock you out. Auto-consent
is the default for self-controlled hosts, so your own machines never make you
wait.

## 🔐 2 · Your own secure private network

<p align="center">
  <img src="assets/private-network.svg" alt="A laptop, GPU box, home server and cloud cluster joined in a private WireGuard mesh with stable names" width="720">
</p>

### The database behind the office firewall

```bash
mh forward --agent office-1 --local 127.0.0.1:5432 --remote db.internal:5432
psql -h 127.0.0.1   # you're inside
```

No VPN concentrator, no exposed port — the flow rides an outbound-only tunnel and
is gated by a default-deny ACL policy an admin manages centrally
([tunnels.md](tunnels.md)).

### Seeing the network as another machine sees it

`mh socks5 --agent berlin-1 --local 127.0.0.1:1080` gives any app a SOCKS5
proxy that exits from that machine — corp-LAN dashboards, region-locked services,
E2E tests from a real customer vantage. Mesh mode (`--agent` omitted) reaches the
*whole fleet* through one proxy, addressing agents by name.

### A private network across home, office, and cloud

Every daemon is an overlay-mesh node: stable private IP (`100.64.0.0/10`),
MagicDNS name (`gpu-1.<your-domain>`), direct LAN paths when possible, NAT
hole-punching and relays when not ([overlay-communication.md](overlay-communication.md)).
`mh ssh gpu-1` opens a shell on any node with **no `sshd` and no open
port** ([meshharbor-ssh.md](meshharbor-ssh.md)). Optional
[exit nodes](overlay-exit-nodes.md) route a laptop's entire internet egress
through a trusted machine — hotel Wi-Fi looks like your home connection.

### A harness for AI agents

A controllable desktop on every machine plus fenced networking between them:
enroll a VM, run a coding agent in a tmux session under virtual-desktop mode,
watch it from a browser tab, take over instantly, close the tab and it keeps
running. The overlay gives orchestrators and workers stable names; default-deny
tunnel ACLs decide exactly which hosts and ports a sandbox may touch. More in
[agent-tunnel-architecture.md](agent-tunnel-architecture.md#ai--agentic-development).

### Operating a fleet

The Devices, Network, and Observability views show every machine, the live mesh
graph with carrier types, relay usage, and per-org activity.
`mh exec` / the device console run commands on trusted devices through four
independent default-deny gates with a full audit trail ([fleet-rpc.md](fleet-rpc.md)).

## 💬 Bonus · Video conferencing & team collaboration

<p align="center">
  <img src="assets/collaboration.svg" alt="A four-person video call with screen sharing next to a chat room with threads and reactions" width="720">
</p>

### A team hub — chat, calls, files

The included pillar: hierarchical rooms (text + voice/video), threads, reactions,
mentions, per-room calls on the mediasoup SFU, recordings, file library with AI
document recognition, full-text search. One org = one tenant; roles gate
everything (see [permission system](#permission-system)).

---

## Permission System

A **u64 bitfield** per role; a member's effective permissions are the union of
their assigned roles. 31 flags today (bits 0–30). The engineering reference,
including how the seeded roles are kept up to date and what a `403` means, is
[permissions.md](permissions.md).

| Bit | Flag | Grants |
|-----|------|--------|
| 0 | `VIEW_CHANNELS` | See rooms |
| 1 | `MANAGE_CHANNELS` | Create/edit/delete rooms |
| 2 | `MANAGE_ROLES` | Role CRUD |
| 3 | `MANAGE_TENANT` | Tenant settings |
| 4–5 | `KICK_MEMBERS` / `BAN_MEMBERS` | Member moderation |
| 6 | `INVITE_MEMBERS` | Create invites |
| 7–14 | `SEND_MESSAGES` · `SEND_THREADS` · `EMBED_LINKS` · `ATTACH_FILES` · `READ_HISTORY` · `MENTION_EVERYONE` · `MANAGE_MESSAGES` · `ADD_REACTIONS` | Chat |
| 15–20 | `CONNECT_VOICE` · `SPEAK` · `STREAM_VIDEO` · `MUTE_MEMBERS` · `DEAFEN_MEMBERS` · `MOVE_MEMBERS` | Voice/video |
| 21 | `MANAGE_MEETINGS` | Start/end conferences |
| 22 | `MANAGE_DOCUMENTS` | File management |
| 23 | `ADMINISTRATOR` | Bypasses **every** check — `has()` short-circuits on it, so this grants bits 24–30 too |
| 24 | `MANAGE_AGENTS` | Enroll/manage devices, tunnel policies, overlay approvals |
| 25 | `REMOTE_CONTROL` | Open remote-desktop sessions |
| 26 | `VIEW_REMOTE_AUDIT` | Read session audit |
| 27 | `EXEC_DEVICE` | Fleet RPC — deliberately **not** in the default admin set |
| 28 | `VIEW_EXEC_AUDIT` | Read the exec audit log |
| 29 | `SSH_DEVICE` | Open a meshharbor-SSH session — also **not** in the default admin set |
| 30 | `VIEW_SSH_AUDIT` | Read the SSH audit log |

```
has(perms, flag) = (perms & ADMINISTRATOR != 0) || (perms & flag == flag)
```

Rooms can overwrite per-role/per-user: `effective = (base & ~deny) | allow`.
Default roles: **member** gets the everyday chat/voice bits; **admin** adds
management bits (but neither `EXEC_DEVICE` nor `SSH_DEVICE` — and not
`MANAGE_TENANT`, so org-level settings stay the owner's); the **owner** role
has all bits, and carries `ADMINISTRATOR` besides.

⚠️ These five roles are **system-managed**: their masks are defined once in
`role::MANAGED_ROLES` and reconciled to every existing organisation at
startup, so a permission bit added to the code reaches orgs that already
exist. Before FR-82 they were written once at tenant creation and never
again — 63 of 72 hosted orgs were still frozen at their creation-day masks.
See [permissions.md](permissions.md).

## Authentication

```mermaid
sequenceDiagram
    participant B as Browser
    participant S as API
    B->>S: POST /api/auth/register {email, username, password, tenant_name?|invite_code?}
    S-->>B: {access_token (httpOnly cookie), refresh_token, user}
    B->>S: authenticated requests (cookie or Bearer)
    B->>S: POST /api/auth/refresh {refresh_token}
    S-->>B: rotated tokens
```

Login by email *or* username (Argon2-verified); OAuth via Google / Facebook /
GitHub / LinkedIn / Microsoft. Device credentials (agents, tunnel clients) use
separate JWT audiences and a two-step enrollment — see
[api.md](api.md#authentication).

## Room & call lifecycle

Rooms are polymorphic — capabilities come from fields, not types:
`media_settings` present ⇒ calls possible; `parent_id` ⇒ nested; `is_open` ⇒
publicly joinable; `is_read_only` ⇒ announcements.

```mermaid
flowchart LR
    C["create room"] --> M["members join"]
    M --> CHAT["chat: threads · reactions ·<br/>pins · files · mentions"]
    M --> CALL["call/start"]
    CALL --> LIVE["conference InProgress<br/>ws: room:call_started<br/>media:join → SFU"]
    LIVE --> REC["recordings · in-call chat"]
    LIVE --> END["call/end<br/>ws: room:call_ended"]
    END --> BG["recordings processed<br/>(background task)"]
```

## Remote-desktop session lifecycle

```mermaid
flowchart LR
    REQ["controller requests session<br/>(REMOTE_CONTROL perm)"] --> CON{"consent"}
    CON -->|"auto-grant (own device)"| UP
    CON -->|"tray / LocalAPI prompt"| UP["WebRTC P2P established"]
    CON -->|"deny / 30 s timeout"| X["refused (audited)"]
    UP --> RUN["screen · input · clipboard ·<br/>files · apps · audio"]
    RUN --> T["terminate (either side,<br/>or admin force-terminate)"]
    T --> AUD["remote_audit trail (90 d)"]
```

## Tunnel policy flow

Default-deny: a flow opens only if an admin-authored policy allows that
*subject* (user / tunnel client) to reach that *destination* through that
*agent* — and the exit machine's own `forward_acl` agrees. Every flow lands in
`tunnel_audit`. Overlay subnet routes and exit nodes follow the same
approve-explicitly pattern (`overlay-node` admin routes, [api.md](api.md#overlay-network)).

## File lifecycle

Upload (multipart, versioned) → MinIO/S3 → optional AI recognition (Claude
vision: raw text, structured JSON, document type, confidence) → download or
cloud sync (Google Drive / OneDrive / Dropbox).

## Invite flow

Invite `{code, max_uses, expires_at, assign_role_ids}` → share link/email/batch →
acceptance creates the membership and assigns roles → status: active / exhausted /
expired / revoked.
