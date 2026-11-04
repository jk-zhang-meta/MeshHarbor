# Self-hosting MeshHarbor

Everything, on your own machine, with no licence key, no activation, no device
cap and no phone-home. The self-hosted edition is the same code that runs the
hosted service — there is no crippled community build. See
[`LICENSING.md`](../LICENSING.md) for why that is a licence commitment rather
than a current-version promise.

We collect no telemetry from self-hosted deployments. That is deliberate: the
product asks you to run a privileged daemon that can see your screen, so an
install that quietly reported home would be indefensible.

---

## What you are about to run

One container serves the web app and the API behind nginx. Around it: MongoDB,
Redis, MinIO for file storage, and optionally coturn as a relay.

| Pillar | Works self-hosted |
|---|---|
| Remote desktop in a browser tab | yes — peer-to-peer, the server only signals |
| Overlay mesh, tunnels, SOCKS5, exit nodes, MagicDNS | yes |
| `meshharbor ssh` (no `sshd`, no open port) | yes |
| Chat, rooms, files, search | yes |
| Video conferencing (mediasoup SFU) | yes, with the media-port caveat below |
| Push notifications, email, OAuth, billing | needs your own keys — see *Optional integrations* |

### Choose a profile

The server is one binary composed from six modules, and the published image
comes in five **profiles** — the same server with only the pillars you run.
A smaller profile is not a crippled one: it is the same code with fewer doors,
and `GET /health` on any of them lists the modules it actually mounts.

| Profile | Image tag | What it runs | Needs alongside it | What it skips |
|---|---|---|---|---|
| `full` (default) | `<tag>` | everything | MongoDB, Redis, MinIO, coturn, the media port range | — |
| `collab` | `<tag>-collab` | chat, rooms, files, video calls | MongoDB, Redis, MinIO, coturn, the media port range | the device fleet, the overlay mesh, tunnels, remote desktop |
| `remote` | `<tag>-remote` | devices + remote desktop | MongoDB, Redis, coturn | the SFU worker build, MinIO, the overlay mesh |
| `mesh` | `<tag>-mesh` | devices + overlay mesh, tunnels, `meshharbor ssh` | MongoDB, Redis, coturn (and DERP relays if you run them) | the SFU worker build, MinIO |
| `access` | `<tag>-access` | devices + remote desktop + mesh — no chat, no calls | MongoDB, Redis, coturn | the SFU worker build, MinIO |

Pick one by **tag** when you pull (`MESHHARBOR_IMAGE=ghcr.io/jk-zhang-meta/meshharbor:<tag>-mesh`
in `.env.selfhost`) or by **`MESHHARBOR_PROFILE`** when you build from source. No published
`v*` image carries the hosted service's billing and newsletter module — that is what `meshharbor.itachi.fans`
runs, not what you run.

> The same package also holds the **`hosted-<date>-<sha7>`** tags and the moving `hosted`
> pointer: the image `meshharbor.itachi.fans` itself deploys, built from every merge to `master` by the
> `hosted image` workflow (FR-73). It is the `full` composition **plus** the billing module,
> holds no secret (everything is configuration), and is public because the source is — but it
> is not a release: it is whatever `master` was an hour ago, with the Stripe webhook and the
> newsletter routes mounted. Pull `latest` or a `v*` tag; leave `hosted-*` to the hosted service.

> A profile does not reject configuration it does not use: a `mesh` image given MinIO
> credentials simply never opens them. A web app built for `full` works against every
> profile — the navigation follows `GET /api/capabilities`, so a `mesh` server shows no
> chat or call surfaces even though the bundle carries them. Building your own bundle
> with `VITE_MODULES=fleet,network bun run build` prunes those routes out of it; the
> published image never needs that, the runtime answer alone decides.

---

## Quickstart

**You need** Docker with Compose v2, ~4 GB RAM, and ~10 GB disk.

```bash
git clone https://github.com/jk-zhang-meta/MeshHarbor.git
cd meshharbor

cp .env.selfhost.example .env.selfhost
```

Open `.env.selfhost` and fill in the four required values. Generate the two
secrets:

```bash
openssl rand -hex 32   # → MESHHARBOR_JWT_SECRET
openssl rand -hex 32   # → MESHHARBOR_TURN_SECRET
openssl rand -hex 24   # → MONGO_ROOT_PASSWORD
openssl rand -hex 24   # → MINIO_ROOT_PASSWORD
```

⚠️ Keep the datastore passwords alphanumeric. The Mongo one is interpolated into
a connection URL, so `@`, `:`, `/`, `?` or `#` inside it breaks the URL — and the
resulting failure looks like a wrong password rather than a quoting problem.

Then bring it up:

```bash
docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost pull
docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost up -d
```

⚠️ **Run `pull` first.** `up -d` on its own will *build* rather than fetch —
Compose treats a service with a `build:` section as buildable, so a missing
image is compiled from source instead of downloaded. Skipping the `pull` costs
you the twenty minutes the published image exists to save, and it does it
silently.

> Images are published at
> [`ghcr.io/jk-zhang-meta/meshharbor`](https://github.com/jk-zhang-meta/MeshHarbor/pkgs/container/meshharbor)
> for **linux/amd64 and linux/arm64**. The tag is a manifest list, so a
> Raspberry Pi, an Apple Silicon Mac and an x86 VPS all pull the same name and
> get the right image. Each architecture is built on its own native runner and
> smoke-tested there before publication — neither is emulated.

### Or build it from source

Always available, and never merely a fallback: the server is AGPL-3.0, and a
published image must never be the only way to run it.

```bash
docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost up -d --build
```

> **The build compiles the Rust server and mediasoup from source.** Measured
> **6 minutes** on a 2024 laptop (16 cores, Docker Desktop + WSL2); budget
> 15–20 on a small VPS or 2–4 cores. Subsequent starts are seconds.

> **Countries in the analytics.** The published image carries DB-IP's
> *IP to Country Lite* database ([CC BY 4.0](https://creativecommons.org/licenses/by/4.0/),
> credited on the dashboard) for the platform analytics' Countries breakdown. A
> source build carries it only if you run `scripts/fetch-geoip.sh` before
> building. Without it every country reads `unknown`, which is a supported
> state, and the boot log warns once. To turn country lookups off in either
> case, set `MESHHARBOR__STATS__GEOIP_MMDB` to an empty value. Details:
> [`files/geoip/README.md`](../files/geoip/README.md).

Watch it come up:

```bash
docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost logs -f meshharbor
curl -fsS http://localhost:8080/health && echo OK
```

Open <http://localhost:8080> and register, then create your organization from
the dashboard. The organization owns your devices, invitations and rooms, and
you are its owner — there is no separate admin bootstrap step and no seeded
account.

⚠️ Registration through the web app creates the account only; the organization
is the next step, not part of the same form.

---

## Add your first machine

> ⚠️ **Do the TLS step below first if the machine is not this one.** Enrollment
> tokens must travel over TLS, so the agent **rewrites `http://` to `https://`**
> for any address that is not loopback (`crates/agent-core/src/enrollment.rs`).
> Against a plain-HTTP server that produces
> `SSL routines:ssl3_get_record:wrong version number` — an error that names
> neither the cause nor the fix. `http://localhost:8080` is exempt and works, so
> enrolling *this* machine needs nothing extra; every other machine needs
> [a real hostname with TLS](#putting-it-behind-a-real-hostname).
> Editing the address in a device's `config.toml` back to `http://` does not get
> around this. Every load of the config reads a remote `http://` as `https://`
> (FR-101 P1b, [security-baseline.md](security-baseline.md) §4). A lab that
> knowingly runs without TLS sets `allow_plaintext_server = true` in that
> device's config, which is the device owner's decision and never the server's.

Mint an enrollment token in the web app (**Devices → Enroll device**), then on
the machine you want to reach:

```bash
# Linux / macOS
curl -fsSL https://<your-host>/api/setup/install.sh | sh -s -- \
    --role daemon --token <enrollment-jwt>

# Windows (PowerShell, elevated)
& ([scriptblock]::Create((irm https://<your-host>/api/setup/install.ps1))) `
    -Role daemon-system -Token <enrollment-jwt>
```

The script you fetch **already points at your server**: the route that serves it
substitutes your `MESHHARBOR_PUBLIC_URL` for the built-in default before the bytes
leave the process, because a piped script has no way to see the URL it came from
(FR-50). You can still pass `--server` / `-Server` to override it.

⚠️ **This depends on `MESHHARBOR_PUBLIC_URL` being right.** If it is not a plain
`scheme://host[:port]`, the server logs a warning and serves the script with the
hosted default untouched — at which point the agent downloads from you and then
tries to enroll against `meshharbor.itachi.fans` with a token only your server can verify,
failing with an authentication error that says nothing about the real cause.
Pass `--server` explicitly if you see that warning. The same value drives your
OAuth returns, invite links and CORS policy, so it is worth getting right
regardless.

⚠️ **On Windows, `irm … | iex` cannot pass arguments at all** — no `-Server`,
no `-Token`. The `scriptblock` form above is the one that can, and it is what
`scripts/install.ps1`'s own header documents.

The token is single-use and expires in 10 minutes. The agent connects
**outbound only** — nothing needs to be opened on the machine you are enrolling.

Then, from the web app, open its desktop; or from any enrolled machine:

```bash
meshharbor ping   <name>          # every node has a stable IP and a MagicDNS name
meshharbor ssh    <name>          # a shell, with no sshd and no listening port
meshharbor forward --agent <name> --local 127.0.0.1:5432 --remote db.internal:5432
```

---

## Putting it behind a real hostname

Optional while you are trying it out on one machine, **required the moment you
add a second** — enrollment refuses plaintext to anything but loopback, as the
warning above explains.

Terminate TLS in front of the stack and point it at `MESHHARBOR_HTTP_PORT`. The app
needs WebSocket upgrades on `/ws` and `/derp`, and both are long-lived — set
generous read timeouts or sessions will be cut every 60 seconds.

⚠️ Whatever you put in front must **forward `Upgrade` and `Connection`**. A
proxy that drops them leaves a device that enrolls successfully and is then
never seen online again, because the agent's control socket can never open —
and nothing in the UI distinguishes that from a machine that is switched off.

```caddy
meshharbor.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy handles WebSockets and certificates with no further configuration. With
nginx, add the usual `Upgrade` / `Connection` headers and
`proxy_read_timeout 3600s`.

Then update `.env.selfhost` and restart:

```bash
MESHHARBOR_PUBLIC_URL=https://meshharbor.example.com
MESHHARBOR_ANNOUNCED_IP=<the host's public IP>
MESHHARBOR_PUBLIC_IP=<the host's public IP>
MESHHARBOR_TURN_URL=turn:meshharbor.example.com:3478
```

⚠️ `MESHHARBOR_PUBLIC_URL` is used for OAuth callbacks and for the links inside
invitation and notification email. A stale value produces invitations that lead
nowhere, and it is not obvious from the failure.

---

## Conference media — the one part that is not a proxy problem

Remote desktop, tunnels, SSH and the overlay mesh are peer-to-peer with a relay
fallback, and work through anything. **Conference video is different**: browsers
send RTP straight at an address the server advertises, on a UDP port range, and
no reverse proxy is involved.

Two settings decide whether it works:

- `MESHHARBOR_ANNOUNCED_IP` — the address browsers send to. `127.0.0.1` works only
  for calls made on the host itself.
- the RTC port range — 32 ports are mapped by default, enough to try it out.

On **Linux**, the clean answer is host networking: give the `meshharbor` service
`network_mode: host`, delete its `ports:` block, and the full 40000–49999 range
is reachable. That is how the hosted service runs. It is not available on Docker
Desktop for macOS/Windows, which is why the port-mapped form is the default.

If signalling looks perfect and no video arrives, this is nearly always the
cause. `connect_transport` succeeding proves only that the client sent its DTLS
parameters — it says nothing about whether packets can flow.

---

## Optional integrations

None of these are required to run the product; all are off until you supply
keys. Add them to the `meshharbor` service's `environment:` block, using the names
from [`.env.example`](../.env.example).

| Feature | Variables |
|---|---|
| Outbound email (invites, notifications, activation) | `MESHHARBOR__EMAIL__*` |
| OAuth sign-in (Google, GitHub, Microsoft, LinkedIn, Facebook) | `MESHHARBOR__OAUTH__*` |
| Web push | `MESHHARBOR__PUSH__*` |
| AI document recognition | `MESHHARBOR__CLAUDE__API_KEY` |
| Stripe billing | `MESHHARBOR__STRIPE__*` |

⚠️ `MESHHARBOR_AUTO_VERIFY=true` is the default **because no SMTP is configured out
of the box** — an account waiting on an activation email that can never arrive is
an account nobody can use. Set it to `false` once email works.

---

## Upgrading

```bash
git pull
docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost up -d --build
```

Schema migrations run at startup and are leader-gated, so it is safe to restart
into a newer build.

⚠️ **Agent updates are a separate track from your server.** Enrolled agents ask
*your* server for the current release, but that endpoint proxies the upstream
[GitHub releases](https://github.com/jk-zhang-meta/MeshHarbor/releases) — it does not
serve builds you produced. Your server is the download host (so corporate
allow-lists only need to trust your hostname, and `github.com` need not be
reachable from the endpoint), while the *version* your fleet converges on is the
upstream one. Rebuilding the server image does not change what agents install.

## Backups

The state that matters lives in two volumes: `mongo_data` (everything except
files) and `minio_data` (uploaded files).

```bash
docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost \
  exec -T mongo mongodump --archive --gzip \
  -u "$MONGO_ROOT_USERNAME" -p "$MONGO_ROOT_PASSWORD" --authenticationDatabase admin \
  > meshharbor-$(date +%F).archive.gz
```

Keep `.env.selfhost` with the backup. Losing `MESHHARBOR_JWT_SECRET` invalidates
every session and every enrolled agent's token — the fleet would have to
re-enroll.

---

## No plan limits

A self-hosted server holds no organization to a plan limit: no device or user
count, no cap on concurrent remote sessions, no meeting length. Plans are sold only
by the hosted service, through a module the self-hosted image is built without.
Every organization still shows `free` in the database, because nobody sold it
anything; on this server that name carries no limits (`Core::plans_sold`,
[FR-115](fr/FR-115-pricing-reshape.md)).

## Known limitations, stated plainly

- **No prebuilt image yet.** First run compiles from source. Tracked in
  [FR-39](fr/FR-39-launch-readiness.md).
- **Single node.** The compose stack is one API instance. Multi-pod scale-out is
  supported by the code (Redis fan-out, leader-gated startup) but is a
  Kubernetes topology, not this file — see
  [`multi-pod-scale-out.md`](multi-pod-scale-out.md).
- **No automatic TLS.** Deliberate: terminate it in whatever you already run.
- **coturn is optional and off the critical path.** The DERP floor over the
  API's own port already guarantees connectivity when no direct path exists.

## Getting help

[Open an issue](https://github.com/jk-zhang-meta/MeshHarbor/issues). Include
`docker compose ... logs meshharbor | tail -100`, your OS, and whether you are
behind a reverse proxy — those three answer most of it.
