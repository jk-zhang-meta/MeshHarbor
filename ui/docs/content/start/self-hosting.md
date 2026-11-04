---
title: Self-hosting Roomler
description: Run the whole Roomler server yourself with one compose file and a published container image — accounts, signalling, chat, conferencing and relays.
tags: [self-hosting, install, docker, getting-started, operations]
order: 15
---

Self-hosting is a first-class path, not a stripped-down one. The same server that
runs the hosted service runs on your own box, minus its billing, with **no feature
held back** and no plan limits: no device or user count, no cap on remote
sessions, no meeting length.

## What you are about to run

One container with the API, the web app, the signalling plane, the chat and
conferencing server and the relay floor — plus MongoDB and MinIO for state and
file storage.

**You need** Docker with Compose v2, about **4 GB RAM** and **10 GB disk**.

## Quickstart

```bash
git clone https://github.com/gjovanov/roomler-ai.git
cd roomler-ai
cp .env.selfhost.example .env.selfhost
```

Fill in the required values in `.env.selfhost`. Generate the secrets:

```bash
openssl rand -hex 32   # MESHHARBOR_JWT_SECRET
openssl rand -hex 32   # MESHHARBOR_TURN_SECRET
openssl rand -hex 24   # MONGO_ROOT_PASSWORD
openssl rand -hex 24   # MINIO_ROOT_PASSWORD
```

:::warning Keep the datastore passwords alphanumeric
The MongoDB password is interpolated into a connection URL, so a `@`, `:`, `/`,
`?` or `#` inside it breaks the URL. The resulting failure looks exactly like a
**wrong password** rather than a quoting problem, which is a bad hour to spend.
:::

Then bring it up:

```bash
docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost pull
docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost up -d
```

:::danger Run `pull` first — `up -d` alone will BUILD
Compose treats a service that has a `build:` section as buildable, so a missing
image is **compiled from source instead of downloaded**. Skipping the `pull`
costs you the twenty minutes the published image exists to save, and it does it
silently. On a clean 4-vCPU VM with a data-centre connection, `pull` took
**10 seconds**, `up -d` **21**, and `/health` answered **32 seconds** after the
first command (measured 2026-10-12). The pull is the part a slower connection
stretches: an earlier run over a home connection took 88 seconds in all.
Building instead takes roughly **six minutes** on a 16-core machine.
:::

Images are published at `ghcr.io/gjovanov/roomler-ai` for **linux/amd64 and
linux/arm64** and are anonymously pullable; every other image in the file is
published for both as well. The arm64 Roomler image is built and smoke-tested
on a native arm64 machine, but the whole stack has not yet been run on an arm64
host.

Watch it come up:

```bash
docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost logs -f roomler
```

## Add your first machine

Your server serves its **own** installers, and the script it hands out names
*your* origin rather than `roomler.ai` — so a machine enrolled from a
self-hosted instance enrols against that instance. Mint a token in your own
dashboard and follow [Get started](/docs/start/).

## Putting it behind a hostname

There is **no automatic TLS**, deliberately: terminate it in whatever you
already run — nginx, Caddy, Traefik, a cloud load balancer. Point the proxy at
the container's HTTP port and set your public origin in the environment so
sign-in returns, invite links and the CORS policy all agree about who you are.

## Conference media — the one part a proxy cannot fix

:::danger This is the failure people hit
Remote desktop, tunnels, SSH and the mesh are peer-to-peer with a relay
fallback, and work through anything. **Conference video is different**: browsers
send media straight at an address the server advertises, on a UDP port range,
with no reverse proxy involved.

If signalling looks perfect and no video ever arrives, this is nearly always the
cause. A successful transport connect proves only that the browser *sent its
parameters* — it says nothing about whether packets can flow.
:::

Two settings decide it:

| Setting | What it must be |
|---|---|
| The **announced IP** | The address browsers should send media to. `127.0.0.1` works only for calls made on the host itself. |
| The **RTC port range** | 32 ports are mapped by default — enough to try it. A real deployment wants the full range. |

On **Linux**, the clean answer is host networking: give the `roomler` service
`network_mode: host` and drop its `ports:` block, and the whole range is
reachable. That is how the hosted service runs. It is not available on Docker
Desktop for macOS or Windows, which is why the port-mapped form is the default.

## Optional integrations

All off by default; each is a block of environment variables:

:::cards
- **Email** icon:info — Invites, notifications and account activation.
- **OAuth sign-in** icon:shield — Google, GitHub, Microsoft, LinkedIn and Facebook.
- **Web push** icon:video — Browser notifications when someone is offline.
- **Billing** icon:book — Stripe, if you are reselling access.
:::

## Upgrading and backups

Upgrading is `pull` then `up -d`. State lives in the MongoDB and MinIO volumes —
back those up, not the container.

## Known limitations, stated plainly

- **Single node.** The compose stack runs one API instance. Multi-node scale-out *is* supported by the code, but it is a Kubernetes topology rather than this file.
- **No automatic TLS.** Deliberate — see above.
- **arm64 is published but not yet run end to end.** Every image has an arm64 build; nobody has brought the whole stack up on an arm64 host yet.
- **The relay is optional.** A separate TURN server is not on the critical path: the built-in relay floor over the API's own port already guarantees connectivity when no direct path exists.

## Licensing

The server is **AGPL-3.0**; the agent that runs on your machines is **MPL-2.0**.
Running it for yourself, your family or your company is exactly what the licence
is for. See [`LICENSING.md`](https://github.com/gjovanov/roomler-ai/blob/master/LICENSING.md)
for the split and what it means if you intend to offer it as a service.
