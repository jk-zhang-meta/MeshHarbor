---
title: Self-host hardening
description: What to get right when running MeshHarbor yourself — secrets, TLS, the origin setting, storage, backups and the checks worth doing after every upgrade.
tags: [security, self-hosting, operations, hardening, docker]
order: 7
---

Self-hosting moves the trust boundary onto your own machine, which is the point.
It also moves the responsibility. This is the short list of things that matter.

## Secrets

:::steps
1. **Generate real secrets.** The token-signing secret and the relay secret must be random, not placeholders. The server **refuses to start** in production mode on the built-in default token secret — deliberately, so a default cannot reach production quietly.
2. **Keep datastore passwords alphanumeric.** The database password is interpolated into a connection URL, so `@`, `:`, `/`, `?` or `#` breaks it — and the failure looks exactly like a wrong password.
3. **Keep `.env.selfhost` out of version control** and readable only by the account running the stack.
4. **Rotate on exposure.** Changing the token-signing secret invalidates every existing session, which is the point.
:::

## TLS

There is no automatic TLS, deliberately — terminate it in whatever you already
run.

:::danger Session cookies are full API credentials
The session cookie is accepted as authentication, so it must never travel in
cleartext. Serve over HTTPS in anything that is not a laptop talking to itself.
:::

## Get the origin right

Set your public origin correctly. It is what sign-in returns, invitation links
and the cross-origin policy all key off.

:::warning A port is part of an origin
`http://127.0.0.1` and `http://127.0.0.1:8080` are different origins. A mismatch
here does not produce a helpful error — it produces a refused websocket upgrade
and an application whose realtime features silently do not work.
:::

By default, when no origins are configured, only the application's own origin is
allowed. That is the safe default; widening it is a deliberate act.

## Network exposure

| Should be reachable | Should not be |
|---|---|
| The HTTP port, behind your TLS terminator | The database |
| The conference media port range | The object store's admin port |

The database and object store are for the application, not for the internet.
Keep them on an internal network.

## Conference media

The one thing a reverse proxy cannot fix — see
[self-hosting](/docs/start/self-hosting/). Getting it wrong yields perfect
signalling and no video, which is a confusing failure to debug from the
application logs.

## Backups

Back up the **database** and the **object store** volumes. Not the container —
it is rebuilt from an image.

:::tip Test a restore before you need one
An untested backup is a hypothesis. Restore into a throwaway stack once and
confirm the application comes up and your files are there.
:::

## Keep it updated

Upgrading is `pull` then `up -d`. Subscribe to releases so you hear about
security fixes rather than discovering them.

## Access control still applies to you

Self-hosting does not change the model — it changes who runs it. Everything in
[users, roles and permissions](/docs/security/users-roles-permissions/),
[network ACLs](/docs/security/overlay-acls/) and [device
policies](/docs/security/device-policies/) works identically, and is worth
configuring rather than leaving open because "it is only us".

## After every upgrade

:::steps
1. The health endpoint returns success.
2. A device still shows online.
3. A remote session still connects.
4. A call still carries video — the most fragile of the four, and the one most likely to be affected by a network change.
:::
