---
title: HTTP API
description: MeshHarbor's REST API — how it is authenticated, how routes are scoped per organization, and where to find the full route list.
tags: [reference, api, http, developers, automation]
order: 4
---

Everything the web application does, it does through a REST API you can use too.

## Base and scoping

```
https://meshharbor.itachi.fans/api/...
```

Almost every route is **scoped to an organization** and nested accordingly:

```
/api/tenant/{organization_id}/room/{room_id}/message/...
/api/tenant/{organization_id}/agent/{agent_id}/...
```

:::warning Organization scoping is enforced, not decorative
An object is resolved **within** the organization in the path. A reference to an
object in a different organization is not found, rather than being fetched and
then checked — so a foreign id returns a 404 and leaks neither content nor
existence.

This matters because anyone can create an organization, so "is a member of some
organization" is not an authorisation check for anything addressed by id.
:::

## Authentication

| Caller | Credential |
|---|---|
| A browser session | An `HttpOnly` session cookie |
| A script or integration | A bearer token |
| An agent | Its own long-lived agent credential |

Tokens are audience-checked: a user token is refused where an agent token is
required, and the reverse.

:::warning A deleted device's credential stops working immediately
Agent-authenticated routes load the device row and refuse a revoked or removed
one. A **lookup failure** is deliberately a server error rather than a 401 — a
database blip must not tell a healthy fleet its credentials were revoked, which
would turn a wobble into an enrollment storm.
:::

## Rate limiting

Requests are rate-limited per client. The powerful device operations —
running a command, opening an SSH session — are additionally limited **per
caller, per device**.

:::tip That second limit protects the target, not just the server
A device holds a small number of pending session grants and evicts the oldest.
Without a ceiling, one noisy caller could push a legitimate caller's unredeemed
grant out of existence.
:::

## Route groups

| Group | Covers |
|---|---|
| `auth`, `oauth`, `user` | Sign-in, registration, profile |
| `tenant`, `member`, `role`, `invite` | Organizations, membership, permissions |
| `room`, `message`, `reaction`, `file` | Chat and files |
| `recording`, `export`, `search` | Call recordings, exports, search |
| `agent`, `session`, `turn` | Devices, remote sessions, relay credentials |
| `notification`, `push` | Notifications |
| `health` | Liveness and readiness |

## Errors

Standard HTTP status codes. A refusal that is a *policy decision* carries a
reason in the body — the same reason that lands in the audit log, so the two can
be correlated.

## Health

```bash
curl -sI https://meshharbor.itachi.fans/health         # liveness
curl -s  https://meshharbor.itachi.fans/health/ready   # readiness, with dependencies
```

Useful for a self-hosted deployment's monitoring.

## Realtime

A websocket at `/ws` carries chat, presence, call signalling and the agent
protocol. The same endpoint serves users and agents with different credential
audiences.

## Full route list

The complete surface, with request and response shapes, is in
[`docs/api.md`](https://github.com/jk-zhang-meta/MeshHarbor/blob/master/docs/api.md)
in the repository — generated from the routes themselves rather than maintained
separately, so it does not drift.

## Stability

:::warning The API is not yet versioned
It is the application's own interface, made available rather than designed as a
public product surface. Routes can change between releases. If you are
automating against it, pin the server version you tested against, and read the
release notes.
:::
