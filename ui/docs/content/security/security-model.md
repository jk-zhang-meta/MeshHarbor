---
title: Security model
description: What is encrypted, what the server can see, where trust sits, and which properties are structural rather than promised.
tags: [security, encryption, privacy, design, architecture]
order: 1
---

## Encryption

| Traffic | Encryption |
|---|---|
| Browser to server | TLS |
| Agent to server (control) | TLS |
| Remote-desktop session | End to end, between browser and agent |
| Mesh traffic | End to end, between the two machines |
| Tunnel and SSH payloads | End to end |
| Relayed traffic | Already encrypted; the relay forwards ciphertext |

:::badges
- **End to end means the endpoints** icon:shield — keys are negotiated between the two machines, not issued by the server.
- **A relay cannot read what it carries** icon:network — adding a relay hop is a performance decision, never a privacy one.
- **The mesh uses established cryptography** icon:check — a WireGuard-style construction rather than something invented here.
:::

## Where trust actually sits

Being precise about this is more useful than a general assurance:

**You trust the server to:**
- authenticate people correctly, and enforce the permissions it is given
- tell each machine the truth about which peers exist
- introduce two endpoints honestly

**You do not have to trust the server with:**
- the contents of a remote session, a tunnel, an SSH session, or mesh traffic
- the decision to enable SSH or remote commands on a machine — those are device-held
- the ability to make a machine relay, act as an exit node, or reconfigure itself, unless that machine opted in

:::danger The device-held gates are the load-bearing part
Every server-side gate falls together if the control plane is compromised. The
gates that live in a machine's own configuration are the ones that do not, and
they are structurally absent from anything the server can push.
:::

## Authentication

Sign in with a password or an OAuth provider (Google, GitHub, Microsoft,
LinkedIn, Facebook). Sessions are held in `HttpOnly` cookies rather than handed
to JavaScript, and are marked `Secure` in production.

:::warning An email address is a reservation, not a contact field
An account only holds an email address if it **proved** ownership of it. A
sign-in provider that merely *asserts* an address — some do, and the assertion
is under the asserting organization's control — does not get to reserve it, and
cannot use it to link into an existing account.

That is what closes a well-known class of account-takeover through a hostile
identity provider, and it is why an unverified provider sign-in behaves more
conservatively than you might expect.
:::

## Agents

Each agent has its own long-lived credential, bound to one machine and one
organization. Deleting a device revokes it immediately; the revocation is
checked on every request the agent makes, not only at connect time.

## Known limits, stated plainly

Honest documentation includes what is not yet done:

- **User sessions are not individually revocable.** Signing out clears your cookie, but an access token already issued remains valid until it expires. Disabling a user does not terminate a session already in progress. This is a known gap.
- **There is no password-change flow yet.**
- **Network ACLs are feature-complete but not yet widely exercised in enforcing mode.** Move an organization to warning mode first and read the results before switching to enforcement.

## Reporting a vulnerability

Please report privately rather than opening a public issue. Details are in
[`SECURITY.md`](https://github.com/jk-zhang-meta/MeshHarbor/blob/master/SECURITY.md).

## Verifying rather than believing

The server is AGPL-3.0 and the agent is MPL-2.0. Every claim on this page is
checkable in the source rather than promised in prose, and the audit log records
what was actually decided.
