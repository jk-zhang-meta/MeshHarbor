---
title: Notifications
description: How MeshHarbor decides who to notify, where — in-app, browser push or email — and how to stop being told about things twice.
tags: [collaboration, notifications, push, email]
order: 4
---

Notifications answer one question: **who needs to know, and where are they?**

## What triggers one

:::cards
- **A mention** icon:info — Someone names you, or the whole room.
- **A thread reply** icon:video — Someone answers in a thread you are part of.
- **A direct message** icon:copy — Always notified.
- **A room invitation** icon:check — Someone adds you to a room.
- **A device event** icon:monitor — A consent request, or a machine needing attention.
:::

## Where it goes

The channel depends on whether you are there:

| You are | You get |
|---|---|
| **Active in the app** | An in-app notification only |
| **Away, with browser push enabled** | A push notification |
| **Away, without push** | An email |

:::tip You should not be told twice
Presence is tracked so that an in-app notification, a push and an email are not
all sent for the same event. If you *are* getting duplicates, it is worth
reporting — it means the dedupe is not seeing you as present.
:::

## Browser push

Push requires the browser's permission, which you grant per browser. Each
browser you sign in from is a separate subscription.

:::warning A push endpoint is validated when you subscribe
Push endpoints are supplied by the browser, and the server sends to them. They
are therefore checked to be genuinely external addresses before being accepted —
otherwise the endpoint would be a way to make the server issue requests inside
its own network.
:::

## Email

Used for invitations, account activation, and notifications when you are away
and have no push subscription. On a self-hosted instance, email is optional and
off until you configure it — invitations then have to be shared as links
instead.

## Consent requests

A remote-session consent request that nobody answers on the machine can be handed
to the **device owner** instead, as a link they can approve from anywhere —
including a phone, without signing in. See [consent](/docs/remote-desktop/consent/).

## Turning things down

Per-room notification settings control how much a busy room tells you.
Organization-wide, an administrator can decide which device events raise a
notification at all.
