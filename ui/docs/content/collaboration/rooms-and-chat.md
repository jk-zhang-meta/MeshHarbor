---
title: Rooms and chat
description: Organised rooms with threaded replies, reactions, mentions, rich text and full-text search — the conversation layer that ships with every MeshHarbor workspace.
tags: [collaboration, chat, rooms, messaging]
order: 1
---

Conversations live in **rooms**. A room is a place with a membership, a purpose
and a history.

## Rooms

| Kind | Who can see it |
|---|---|
| **Open** | Anyone in the organization can find and join it |
| **Private** | Members only; it does not appear to anyone else |

Rooms have a name, a purpose line and tags, all of which are searchable — so a
workspace with a hundred rooms is still navigable.

:::warning Private means private
A private room is invisible to non-members and cannot be joined without an
invitation. Only open rooms can be joined freely, and only members receive a
room's live updates.
:::

## Messages

:::cards
- **Rich text** icon:copy — Bold, italic, lists, links, inline code and code blocks.
- **Threads** icon:video — Reply in a thread to keep a side conversation out of the main flow.
- **Reactions** icon:check — Emoji reactions, including custom ones you upload.
- **Mentions** icon:info — Mention a person, or the whole room, and they get notified.
- **Attachments** icon:download — Drop a file into a message; it joins the room's library.
- **Editing** icon:terminal — Edit and delete your own messages.
:::

## Search

Full-text search across messages, rooms and people. Search is scoped to your
organization and to rooms you are actually a member of — you cannot search your
way into a room you were not invited to.

## Pinned messages

Pin the messages a room keeps coming back to — the runbook, the standing
decision, the link everyone asks for. Pinned messages are listed separately from
the scroll.

## A note on message formatting

:::danger Message HTML is sanitised on purpose, and the allowlist is a security control
Rendered messages are filtered through a strict allowlist, and inline CSS is
deliberately **excluded**. Author-controlled styling in a message is not a
cosmetic feature — it lets one message paint a full-screen overlay inside a page
the reader already trusts, which is credential phishing that no framing header
prevents.

If a formatting feature seems arbitrarily missing, this is usually why.
:::

## Export

A room's history can be exported for record-keeping or migration.

## Limits by plan

Member counts and file storage vary by plan; the mechanics above do not. See
[pricing](/pricing).
