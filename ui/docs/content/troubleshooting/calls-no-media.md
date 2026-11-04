---
title: Calls have no video
description: Everyone joins the call and nobody appears — the media path, why signalling can look perfect while no packets flow, and what to check first.
tags: [troubleshooting, video, calls, webrtc, self-hosting]
order: 4
---

The signature is distinctive: participants join, the interface looks right,
nobody sees anybody. That combination points at the **media path**, not at the
application.

:::danger Joining a call proves nothing about media
The steps that get you into a call are signalling. A successful transport
connect means only that your browser **sent its parameters** — no packet has
been carried yet. So "everything succeeded and there is no video" is not a
contradiction; it is the expected shape of this failure.
:::

## On the hosted service

### 1 · Browser permissions

Camera and microphone must be permitted for the site. A blocked permission shows
as a camera-off tile rather than an error.

### 2 · Is anyone's camera actually on?

A tile showing an avatar instead of video means that person's camera is off —
which is displayed deliberately rather than leaving a frozen last frame on
screen.

### 3 · A very restrictive network

Some networks block the UDP range media uses. Symptom: calls work everywhere
except one location.

### 4 · Works for some colleagues and not others

:::tip This pattern points at one server node, not the application
On a multi-node deployment, an organization's users are grouped onto one node.
If a node is missing its media forwarding rules, it breaks **a consistent subset
of organizations** while everyone else is fine.

"Video works for team A but not team B" is therefore a per-node media-path
suspect, not an application bug. Worth reporting with which organizations are
affected.
:::

## On a self-hosted instance

This is where it nearly always is.

:::danger Conference media does not go through your reverse proxy
Browsers send media **directly** to an address the server advertises, on a UDP
port range. No proxy is involved and none can help.

Two settings decide whether anything arrives:

- **The announced address** — what browsers should send to. `127.0.0.1` works only for a call made on the host itself.
- **The RTC port range** — a small range is mapped by default, enough to try it. A real deployment wants the full range reachable.
:::

On **Linux**, host networking is the clean fix: give the service
`network_mode: host` and drop its port mappings. That is how the hosted service
runs. It is unavailable on Docker Desktop for macOS and Windows, which is why
the port-mapped form is the default.

Check the announced address first:

```bash
docker compose -f docker-compose.selfhost.yml --env-file .env.selfhost \
  logs meshharbor | grep -i announced
```

If it reports a loopback or container-internal address, that is your answer.

### The other self-hosting cause

:::warning An empty relay URL makes calls unjoinable in any browser
A blank relay address advertises an ICE server with an empty URL, which browsers
reject outright — so **nobody** can join, in any browser, on any network. If no
call has ever worked on a fresh deployment, check this before the port range.
:::

## Audio works, video does not

Usually bandwidth. Audio is small and survives; video is the first thing dropped
when a path cannot carry it. Check the network between the participant and the
server.

## What to include when reporting

- Whether it is hosted or self-hosted
- Whether **anyone** ever sees video, or only some people
- Whether audio works
- For self-hosted: the announced address and the port range
