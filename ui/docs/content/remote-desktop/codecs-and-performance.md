---
title: Codecs and performance
description: Which video codecs and hardware encoders MeshHarbor uses on Windows, macOS and Linux — and what to change when a remote session feels slow.
tags: [remote-desktop, performance, codecs, encoders, windows, macos, linux]
order: 4
---

MeshHarbor encodes the remote screen as video and decodes it in your browser. Which
encoder it uses depends on the machine's hardware, and it is chosen by
**probing** rather than by guessing.

## Codecs

| Codec | Notes |
|---|---|
| **H.264** | The universal floor. Available everywhere, decodes everywhere. |
| **HEVC** | Better quality per bit; needs support on both ends. |
| **AV1** | Best compression; newest hardware only. |
| **VP9** | Used for the 4:4:4 path, where crisp text matters more than motion. |

A codec is only offered when **both ends** can handle it, so a session always
negotiates down to something that actually works rather than failing.

## Hardware encoders by platform

:::os
@windows
The broadest support of the three. On startup the agent probes what the machine
can really do and advertises only what succeeded.

- **Media Foundation H.264** — the built-in hardware path.
- **NVIDIA, Intel and AMD** encoders for H.264, HEVC and AV1 where the GPU and driver provide them.
- **Software** (openh264) as the always-available floor.

Force one if you need to:

```powershell
meshharbord run --encoder hardware   # try hardware first
meshharbord run --encoder software   # skip hardware entirely
```

@macos
Apple Silicon encodes **H.264 and HEVC in hardware**, through Apple's
VideoToolbox. A Mac also offers software H.264 (openh264) and the VP9 4:4:4
path (libvpx), which is software on every Mac.

:::note What a Mac does not have
There is no AV1 hardware encoder on any shipping Mac (Apple has announced
none), and VideoToolbox's HEVC has no 4:4:4 profile, so full-color text
sessions use the software VP9 4:4:4 path.
:::

@linux
NVIDIA, Intel and AMD hardware encoders are used where the driver provides them,
with software as the floor.

The agent's capability probe runs in a **separate process** on purpose: a
graphics driver that faults while being probed then takes down the probe rather
than the agent. Before that, a bad driver could restart the agent straight back
into the same probe — a crash loop rather than a degraded machine.
:::

## Why a probe rather than a list

Reporting a codec as available because the hardware *ought* to support it is how
you get a session that negotiates a format and then produces nothing. The agent
therefore encodes an actual frame with each candidate at startup and advertises
only what worked.

## When a session feels slow

Work down this list — it is ordered by how often each one is the answer.

:::steps
1. **Check the connection indicator.** If it reads **Relay**, the path is the problem, not the encoder. A relayed pair is bandwidth-capped by design. See [cannot connect](/docs/troubleshooting/cannot-connect/).
2. **Check what the far end is doing.** A machine pinned at 100% CPU encodes slowly no matter which encoder it picked.
3. **Set priority to Responsiveness.** Trades sharpness during motion for input latency.
4. **Reduce the resolution at the far end.** A 4K desktop is four times the pixels of 1080p, and on a software encoder that is the whole budget.
5. **Try forcing hardware encoding** on Windows or Linux, in case the probe fell back for a reason worth knowing.
:::

:::tip "Slow" almost always means "relayed"
Across a lot of field measurement, the overwhelmingly common cause of a sluggish
session is a pair that fell back to a relay — very often because a VPN client on
one end captured the local network range. The same two machines on a direct path
are typically an order of magnitude better. Check the indicator first.
:::

## Browser-side decoding

Where the browser supports it, the viewer uses a **low-latency decode path** that
bypasses the video element's built-in buffering. It checks for the pieces it needs
(WebCodecs and encoded transforms) and falls back to the video element where they
are missing.

:::warning Why Chromium is the recommendation
A normal `<video>` element enforces a jitter buffer of roughly 80 ms regardless
of what you ask for, which is a large share of a remote-control latency budget.
Decoding frames directly and painting them avoids it. Chromium browsers are where
that path has had the most testing, so they give the best experience. Safari and
Firefox run the viewer too, with less testing so far.
:::

## What a good session looks like

| Path | Round-trip input latency |
|---|---|
| Same LAN | Single-digit milliseconds |
| Direct across the internet | Roughly the network round-trip, plus encode and decode |
| Relayed | Noticeably higher, and bandwidth-capped |

If a **LAN** pair feels slow, something is wrong and worth reporting. If a
**relayed** pair feels slow, the fix is to get it off the relay.
