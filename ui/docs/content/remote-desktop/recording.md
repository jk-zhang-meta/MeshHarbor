---
title: Screen recording
description: Record your own screen from meshharbor-desktop, or the screen of a machine you control from the viewer, in full quality, then cut it, speed it up and add music.
tags: [remote-desktop, recording, sessions]
order: 7
---

MeshHarbor records a screen to an ordinary MP4 file. You can record **your own
screen** from meshharbor-desktop, or **the screen of a machine you are
controlling** from the viewer's toolbar. Either way the recording is made on the
machine whose screen it shows, and the file stays there until someone opens or
downloads it.

:::badges
- **Full quality** icon:video — encoded on that machine, not copied from the live stream. The live view shrinks to fit a slow network; the recording keeps the screen's own resolution.
- **Never through the server** icon:shield — a remote recording reaches you over the session's own peer-to-peer channel. The server never holds any of it.
- **Plays anywhere** icon:file — a standard MP4 that your system's own player opens.
:::

## Record your own screen

On the machine, open **meshharbor-desktop → Recordings**, set the options under
**Record this screen**, and press **Start recording**.

| Option | Choices |
|---|---|
| **Frame rate** | 30 fps (the default) or 60 fps |
| **Encoder** | Automatic (GPU, else software), GPU only, or Software only |
| **Computer audio** | What the computer plays. Off unless ticked |
| **Microphone** | Off unless ticked |

While it records, the view shows a red **REC** chip with the running time, the
size, the encoder and the resolution, and the tray icon turns red. **Stop
recording** is in the view and in the tray menu.

The same from a terminal on that machine:

```bash
mh record start --fps 60 --system-audio
mh record status
mh record stop
mh record ls
mh record rm <file.mp4>
```

## Record a remote screen

:::steps
1. Open the machine's screen as usual, with **View screen**.
2. In the session toolbar, open **Record this screen**. Tick **Include what the computer plays** if you want its sound, then press **Start recording**.
3. If someone at the machine approved this session, they are asked again for the recording. Your toolbar reads "Waiting for the person at the device to allow it…" until they answer.
4. Before the first frame is written, the machine shows a banner saying it is being recorded, with **Stop recording**, and its tray icon turns red.
5. Your toolbar shows the running time with **Stop**. When the recording ends it appears under **Your recordings on this device**, ready to download.
:::

:::warning Off until the machine's owner allows it
Two switches decide whether a session can record, and both start off.

- **On the machine:** meshharbor-desktop → **Recordings** → **Recording by a remote controller** → **Allow remote recording**, plus **Include computer audio** if remote recordings may carry its sound. Only someone at that machine can change these; the server cannot turn them on.
- **In the organization:** you can always record a device you own, and the organization's owner can record any device. Anyone else needs the **Record remote screens** permission on one of their roles ([users, roles and permissions](/docs/security/users-roles-permissions/)).

Until both allow it, the Record control is greyed out and its tooltip says why.
:::

The machine's microphone is never recorded remotely.

### Downloading a recording

- **Download** saves into a file you pick with the browser's save dialog or,
  where the browser has none, into memory, up to 2 GiB.
- A download held in memory is checked against the machine's SHA-256 and kept
  only if it matches. A download saved straight to a file shows the machine's
  SHA-256, so you can compare.
- If the session drops mid-download, the download pauses, and your next session
  continues it from where it stopped.
- Only the person who made a recording can list it or download it.

### When the session drops, or someone stops it

- If your session drops, the recording keeps running for a minute. Reconnect in
  that minute and your toolbar reads **REC · reconnecting**, then picks it back
  up. After a minute without you, it stops.
- **Disconnect** stops your recording first.
- The person at the machine can stop it at any time, and switching **Allow
  remote recording** off stops it too.
- Recording needs someone signed in at the machine. A sign-in screen is
  refused, and a Windows machine with nobody signed in never records. The one
  exception is a Linux machine with no screen at all: its service records
  into a folder of its own, and the viewer tells you so.

## Where recordings are saved

| | Default folder | If that one cannot be used |
|---|---|---|
| **Windows** | `Videos\MeshHarbor`, when Videos is local and not under OneDrive | `MeshHarbor Recordings` in your user folder |
| **macOS** | `~/Movies/MeshHarbor` | `~/MeshHarbor Recordings` |
| **Linux** | `MeshHarbor` in your Videos folder | `~/MeshHarbor Recordings` |

The **Recordings** view shows the folder in use, and says why when it is not the
usual one. **Change folder…** picks another, **Use the default folder** goes
back, and **Open folder** shows it in your file manager.

:::tip Why not OneDrive
A Videos folder under OneDrive is passed over on purpose: OneDrive would upload
every recording, gigabytes at a time.
:::

## Cut, speed up and add music

In **Recordings**, press **Edit** on a recording.

- **Split at the playhead** to cut the timeline into pieces, then mark each
  piece **Keep**, **Cut** or **Speed up** (×1.25 up to ×16).
- **Sound:** the recording's own sound, muted wherever a piece is sped up, and
  **Add music…** (MP3, M4A/AAC, FLAC, Ogg or WAV) with its volume, start, fade
  in, fade out and loop.
- **Export** writes a new file next to the original, named
  `<recording> (edited).mp4`. The original is never changed, and your edits are
  saved as you go, so you can close the editor and come back to them.

## When something goes wrong

- A crash or an update in the middle of a recording costs only the last few
  seconds. The next recording turns what was left into a playable file, marked
  as interrupted.
- Every refusal says why, in one sentence, in the viewer and in meshharbor-desktop.

## Limits

- **macOS** records the picture only for now: no microphone and no computer
  audio.
- Recording arrived with agent **0.4.110**. A machine on an older agent shows no
  Record control.
- This page is about screens. MeshHarbor does not record video calls.
