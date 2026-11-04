# MeshHarbor vs StarDesk

StarDesk Remote, from GearUP, is a remote desktop built for gaming: play your PC's games from a phone, or
reach your desktop from anywhere, with native apps on Windows, macOS, iOS and Android. It is free. MeshHarbor
is a different shape of product, a browser-based remote desktop and a private network on one agent. Some
of StarDesk's choices are ones we are studying closely.

Everything said about StarDesk here comes from StarDesk's own website and help center. Following
[rule 3](README.md#our-rules-for-these-pages), we publish no measurements of it.

## What StarDesk does better

- **Frame rate and picture.** StarDesk advertises up to 4K at 144 fps with HDR, and a frame-rate lock of
  60, 120 or 144. MeshHarbor targets 60 fps (30 on relayed paths) and streams SDR: an HDR desktop is
  tone-mapped down.
- **Native controllers.** Its controller apps own the pointer and the screen. That gives it mouse modes
  that switch to relative movement for games and 3D applications, game-controller support, and on phones
  more than 200 touch key-mapping presets plus macro keys. MeshHarbor's controller is a browser tab: absolute
  mouse, an on-screen keyboard on phones, no gamepad.
- **Privacy at the host.** A privacy mode blacks out the host's own display, a host-mute switch silences
  its speakers, and the PC can lock itself when the session ends. MeshHarbor has none of these yet.
- **The screen follows the client.** StarDesk can change the host's resolution to match the client's, and
  falls back to a virtual "Universal Screen" when no real mode fits. MeshHarbor can switch a Windows host to
  the closest existing mode, on request, and has no virtual display.
- **Quiet defaults.** Clipboard sync, file transfer and remote audio start **off**. In MeshHarbor, clipboard
  sync and file transfer are on whenever the session's permissions allow them.
- **Price.** Free, with no tiers and no session limits, at the time of writing.
- **Relay reach.** It advertises more than 300 relay nodes. MeshHarbor's relays are regional, and you can run
  your own.

If you want to play PC games from a phone, StarDesk is built for exactly that and MeshHarbor is not.

## Where MeshHarbor differs

**Nothing to install on the controlling side.** The viewer is a browser tab. A borrowed laptop, a locked-down
corporate machine or a kiosk can control your fleet without an install or admin rights.

**It is also a private network.** The same agent puts each machine on a WireGuard mesh with a stable address
and name, carries port forwards and a SOCKS5 doorway into its network, and runs an SSH server that binds no
port. StarDesk is a remote desktop only.

**Linux hosts.** MeshHarbor's agent runs on Windows, macOS and Linux, X11 and Wayland, including headless
servers and cluster nodes. StarDesk's hosts are Windows and macOS.

**Consent and audit for teams.** Five consent modes with a device-owned floor that the server cannot loosen,
break-glass that is audited and tells the owner, on-device recording with its own prompt, roles and
per-organization policy. Every remote session and every consent decision is recorded.

**You can host the whole thing.** The same code on your hardware, unlimited devices, no licence key. See
[`../self-hosting.md`](../self-hosting.md).

**Open source.** The server is AGPL-3.0 and everything installed on a machine is MPL-2.0. You can read what
runs as SYSTEM or root on your machines.

## Side by side

| | MeshHarbor | StarDesk |
|---|---|---|
| Controller | browser tab, nothing to install | native apps (Windows, macOS, iOS, Android) |
| Hosts | Windows, macOS, Linux (X11 and Wayland) | Windows, macOS |
| Frame rate | up to 60 fps | up to 144 fps (advertised) |
| HDR | **no** (tone-mapped to SDR) | yes (advertised) |
| 4:4:4 colour | yes, where encoder and browser both support it | yes ("True Color") |
| Relative mouse for games / 3D | **no** | yes (auto-switching mouse modes) |
| Gamepad, touch key-mapping presets | **no** | yes |
| Privacy mode, host mute, lock after session | **no** | yes |
| Clipboard, files, audio off by default | audio only | yes |
| Private mesh network, tunnels, SSH | **yes** | no |
| Self-host the whole product | yes | no |
| Source available | yes | no |
| Price | 10 users and 100 devices free, commercial use included; paid plans per user; free to self-host | free |

## Choosing

- **Use StarDesk** to play your PC games from a phone or tablet, or wherever native apps, high refresh rates
  and HDR matter more than anything else.
- **Use MeshHarbor** to reach a fleet of your own machines, including Linux servers, from any browser, with the
  machines also on a private network, and with consent, audit and self-hosting in reach.

---

*Checked 2026-10-13 against MeshHarbor's own source and StarDesk's public website and help center; MeshHarbor's own
price updated 2026-10-20 (FR-115). StarDesk is young and changes quickly. If anything here is wrong or has aged,
[open an issue](https://github.com/jk-zhang-meta/MeshHarbor/issues); we would rather fix it than win on a stale
fact.*
