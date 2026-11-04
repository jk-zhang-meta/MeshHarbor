# MeshHarbor vs RustDesk

RustDesk is the open-source remote-desktop project most people reach for, and
deservedly. Both are Rust, both self-hostable, both aimed at getting you onto a
machine you own without a subscription.

## What RustDesk does better

- **Maturity in remote desktop.** Years of production use and an enormous
  install base. Its viewer and codec paths have been beaten on by more people
  and more hardware than MeshHarbor's have.
- **Native clients everywhere.** Desktop viewers plus **iOS and Android**.
  MeshHarbor's viewer is a browser tab — no install, but also no native mobile app,
  and the low-latency rendering path is Chromium-first.
- **Wayland breadth.** Both capture Wayland now — MeshHarbor's landed in
  [FR-36](../fr/FR-36-wayland-capture.md) (DRM/KMS plus `uinput`, field-verified
  against a GNOME session it drives, types into, and reaches at the greeter and
  the lock screen) and [FR-45](../fr/FR-45-portal-capture.md) (the desktop
  portal, for hosts with no scanout). RustDesk still covers more compositors and
  more distro/session combinations out of the box, and its path has far more
  field hours behind it.
- **A large community**, translations, and a decade of accumulated recipes.

If your problem is "I need to see and control a remote screen", RustDesk solves
exactly that and solves it well.

## Where MeshHarbor differs

**A private network comes with it.** RustDesk gives you a screen. MeshHarbor gives
you the screen *and* a WireGuard mesh: the same machine gets a stable private
address, a DNS name, port forwards, a SOCKS5 doorway into its network, and SSH
with no `sshd`. So "let me look at that server" and "let me reach the database
behind it" are the same agent, the same enrolment and the same policy — instead
of a remote-desktop product plus a VPN product that know nothing about each
other.

**Nothing to install on the viewing side.** Any Chromium browser is the
controller. That matters more than it sounds on a locked-down machine where you
cannot install a viewer at all.

**Licensing is settled and written down.** RustDesk's server has had public
friction between its open edition and its Pro edition. MeshHarbor's split is
declared up front: the server is **AGPL-3.0**, everything installed on a machine
— agent, CLI, desktop and setup apps — is **MPL-2.0**, and CI asserts that no
AGPL crate reaches a shipped agent binary. For an MSP that means the thing you
deploy at a client site imposes nothing on your own stack. See
[`../../LICENSING.md`](../../LICENSING.md).

**Supply-chain hygiene as a shipped property.** Windows installers are
Authenticode-signed and the updater verifies both the signature *and* that the
signer is us; Linux and macOS artifacts carry GPG signatures checked against a
key pinned inside the binary; the updater refuses a downgrade by binding the
manifest's claimed version to the installer's own embedded version. For a
product that runs as SYSTEM/root and can see your screen, that is not a
formality.

**Fleet operations.** Enrolment, per-device policy, remote command execution
behind four independent default-deny gates, an audit trail per session, and a
live mesh graph — built in rather than assembled.

## Side by side

| | MeshHarbor | RustDesk |
|---|---|---|
| Remote desktop, self-hosted | yes | yes |
| Viewer | browser tab, nothing to install | native clients + mobile |
| Mobile viewer | **no** | yes |
| Wayland capture | yes ([FR-36](../fr/FR-36-wayland-capture.md) DRM/KMS + [FR-45](../fr/FR-45-portal-capture.md) portal) | yes, broader compositor coverage |
| Hardware encoding | NVENC / QSV / AMF / Media Foundation, probe-and-rollback | yes |
| Unattended / lock screen | yes — Windows SystemContext, and Linux Wayland at the greeter and lock screen (FR-36) | yes |
| WireGuard mesh between machines | **yes** | not in scope |
| Port forwards / SOCKS5 | yes | limited |
| SSH without `sshd` | yes | not in scope |
| Chat / video conferencing | included | not in scope |
| Licence | AGPL server + MPL agent, split declared | AGPL, with a separate Pro edition |
| Signed + provenance-attested releases | yes, verified by the updater | varies |

## Choosing

- **Use RustDesk** if you need mobile, native viewers, broader Wayland compositor
  coverage, or the safety of the more battle-tested option for remote desktop
  specifically.
- **Use MeshHarbor** if the machines you want to reach are also machines you want on
  a private network — or if you want one agent, one policy model and one audit
  trail instead of two products.
- **They coexist.** Nothing stops you running RustDesk over a MeshHarbor mesh; the
  overlay is just a network.

---

*Re-checked 2026-09-02 against MeshHarbor's own source and RustDesk's public
documentation and release notes. The Wayland row was **wrong in our own
disfavour** until this pass — it still conceded a gap FR-36 had closed and
field-verified on 2026-08-30. If anything here is wrong or has aged,
[open an issue](https://github.com/jk-zhang-meta/MeshHarbor/issues) — we would rather
fix it than win on a stale fact.*
