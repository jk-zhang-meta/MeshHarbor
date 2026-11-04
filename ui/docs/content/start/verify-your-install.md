---
title: Verify your install
description: Confirm the MeshHarbor agent is running, enrolled, reachable and on the mesh — and verify the artifact you installed was really signed by us.
tags: [install, verification, security, troubleshooting, getting-started]
order: 16
---

Two different questions, both worth answering: **is it working?** and **is it
really ours?**

## Is it working?

```bash
mh status
```

A healthy machine reports its version, its organization, that its control
connection is **connected**, and — if the mesh is on — its overlay address and
name.

:::warning `connected` and `overlay OFF` on one line is a real state
An agent can be perfectly connected to the control plane while having **no mesh
at all**. That is why the two are printed together: the connection being healthy
says nothing about whether the machine has a private address.
:::

Then, from any other enrolled machine:

```bash
mh peers
```

Every peer, its address, and **how it is currently reached** — direct, or via a
relay. An organization whose mesh is off is named explicitly rather than being
omitted, so an empty-looking list is never ambiguous.

### The three device states

| State | Meaning | What to do |
|---|---|---|
| **Online** | The server holds a live socket to the agent | Nothing |
| **Stale** | Heartbeating, but no server holds its live socket | Wait ~2 minutes; it self-heals |
| **Offline** | No heartbeat at all | See [device offline](/docs/troubleshooting/device-offline/) |

## Is it really ours?

Every published artifact is signed, and the checks are worth running once so you
know what "signed" means here.

### Windows — Authenticode

```powershell
Get-AuthenticodeSignature "C:\Program Files\MeshHarbor\meshharbord.exe" |
  Select-Object Status, @{n='Signer';e={$_.SignerCertificate.Subject}}
```

`Status` must be `Valid` **and** the signer must name **G ROX LTD**.

:::danger Both halves of that check are load-bearing
A valid signature alone proves only that *someone Windows trusts* signed the
file — and every commercial code-signing certificate chains to a trusted root.
It is the **publisher name** that makes the signature mean "ours". The agent's
own updater applies exactly these two checks and refuses an update that fails
either.
:::

### Linux and macOS — GPG

Every release asset ships a detached `.asc` signature against a published
release key, plus a SHA-256 sidecar and SLSA build provenance:

```bash
gpg --verify meshharbord-<version>-x86_64-unknown-linux-gnu.deb.asc meshharbord-<version>-x86_64-unknown-linux-gnu.deb

gh attestation verify meshharbord-<version>-x86_64-unknown-linux-gnu.deb --repo jk-zhang-meta/MeshHarbor
```

The updater verifies that signature against a key **pinned inside the binary**,
and refuses fail-closed if the signature is missing or does not match.

### Why a checksum is not enough on its own

:::warning A hash from the same place as the download proves nothing
The checksum arrives in the **same manifest, from the same origin**, as the
download URL. Anyone able to serve you one can serve you the other. That is why
the trust anchor is a signature verified against a key we published in advance —
not a hash.

The updater also binds the two together: the version *inside* the signed
artifact must match the version the release claimed, so a tampered manifest
cannot point a "new" release at a genuinely-signed **older**, known-vulnerable
build.
:::

## Quick checklist

:::steps
1. `mh status` reports **connected**.
2. The device shows **Online** in the dashboard.
3. `mh peers` from another machine lists it — if you expect it on the mesh.
4. *View screen* shows the real desktop, not wallpaper. On macOS, wallpaper means [a missing privacy grant](/docs/start/install/macos/).
5. The installed binary verifies against the expected publisher.
:::
