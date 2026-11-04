---
title: Signed releases
description: Every MeshHarbor artifact is signed — Authenticode on Windows, GPG and notarisation elsewhere — and the auto-updater verifies the publisher, not just the hash.
tags: [security, signing, updates, verification, supply-chain]
order: 6
---

The agent updates itself, and it runs what it downloads **as the machine's most
privileged account** — `SYSTEM` on Windows, `root` under systemd. That makes the
update path the most security-sensitive thing in the product, and it is built
accordingly.

## What is signed

| Platform | Signature |
|---|---|
| **Windows** | Authenticode, publisher **G ROX LTD** |
| **macOS** | Developer ID signed, and notarised where the format allows |
| **All platforms** | A detached GPG signature (`.asc`) against a published release key |
| **All platforms** | SLSA build provenance, attested by the build system |

## What the updater actually checks

:::steps
1. **The signature is valid** — Authenticode on Windows; GPG against a key **pinned inside the binary** on Linux and macOS.
2. **The publisher is us** — the signer must name **G ROX LTD**.
3. **The artifact's own version matches what the release claimed.**
4. Only then does it install — and it **rolls back** if the new version crash-loops.
:::

Each of those exists because of a specific attack, and each is worth
understanding.

### Why the publisher check is not redundant

:::danger A valid signature alone proves only that *someone Windows trusts* signed it
Every commercial code-signing certificate chains to a root the operating system
trusts. An attacker with any legitimate certificate produces a file that
`WinVerifyTrust` accepts.

It is the **publisher name** that makes the signature mean "ours". Both halves
are load-bearing; either alone is not a control.
:::

### Why a checksum is not the anchor

:::danger The hash arrives from the same place as the download
The digest and the download URL are in the same manifest, from the same origin.
Anyone able to serve one can serve the other, so a checksum verifies **transfer
integrity** and proves nothing about **origin**.

Making the checksum merely mandatory would not fix this. The anchor has to be a
signature against a key published in advance — which is what the pinned key is.
:::

### Why the version binding exists

:::danger A signature alone does not stop a rollback
Without the third check, a tampered manifest could advertise a brand-new version
while pointing the download at a **genuinely signed older build** — and both the
signature and the publisher check would pass, while the fleet was downgraded
into a version with known vulnerabilities.

The fix binds the two claims: the version *inside* the signed artifact, which
cannot be edited without breaking the signature, must equal what the manifest
said.
:::

## Verifying by hand

**Windows:**

```powershell
Get-AuthenticodeSignature "C:\Program Files\MeshHarbor\meshharbord.exe" |
  Select-Object Status, @{n='Signer';e={$_.SignerCertificate.Subject}}
```

**Linux and macOS:**

```bash
gpg --verify meshharbord-<version>-x86_64-unknown-linux-gnu.deb.asc meshharbord-<version>-x86_64-unknown-linux-gnu.deb
gh attestation verify meshharbord-<version>-x86_64-unknown-linux-gnu.deb --repo jk-zhang-meta/MeshHarbor
```

## Where downloads come from

Installers and updates are served through **your server's own origin** rather
than from GitHub. That is not vanity: it means a corporate allow-list only has
to trust one hostname, which is the difference between an agent that can update
itself on a managed network and one that cannot.

## No key material in CI

Signing happens through short-lived, federated credentials rather than a stored
key. There is no signing key in the repository, in a CI secret, or on a build
machine to steal.

## A gap worth stating

:::warning The manifest itself is not yet signed as a unit
Version, URL and hash are not currently attested together. The artifact
signature plus the version binding closes the practical attacks — a tampered
manifest cannot deliver anything unsigned, nor a signed older build — but the
manifest remains the weakest link in the chain, and saying so is more useful
than implying otherwise.

The standalone tunnel CLI's own `self-update` checks the same pinned key, on
every OS, from the first tunnel release that carries the check; before it, the
CLI checked only the manifest's hash. On machines that also run the agent this
does not apply, because there the CLI is a shim with nothing of its own to update.
:::
