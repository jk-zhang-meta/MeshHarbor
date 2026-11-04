# Licensing

Roomler is open source under a **split licence**: the server you would *host* is
AGPL-3.0-only, and everything you *install on a machine* is MPL-2.0.

If you only read one paragraph: **you can self-host all of it, free, on unlimited
devices, forever, and the agent you deploy to your own or your clients' machines
carries no copyleft obligation on anything you build around it.**

---

## Answers to the questions people actually ask

### Can I self-host it for free?

**Yes.** Unlimited devices, unlimited users, no licence key, no activation, no
phone-home. The self-hosted edition is not a crippled build — it is the same code
that runs the hosted service.

We do not collect telemetry from self-hosted deployments. That is a deliberate
design property, not a current-version limitation: the product asks you to run a
privileged daemon that can see your screen, so a self-hosted install that quietly
reported home would be indefensible.

### I'm an MSP / IT provider. Can I use this to serve my clients?

**Yes, and this is the case the split exists to protect.**

The agent you deploy at a client site — `roomlerd`, the `roomler` CLI, the
desktop and setup apps — is **MPL-2.0**. MPL is a *file-level* copyleft: if you
modify one of our files, you publish that file. It imposes **nothing** on your
service, your RMM stack, your scripts, your billing system, or any proprietary
tooling you deploy alongside it.

You may:

- install the agent on as many client endpoints as you like, commercially;
- bundle it inside your own installer or management product;
- run the server internally to serve your clients' machines;
- keep every line of your own code closed.

This is the specific reason the agent is **not** AGPL. An AGPL-licensed binary on
a customer endpoint is a procurement blocker at most enterprises, and it is
exactly the friction that pushes providers toward paid proprietary alternatives.
We would rather you used ours.

### Can I modify the server for internal use?

**Yes.** The AGPL's obligation triggers on making the software available to third
parties over a network. Running a modified server for your own organisation
doesn't require you to publish anything to the world — and if you never modify it,
the AGPL asks nothing of you at all.

### Can I embed the server in my own commercial product?

Not under the AGPL, if that product is proprietary. See
[COMMERCIAL.md](COMMERCIAL.md) — an exception is available and is a normal,
uncomplicated purchase.

### Can I resell Roomler as a hosted service?

Under the AGPL, yes — provided you publish your modifications to the server under
the AGPL as well. If you want to host a proprietary fork, that needs a commercial
exception. See [COMMERCIAL.md](COMMERCIAL.md).

### I contributed before the split. What happened to my code?

Nothing was taken away. Every release up to and including the commit that
introduced this file was published under the MIT licence, and that grant is
**irrevocable**: anything published under MIT stays available under MIT forever,
including forks. The MIT text is retained verbatim in
[LICENSE-MIT](LICENSE-MIT).

The split governs the project going forward, not the past.

---

## Which licence applies to which component

The authoritative statement for any given file is its own
`SPDX-License-Identifier` header. This table is the map.

| Component | Path | Licence |
|---|---|---|
| HTTP/WS API, control plane | `crates/api` | `AGPL-3.0-only` |
| Business logic, DAOs | `crates/services` | `AGPL-3.0-only` |
| Database models and indexes | `crates/db` | `AGPL-3.0-only` |
| Server configuration | `crates/config` | `AGPL-3.0-only` |
| Server composition core (the `Module` contract, hooks, jobs) | `crates/core` | `AGPL-3.0-only` |
| Feature modules: SaaS, chat, conference, fleet, remote, network | `crates/modules/*` | `AGPL-3.0-only` |
| Regional DERP relay | `crates/derp-relay` | `AGPL-3.0-only` |
| Integration tests | `crates/tests` | `AGPL-3.0-only` |
| Web UI | `ui/` | `AGPL-3.0-only` |
| Remote-control agent (`roomlerd`) | `agents/meshharbord` | `MPL-2.0` |
| Tunnel/CLI client (`roomler`) | `agents/meshharbor-cli` | `MPL-2.0` |
| CLI shim | `agents/meshharbor-cli-shim` | `MPL-2.0` |
| Desktop companion | `agents/meshharbor-desktop` | `MPL-2.0` |
| Install wizard | `agents/meshharbor-setup` | `MPL-2.0` |
| Wizard machinery | `crates/meshharbor-setup-core` | `MPL-2.0` |
| Agent building blocks | `crates/agent-core` | `MPL-2.0` |
| Overlay/tunnel transport core | `crates/tunnel-core` | `MPL-2.0` |
| Remote-control protocol | `crates/remote_control` | `MPL-2.0` |
| LocalAPI protocol | `crates/localapi` | `MPL-2.0` |
| TURNS-over-TCP adapter | `crates/tcp-turn-conn` | `MPL-2.0` |
| Documentation | `docs/` | `CC-BY-4.0` |
| Vendored upstream forks | `crates/vendored/*` | upstream terms, unchanged |

### Why some crates are MPL even though the server links them

Four crates — `tunnel-core`, `remote_control`, `localapi`, `tcp-turn-conn` — are
compiled into **both** the server and the agent. A crate in that position must
take the more permissive of the two licences, or the agent inherits the server's
copyleft and the guarantee in the MSP answer above stops being true.

They are therefore MPL-2.0, and the AGPL-licensed server links them. That
direction is fine: MPL-2.0 §3.3 expressly allows MPL-covered files to be
distributed as part of a Larger Work under a secondary licence such as the
(A)GPL, with the MPL files remaining under the MPL.

The same rule applies to a single file: `ui/src/utils/mesh.ts` (the mesh graph's
edge rules) is bundled into the desktop companion as
`agents/meshharbor-desktop/src/front/mesh-util.js`, so it is MPL-2.0 inside the
otherwise AGPL web app (`CLIENT_FILES` in `scripts/licence-classes.sh`).

We would rather state this plainly than let someone discover it by reading the
dependency graph: **the AGPL here protects the control plane against commercial
re-hosting. It is not a claim to have locked up the transport or encoding code.**

---

## Contributing

Contributions are welcome. A PR falls under the licence of the directory it
touches — see the table above, or just read the SPDX header on the file you are
editing.

We ask contributors to sign a CLA ([docs/CLA.md](docs/CLA.md)) granting G ROX EOOD
the right to relicense contributions. This is what makes the commercial exception
in [COMMERCIAL.md](COMMERCIAL.md) possible; without it, dual licensing becomes
impossible again the moment the first external contribution lands.

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## Third-party components

Roomler ships third-party code, some of it under licences with their own
obligations — including a **written offer for LGPL relinking** covering the
statically-linked FFmpeg libraries in the Windows agent.

See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

---

## Contact

Licensing questions: **legal@roomler.ai**

G ROX EOOD · Plovdivska 110, 4400 Pazardzhik, Bulgaria · UIC 205174895 ·
VAT BG205174895. Full company details at
[roomler.ai/imprint](https://roomler.ai/imprint).

*This document explains our licensing in plain language for convenience. Where it
and a licence text disagree, the licence text governs.*
