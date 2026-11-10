# MeshHarbor vs TeamViewer (and AnyDesk)

TeamViewer defined this category. If you support other people's machines for a
living, it is probably what you or your clients already use — and what you
already resent paying for.

## What TeamViewer does better

- **Reach.** Windows, macOS, Linux, ChromeOS, iOS, Android, and *attended
  support for mobile devices* — including screen sharing from a phone you do not
  administer. MeshHarbor has no mobile agent at all.
- **The support workflow.** Ad-hoc session codes for a stranger's machine, a
  service desk, queues, session hand-off, ticketing integrations. MeshHarbor's model
  is enrolment: someone installs an agent once. That is right for machines you
  own and wrong for one-off help for a member of the public.
- **Enterprise surface.** Compliance certifications, conditional access, mass
  deployment tooling, reporting, session recording as a managed feature, and a
  support contract with a company that will answer the phone.
- **Twenty years of edge cases** in getting a picture out of a machine on a bad
  network.

If you need attended support for arbitrary machines and phones, with a vendor
behind it, TeamViewer is the answer and this page is not going to change that.

## Where MeshHarbor differs

**No commercial-use detection.** The single most common complaint about the free
tier is being flagged as commercial and locked out mid-session, often
incorrectly. MeshHarbor has no heuristic that watches how you use it, because the
plans are counted by devices rather than policed by suspicion — and if you
self-host, there is no counting at all.

**Price shape.** MeshHarbor is $8 per user a month (Pro, 1,000 devices) and $16
(Business, 5,000), and free for 10 users and 100 devices with commercial use
allowed. Remote support
suites are typically priced per concurrent seat with device tiers layered on
top. Compare against your own quote
rather than a number on a page — but for a small IT shop the difference is
usually an order of magnitude.

**You can host the whole thing.** Not a "private cloud" SKU: the same code, on
your hardware, unlimited devices, no licence key, no activation, and no
telemetry from self-hosted deployments. See [`../self-hosting.md`](../self-hosting.md).

**The server never sees the session.** Pixels, keystrokes, clipboard and files
travel peer-to-peer, end-to-end encrypted; the coordinator introduces the two
ends and enforces policy. When no direct path can be punched, relays forward
ciphertext they cannot read.

**It is also a private network.** The same agent puts the machine on a WireGuard
mesh with a stable address and name, gives you port forwards and a SOCKS5
doorway into its network, and an SSH server that binds no port. For an MSP,
"remote into the client's PC" and "reach the client's NAS from my laptop" become
one tool.

**Open source, and the agent's licence is chosen for MSPs.** The agent you
deploy at a client site is MPL-2.0 — file-level copyleft that imposes nothing on
your RMM, scripts, billing or bundling. See [`../../LICENSING.md`](../../LICENSING.md)
and [`../../COMMERCIAL.md`](../../COMMERCIAL.md).

## Side by side

| | MeshHarbor | TeamViewer / AnyDesk |
|---|---|---|
| Attended support for a stranger's PC | **limited** — only your own already-enrolled devices, by a time-limited code the device owner approves (FR-52) | yes, session codes, nothing pre-installed |
| Mobile device support | **no** | yes |
| Unattended access to your own machines | yes | yes |
| Viewer | browser tab, nothing to install | native client |
| Commercial-use detection on free tier | **none** | yes |
| Self-host the whole product | yes, unlimited devices | no |
| End-to-end encrypted, server sees nothing | yes | yes (vendor-operated) |
| Private mesh network between machines | **yes** | no |
| Port forwarding / SOCKS5 / SSH | **yes** | limited |
| Source available | yes | no |
| Vendor support contract | **no** | yes |
| Compliance certifications | **no** | yes |

## Choosing

- **Stay with TeamViewer** for attended support of a device with nothing
  MeshHarbor installed on it — a customer's laptop, a one-off repair, a phone —
  or where procurement requires certifications and a support contract.
  **Use MeshHarbor's connect codes** once the device is already enrolled in
  someone's fleet: its owner opens that one device for a limited window,
  approves the specific request by name ("outside your organization"), and
  the access is scoped (view + input, never files) and fully audited.
- **Use MeshHarbor** for a fleet you enrol once — your own machines, or clients on a
  managed agreement — especially if you would also like those machines on a
  private network, and especially if you want the option to host it yourself.
- **The migration question worth asking** is not "is it as good", it is "how much
  of what I pay for is attended support of unmanaged devices?" If the answer is
  "almost none", the comparison changes shape.

---

*Checked 2026-08-29 against MeshHarbor's own source and public vendor
documentation; MeshHarbor's own prices updated 2026-10-20 (FR-115); the attended-
support row updated 2026-10-20 after FR-52's connect codes were field-verified
end to end. Pricing and
packaging change often, so verify against your own quote. If anything here is wrong or has aged,
[open an issue](https://github.com/jk-zhang-meta/MeshHarbor/issues) — we would rather
fix it than win on a stale fact.*
