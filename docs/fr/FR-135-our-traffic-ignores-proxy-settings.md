# FR-135: Our traffic ignores proxy settings — only a TUN-mode VPN carries it

> **Status:** in progress — claimed 2026-11-24. Tracking issue: none (GitHub Issues are disabled on
> this repository); this spec and its registry row are the record.

## Goal (the user, 2026-11-24)

> 我希望你修改我们的流量不要被代理软件，就是 VPN 软件代理，除了 TUN 模式。

Proxy apps (Clash and the like) in "system proxy" mode set the OS proxy and `HTTP(S)_PROXY` /
`ALL_PROXY`; HTTP clients that honour them send MeshHarbor's traffic through the proxy. The centre
then sees the proxy's exit address (a wrong country, a wrong zone), latency grows, and a proxy rule
can break the control connection. A TUN-mode VPN captures packets below every application, cannot be
avoided by an application, and is accepted.

- Every native client we ship — `meshharbord`, `mh` / the shim, the desktop companion, the setup
  wizard, the updater — connects **without** any proxy: environment variables, the Windows system
  proxy (WinINET/WinHTTP), macOS system proxy and PAC are all ignored, for HTTP, WebSocket and DERP.
- One device-local opt-in, `use_system_proxy = true`, restores proxy use for a network that reaches
  the internet only through a proxy (a corporate one). It is device-owned, never pushed by the server.
- The desktop companion's web views that load our server skip the system proxy where the platform
  allows it.

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| P1 | One client-builder helper with no proxy, used by every native client; the opt-in | `use_system_proxy = true` | planned |
| P2 | Desktop web views; field check with a proxy app in system-proxy mode | — | planned |

## Acceptance criteria

- [ ] **AC1.** With `HTTPS_PROXY` / `ALL_PROXY` pointing at a dead proxy, the agent, `mh` and the
  updater still reach the server (tests).
- [ ] **AC2.** No native client builds an HTTP or WebSocket client outside the helper (a test or lint).
- [ ] **AC3.** `use_system_proxy = true` honours the proxy again (tests).
- [ ] **AC4.** On a host running a proxy app in system-proxy mode, the centre records the host's own
  address, not the proxy's (field).
- [ ] **AC5 (docs).** The networking/installation docs say it (anchors) and a row in
  [docs/README.md](../README.md).

## Field-verification log

| When (UTC) | What | Result |
|---|---|---|
