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

## Key design

- **Single native HTTP client constructor** (`crates/agent-core/src/http_client.rs:41-67`): `http_client::builder()`, `http_client::builder_with(bool)`, and `http_client::client()` call `.no_proxy()` by default (disabling `HTTP(S)_PROXY` / `ALL_PROXY`, WinINET, and macOS System Configuration). Every native crate (`agents/`, `crates/agent-core`, `crates/meshharbor-setup-core`) routes through this helper; the Hive model sidecar (`agents/meshharbord/src/hive/sidecar.rs:283-292`) is explicitly exempt (`fr-135: allowed`) because its upstream is the model provider, not the MeshHarbor centre.
- **WebSockets & DERP**: `tokio-tungstenite` (`agents/meshharbord/src/ws_connect.rs`, `agents/meshharbor-cli/src/forward.rs`) dials TCP directly and has no proxy support; verified under dead proxy env vars in `crates/agent-core/tests/fr135_no_proxy.rs`.
- **Device-local opt-in**:
  - `use_system_proxy` (`bool`, default `false`) in `AgentConfig` (`crates/agent-core/src/config.rs:1836`, `config_surface.rs:1968`, `config::try_load` at `config.rs:3817`). Structurally absent from `DesiredConfig` and locked by `the_device_owned_refusals_are_not_pushable` (`crates/remote_control/src/models.rs:10023-10068`).
  - `MESHHARBOR_USE_SYSTEM_PROXY=1` (`OPT_IN_ENV`, `http_client.rs:35`) for processes without a readable device config (tunnel-only hosts, fresh setup wizard runs, non-root companion against a root/SYSTEM config). `http_client::read_device_opt_in()` (`http_client.rs:91-106`) is called at startup in `mh` (`agents/meshharbor-cli/src/cli.rs:1105`), `meshharbor-desktop` (`agents/meshharbor-desktop/src/main.rs:59`), and `meshharbor-setup` (`agents/meshharbor-setup/src/main.rs:49`).
- **Desktop web views** (`agents/meshharbor-desktop/src/web_proxy.rs:30-76`):
  - Windows (WebView2): sets `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` with `--no-proxy-server` (preserving wry defaults and existing args) before any web view exists (`main.rs:60-61`).
  - Linux (WebKitGTK): sets `NetworkProxyMode::NoProxy` on the `WebsiteDataManager` in `setup` (`main.rs:240-242`) and on newly created account windows (`account_window.rs:130-131`).
  - macOS (WKWebView): WebKit has no "direct / ignore system proxy" API (`proxyConfigurations` only adds custom proxies on macOS 14+), so WKWebView follows the macOS system proxy (documented in `web_proxy.rs:11` and `docs/desktop-companion.md`).
- **Source guard** (`crates/agent-core/tests/fr135_proxy_guard.rs`): scans all native roots (`agents`, `crates/agent-core`, `crates/tunnel-core`, `crates/meshharbor-setup-core`, `crates/hive-node`, `crates/localapi`, `crates/tcp-turn-conn`, `crates/remote_control`) and fails on any unmarked `reqwest::Client::{new,builder,default}`, `ClientBuilder::{new,default}`, `reqwest::get`, `reqwest::blocking::`, or `use reqwest::{Client,get}`.

## Phases

| Phase | What | Kill switch | Status |
|---|---|---|---|
| P1 | One client-builder helper with no proxy, used by every native client; the opt-in | `use_system_proxy = true` / `MESHHARBOR_USE_SYSTEM_PROXY=1` | built & unit-tested |
| P2 | Desktop web views; field check with a proxy app in system-proxy mode | `use_system_proxy = true` / `MESHHARBOR_USE_SYSTEM_PROXY=1` | code & unit tests done; field check pending |
| P3 (docs) | Networking, installation, companion docs with diagrams & anchors; `docs/README.md` rows | — | done |

## Acceptance criteria

- [x] **AC1.** With `HTTPS_PROXY` / `ALL_PROXY` pointing at a dead proxy, the agent, `mh` and the
  updater still reach the server (tests: `crates/agent-core/tests/fr135_no_proxy.rs` covers HTTP +
  WebSocket against dead `127.0.0.1:9` with positive control; `fr135_proxy_guard.rs` proves all
  native clients route through the helper).
- [x] **AC2.** No native client builds an HTTP or WebSocket client outside the helper (a test or
  lint: `crates/agent-core/tests/fr135_proxy_guard.rs`, plus `tokio-tungstenite` direct-TCP check).
- [x] **AC3.** `use_system_proxy = true` honours the proxy again (tests:
  `crates/agent-core/tests/fr135_no_proxy.rs` proves both `MESHHARBOR_USE_SYSTEM_PROXY=1` and
  `use_system_proxy = true` in `config.toml` route HTTP + HTTPS `CONNECT` through a local recording
  proxy; `crates/remote_control/src/models.rs::the_device_owned_refusals_are_not_pushable` proves
  `use_system_proxy` is absent from `DesiredConfig`).
- [ ] **AC4.** On a host running a proxy app in system-proxy mode, the centre records the host's own
  address, not the proxy's (field).
- [x] **AC5 (docs).** The networking/installation docs say it (anchors in
  [overlay-communication.md](../overlay-communication.md#native-clients-ignore-proxy-settings-fr-135),
  [installation.md](../installation.md#proxy-settings-fr-135),
  [desktop-companion.md](../desktop-companion.md#proxy-settings-for-web-views-fr-135)) and rows in
  [docs/README.md](../README.md).

## Field-verification log

| When (UTC) | What | Result |
|---|---|---|
