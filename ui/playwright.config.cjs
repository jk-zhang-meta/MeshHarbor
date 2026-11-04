// CJS twin of playwright.config.ts. Exists because bun's Node compat
// trips over Playwright's ESM preflight loader when running with a
// `.ts` config under a package.json that has `"type": "module"` — see
// `node_modules/playwright/lib/transform/transform.js:222` looking for
// the synthetic `<file>.esm.preflight` module that only real Node.js
// generates. The `.cjs` extension is unconditionally CJS regardless of
// the package "type", so Playwright takes the `require(file)` branch
// and skips the broken ESM path.
//
// Pattern lifted from gjovanov/lgr/packages/e2e — same workaround.
//
// Keep this config in sync with playwright.config.ts. The `.ts` file
// is preserved for editor / typed-config integrations; this `.cjs` is
// what `bunx playwright test` (and CI) actually load.
const { defineConfig, devices } = require('@playwright/test')

// ── bun + Windows CDP-pipe workaround ─────────────────────────────
// Force Playwright to use the WebSocket CDP transport instead of the
// default `--remote-debugging-pipe` transport. Bun's Node compat
// layer doesn't forward the extra stdio file descriptors (3 + 4)
// the pipe transport needs, so the launch hangs at the CDP
// handshake until timeout. Real Node.js handles fd-3+ correctly;
// bun does not (as of 1.3.x). Removable once bun fixes fd
// forwarding.
//
// Two patches are needed:
//   1. `Chromium.prototype.defaultArgs` — swap
//      `--remote-debugging-pipe` for `--remote-debugging-port=0` so
//      Chrome exposes CDP over a TCP port and prints
//      `DevTools listening on ws://...` to stderr (which Playwright's
//      `waitForReadyState` reads).
//   2. `BrowserType.prototype.supportsPipeTransport` — return
//      `false` so the post-launch transport selection (in
//      `browserType.js:260`) takes the WebSocket branch instead of
//      the pipe branch (which would try to read fds 3+4).
//
// Done at config-load time (not via globalSetup) because Playwright
// re-loads the config in every worker process; globalSetup runs ONCE
// in the runner, which is too late.
try {
  const path = require('path')
  const pwRoot = path.join(__dirname, 'node_modules', 'playwright-core', 'lib', 'server')

  // Patch 1: defaultArgs swap.
  const Chromium = require(path.join(pwRoot, 'chromium', 'chromium.js')).Chromium
  if (Chromium && !Chromium.prototype.__bunCdpPatched) {
    const original = Chromium.prototype.defaultArgs
    Chromium.prototype.defaultArgs = async function patched(opts, isPersistent, userDataDir) {
      const args = await original.call(this, opts, isPersistent, userDataDir)
      const idx = args.indexOf('--remote-debugging-pipe')
      if (idx >= 0) args.splice(idx, 1, '--remote-debugging-port=0')
      return args
    }
    Chromium.prototype.__bunCdpPatched = true
  }

  // Patch 2: force WebSocket transport.
  const BrowserType = require(path.join(pwRoot, 'browserType.js')).BrowserType
  if (BrowserType && !BrowserType.prototype.__bunPipeOff) {
    BrowserType.prototype.supportsPipeTransport = function () { return false }
    BrowserType.prototype.__bunPipeOff = true
  }

  // Patch 3: replace WebSocketTransport's `connect` with one that
  // uses bun's native global `WebSocket` instead of the bundled
  // `ws` module. The bundled `ws` pulls in Node's
  // `httpHappyEyeballsAgent` for the HTTP upgrade phase; bun's
  // `node:net` shim doesn't fully support that agent and the
  // upgrade hangs forever. Bun's global `WebSocket` (browser-style
  // API, backed by uWebSockets) talks to Chrome's CDP cleanly —
  // verified independently against a manually-launched headless
  // chromium.
  const transportPath = path.join(pwRoot, 'transport.js')
  const transportMod = require(transportPath)
  const WebSocketTransport = transportMod.WebSocketTransport
  if (WebSocketTransport && !WebSocketTransport.__bunPatched && typeof globalThis.WebSocket === 'function') {
    const NativeWS = globalThis.WebSocket
    WebSocketTransport.connect = async function bunConnect(progress, url, options = {}) {
      progress?.log?.(`<ws connecting> ${url}`)
      const transport = Object.create(WebSocketTransport.prototype)
      transport.headers = []
      transport.wsEndpoint = url
      transport._logUrl = url
      transport._progress = progress
      const ws = new NativeWS(url)
      transport._ws = ws
      ws.binaryType = 'arraybuffer'
      ws.onmessage = (ev) => {
        let parsed
        try { parsed = JSON.parse(typeof ev.data === 'string' ? ev.data : Buffer.from(ev.data).toString()) }
        catch { return }
        if (transport.onmessage) {
          try { transport.onmessage.call(null, parsed) } catch { /* swallow */ }
        }
      }
      ws.onclose = (ev) => {
        progress?.log?.(`<ws disconnected> ${url} code=${ev.code}`)
        if (transport.onclose) transport.onclose.call(null, ev.reason)
      }
      // Override send/close to talk to the native WS.
      transport.send = (msg) => ws.send(JSON.stringify(msg))
      transport.close = () => { try { ws.close() } catch { /* ignore */ } }
      transport.closeAndWait = async function () {
        if (ws.readyState === NativeWS.CLOSED) return
        await new Promise((res) => {
          const prev = ws.onclose
          ws.onclose = (e) => { try { prev?.(e) } catch { /* swallow */ }; res(undefined) }
          try { ws.close() } catch { /* already closed */ }
        })
      }
      await new Promise((resolve, reject) => {
        ws.onopen = () => { progress?.log?.(`<ws connected> ${url}`); resolve(undefined) }
        ws.onerror = (ev) => reject(new Error('WebSocket error: ' + (ev?.message || 'unknown')))
      })
      return transport
    }
    WebSocketTransport.__bunPatched = true
  }

  // eslint-disable-next-line no-console
  console.log('[playwright.config.cjs] CDP transport switched to WebSocket (bun fd-forwarding workaround)')
} catch (err) {
  console.warn('[playwright.config.cjs] CDP-pipe patch failed:', err && err.message)
}
// ───────────────────────────────────────────────────────────────────

module.exports = defineConfig({
  testDir: './e2e',
  // testIgnore is the only reliable way to exclude SPEC FILES from
  // discovery — `--grep-invert` only matches test NAMES (the
  // describe-then-it title), so file-path regexes there silently
  // match nothing. Two ignore sets:
  //   - Always: `**/video/**` (record-intro.spec.ts is a demo
  //     mp4-producer, not a regression test; uses ESM import-
  //     attribute syntax that Playwright's CJS transformer trips on
  //     inside the e2e Job's bun runtime)
  //   - When `E2E_SKIP_PHASE_3=1` (set by the e2e Job manifest in
  //     first-cut mode): the specs that need infra not yet in
  //     cluster — oauth (no provider stubs), conference-multi +
  //     rc-vp9-444 (mediasoup-in-k8s dance). Cycle 4 Chunk 1
  //     landed Mailpit + the SMTP backend so `email-flows.spec.ts`
  //     no longer needs to be skipped here.
  testIgnore: (() => {
    const always = ['**/video/**']
    if (process.env.E2E_SKIP_PHASE_3 === '1') {
      always.push(
        '**/oauth.spec.ts',
        '**/conference.spec.ts',
        '**/conference-chat.spec.ts',
        '**/conference-multi.spec.ts',
        '**/rc-vp9-444.spec.ts',
      )
    }
    return always
  })(),
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: 'html',
  use: {
    baseURL: process.env.E2E_BASE_URL || 'http://localhost:5000',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // Force full Chromium rather than the default chrome-headless-shell
        // — the headless-shell variant doesn't ship VP9 4:4:4 decoder in
        // some builds; the full Chromium has WebCodecs + VideoEncoder in
        // feature-complete form.
        channel: 'chromium',
        // `PWHEAD=1` flips to headed mode for interactive debugging.
        headless: process.env.PWHEAD !== '1',
        launchOptions: {
          args: [
            '--use-fake-device-for-media-stream',
            '--use-fake-ui-for-media-stream',
            // Tell Playwright's `waitForReadyState` (in chromium.js)
            // to actually parse the `DevTools listening on ws://…`
            // line — that wait is gated on user args containing
            // `--remote-debugging-port` OR `options.cdpPort` being
            // set, neither of which we have otherwise. The
            // `defaultArgs` patch above also swaps the pipe flag for
            // a port flag in the final args list, so Chrome itself
            // gets the right transport.
            '--remote-debugging-port=0',
            // Disable Chromium feature gates that intermittently fire
            // `net::ERR_ACCESS_DENIED` against `http://meshharbor2/...`
            // from inside the e2e cluster:
            //   - BlockInsecurePrivateNetworkRequests / InsecurePrivate
            //     NetworkSubresources: Chrome's CORS-RFC1918 gate; a
            //     page on `meshharbor2` (cluster-private IP) loading
            //     subresources from the same private IP can be blocked
            //     post-redirect once the navigation crosses the
            //     "treat-as-public" heuristic threshold for any frame.
            //   - HttpsUpgrades / HttpsFirstBalancedMode: Chrome auto-
            //     upgrade HTTP→HTTPS for "known typed" hosts; once a
            //     run has hit a navigation that matches the heuristic,
            //     subsequent http navigations to the same host fail
            //     fast with ERR_ACCESS_DENIED because no HTTPS server
            //     is bound.
            //   - DnsHttpsSvcb / EncryptedClientHello: peripheral DNS
            //     features that occasionally interact badly with the
            //     bun-WebSocket CDP path.
            '--disable-features=BlockInsecurePrivateNetworkRequests,InsecurePrivateNetworkSubresources,HttpsUpgrades,HttpsFirstBalancedMode,DnsHttpsSvcb,EncryptedClientHello',
          ],
        },
      },
    },
  ],
  webServer: process.env.CI
    ? undefined
    : {
        command: 'bun run dev',
        // Vite dev server in this repo binds 5000 (see vite.config.ts);
        // the `.ts` config lists 5173 historically. Match the actual
        // bind so `reuseExistingServer` works without extra setup.
        port: 5000,
        reuseExistingServer: true,
        timeout: 30_000,
      },
})
