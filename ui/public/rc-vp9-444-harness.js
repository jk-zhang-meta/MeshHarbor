// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
// Extracted from an inline <script> in rc-vp9-444-harness.html.
//
// The app's own CSP is `script-src 'self' https://purestat.ai` (see
// files/nginx-pod.conf), which forbids inline script — so as an inline block
// this NEVER RAN against a built image. The page loaded, the harness globals
// were never defined, and e2e/rc-vp9-444.spec.ts timed out on "harness never
// reached done/error" while scripts/e2e-expected-failures.txt blamed a
// missing agent. Same origin + external file satisfies 'self'.
//
// ⚠️ Keep this OUT of the HTML. A future inline convenience re-breaks it
// silently: the only symptom is a console CSP line nobody reads.

  // Vite serves TS sources directly in dev, so importing the production
  // worker keeps the harness tied to whatever the app actually ships.
  const WORKER_URL = '/src/workers/rc-vp9-444-worker.ts'

  const statusEl = document.getElementById('status')
  const logEl = document.getElementById('log')
  const canvasEl = document.getElementById('paint')
  // Globals the Playwright spec polls / asserts on. Setting them on
  // window because page.evaluate() reads from there.
  /** @type {{
   *    state: 'idle' | 'running' | 'done' | 'error',
   *    framesEncoded: number,
   *    framesSent: number,
   *    framesDecoded: number,
   *    firstFrame: { width: number, height: number } | null,
   *    decoderConfigured: boolean,
   *    error: string | null,
   *    log: string[],
   *  }} */
  const result = {
    state: 'idle',
    framesEncoded: 0,
    framesSent: 0,
    framesDecoded: 0,
    firstFrame: null,
    decoderConfigured: false,
    error: null,
    log: [],
  }
  // Make readable by Playwright via page.evaluate().
  window.__rcVp9_444Harness = result

  function log(line, cls = 'info') {
    result.log.push(line)
    const span = document.createElement('span')
    span.className = cls
    span.textContent = line + '\n'
    logEl.appendChild(span)
  }
  function setStatus(line, cls = 'info') {
    statusEl.textContent = line
    statusEl.className = cls
    log(line, cls)
  }
  function fail(err) {
    const msg = err && err.message ? err.message : String(err)
    result.state = 'error'
    result.error = msg
    setStatus('ERROR: ' + msg, 'err')
  }

  // ---- Wire-format helpers (must match agents/meshharbord/src/encode/libvpx.rs) ----
  const HEADER_BYTES = 13
  const FLAG_KEYFRAME = 0x01
  function buildFrame(payload, isKey, timestampUs) {
    const out = new Uint8Array(HEADER_BYTES + payload.byteLength)
    const dv = new DataView(out.buffer, 0, HEADER_BYTES)
    dv.setUint32(0, payload.byteLength, true /* little-endian */)
    dv.setUint8(4, isKey ? FLAG_KEYFRAME : 0)
    const ts = BigInt(timestampUs)
    dv.setUint32(5, Number(ts & 0xFFFFFFFFn), true)
    dv.setUint32(9, Number((ts >> 32n) & 0xFFFFFFFFn), true)
    out.set(new Uint8Array(payload.buffer ? payload.buffer : payload, payload.byteOffset || 0, payload.byteLength), HEADER_BYTES)
    return out
  }

  // ---- Synthetic frame producer ----
  // Draws a moving stripe so each VP9 frame differs and the encoder
  // doesn't elide them entirely. 64×36 keeps the bitstream tiny so
  // the test runs in < 5 s even on a CPU-bound CI runner.
  const PRODUCER_W = 64
  const PRODUCER_H = 36
  const TOTAL_FRAMES = 12
  function makeFrame(i) {
    const off = new OffscreenCanvas(PRODUCER_W, PRODUCER_H)
    const ctx = off.getContext('2d')
    ctx.fillStyle = '#000'
    ctx.fillRect(0, 0, PRODUCER_W, PRODUCER_H)
    ctx.fillStyle = '#fff'
    const x = (i * 5) % PRODUCER_W
    ctx.fillRect(x, 0, 6, PRODUCER_H)
    ctx.fillStyle = '#0f0'
    ctx.fillRect(0, (i * 3) % PRODUCER_H, PRODUCER_W, 4)
    return new VideoFrame(off, { timestamp: i * 33333 })
  }

  // ---- Main ----
  async function run() {
    if (result.state !== 'idle') return
    result.state = 'running'
    setStatus('feature-checking…')

    // Decoder support is a prereq for the consumer side. Encoder
    // support is a prereq for the producer side. Production targets
    // VP9 profile 1 (4:4:4) — the WHOLE point of Phase Y — but
    // current Chromium WebCodecs lacks a profile-1 *encoder* (decoder
    // works fine). For the e2e mechanics (wire format + DC + worker
    // assembler + decoder lifecycle) we fall through to profile 0
    // (4:2:0) so the test can produce frames with `VideoEncoder`. The
    // PRODUCTION pipeline never needs a browser encoder — the agent
    // is the only encoder; the browser only decodes — so this
    // fallback doesn't loosen real-world coverage.
    if (typeof VideoDecoder !== 'function' || typeof VideoEncoder !== 'function') {
      return fail(new Error('WebCodecs VideoDecoder/VideoEncoder unavailable'))
    }
    const candidateCodecs = ['vp09.01.10.08', 'vp09.00.10.08']
    let encodableCodec = null
    for (const codec of candidateCodecs) {
      const decSupp = await VideoDecoder.isConfigSupported({ codec })
      if (!decSupp.supported) continue
      const encSupp = await VideoEncoder.isConfigSupported({
        codec, width: PRODUCER_W, height: PRODUCER_H, bitrate: 200_000, framerate: 30,
      })
      if (encSupp.supported) { encodableCodec = codec; break }
    }
    if (!encodableCodec) return fail(new Error('no VP9 codec round-trips encode+decode in this Chromium'))
    result.codec = encodableCodec
    log('codec selected: ' + encodableCodec, 'ok')

    // Spin up the production worker so the e2e covers the actual
    // module path that ships in production.
    // ⚠️ WORKER_URL is a Vite DEV path. Against a built image nginx's SPA
    // fallback answers it with index.html and HTTP **200** — so `new Worker`
    // gets HTML where it expects a module and dies with a parse error that
    // names neither the URL nor the cause. Say so instead.
    const probe = await fetch(WORKER_URL, { method: 'GET' })
    const ctype = probe.headers.get('content-type') || ''
    if (!/javascript|typescript/i.test(ctype)) {
      throw new Error(
        `worker source is not being served as script: GET ${WORKER_URL} -> ` +
        `${probe.status} ${ctype || '(no content-type)'}. This harness loads the ` +
        `worker from the Vite DEV path, so it only runs against \`bun run dev\`; ` +
        `a built image serves the SPA fallback here. Building the harness as a ` +
        `Vite entry (so the worker URL is hashed and real) is what would let the ` +
        `e2e suite run it.`,
      )
    }
    const worker = new Worker(WORKER_URL, { type: 'module' })
    worker.onmessage = (ev) => {
      const msg = ev.data
      if (!msg || typeof msg.type !== 'string') return
      if (msg.type === 'decoder-configured') {
        result.decoderConfigured = true
        log('decoder configured ' + msg.codec, 'ok')
      } else if (msg.type === 'first-frame') {
        result.firstFrame = { width: msg.width, height: msg.height }
        result.framesDecoded = Math.max(result.framesDecoded, 1)
        log('first-frame ' + msg.width + 'x' + msg.height, 'ok')
      } else if (msg.type === 'frame-decoded') {
        result.framesDecoded = msg.count
      } else if (msg.type === 'decoder-error' || msg.type === 'decode-error' || msg.type === 'decoder-configure-error') {
        log('worker error ' + msg.type + ': ' + msg.error, 'err')
      } else if (msg.type === 'frame-rejected') {
        log('frame-rejected ' + JSON.stringify(msg), 'err')
      }
    }
    // Hand a real OffscreenCanvas (transferred from the visible one)
    // so we exercise the paint path too — the canvas updates in the
    // page are visible feedback during interactive runs. Pass the
    // negotiated codec down so the worker's VideoDecoder configures
    // correctly (default is profile 1; e2e overrides to profile 0).
    const off = canvasEl.transferControlToOffscreen()
    worker.postMessage({ type: 'init-canvas', canvas: off, codec: encodableCodec }, [off])

    // Two PeerConnections in the same window, looped via direct SDP
    // exchange. ICE candidates resolve to host candidates only
    // (loopback) — no STUN/TURN involved.
    const pcAgent = new RTCPeerConnection()
    const pcCtrl = new RTCPeerConnection()
    pcAgent.onicecandidate = (e) => { if (e.candidate) pcCtrl.addIceCandidate(e.candidate) }
    pcCtrl.onicecandidate = (e) => { if (e.candidate) pcAgent.addIceCandidate(e.candidate) }
    // Controller opens the DC (matches the production code path); the
    // "agent" side gets it via ondatachannel.
    const dcCtrl = pcCtrl.createDataChannel('video-bytes', { ordered: true })
    dcCtrl.binaryType = 'arraybuffer'
    dcCtrl.onmessage = (ev) => {
      if (!(ev.data instanceof ArrayBuffer)) return
      try {
        worker.postMessage({ type: 'chunk', bytes: ev.data }, [ev.data])
      } catch (err) {
        log('worker post failed: ' + err.message, 'err')
      }
    }
    let dcAgent = null
    pcAgent.ondatachannel = (ev) => {
      if (ev.channel.label === 'video-bytes') {
        dcAgent = ev.channel
        dcAgent.binaryType = 'arraybuffer'
      }
    }

    // Standard offer/answer between the two local PCs.
    const offer = await pcCtrl.createOffer()
    await pcCtrl.setLocalDescription(offer)
    await pcAgent.setRemoteDescription(offer)
    const answer = await pcAgent.createAnswer()
    await pcAgent.setLocalDescription(answer)
    await pcCtrl.setRemoteDescription(answer)
    log('SDP exchanged', 'info')

    // Wait for the controller-side DC to open AND the agent-side DC
    // to be received. Bail at 5 s — Chromium's loopback typically
    // settles in < 200 ms.
    await waitFor(() => dcCtrl.readyState === 'open' && dcAgent && dcAgent.readyState === 'open', 10000, 'DC open')
    log('DC open, encoding ' + TOTAL_FRAMES + ' frames', 'info')

    // Producer: VideoEncoder for VP9 profile 1, push N frames.
    const encoder = new VideoEncoder({
      output: (chunk) => {
        result.framesEncoded++
        const buf = new ArrayBuffer(chunk.byteLength)
        chunk.copyTo(buf)
        const isKey = chunk.type === 'key'
        const wire = buildFrame(new Uint8Array(buf), isKey, chunk.timestamp || 0)
        try {
          dcAgent.send(wire)
          result.framesSent++
        } catch (err) {
          log('dcAgent.send failed: ' + err.message, 'err')
        }
      },
      error: (err) => log('encoder error: ' + (err && err.message), 'err'),
    })
    encoder.configure({
      codec: encodableCodec,
      width: PRODUCER_W,
      height: PRODUCER_H,
      bitrate: 200_000,
      framerate: 30,
      latencyMode: 'realtime',
    })
    for (let i = 0; i < TOTAL_FRAMES; i++) {
      const f = makeFrame(i)
      encoder.encode(f, { keyFrame: i === 0 })
      f.close()
    }
    await encoder.flush()
    encoder.close()
    log('all ' + TOTAL_FRAMES + ' frames encoded + sent', 'ok')

    // Wait for decode to catch up. SCTP latency on loopback is
    // negligible; the bound here is the worker's queue depth.
    await waitFor(() => result.framesDecoded >= TOTAL_FRAMES, 5000, 'decode-complete')
    setStatus('done — ' + result.framesDecoded + ' frames decoded', 'ok')
    result.state = 'done'

    try { worker.postMessage({ type: 'close' }) } catch {}
    try { worker.terminate() } catch {}
    try { pcAgent.close() } catch {}
    try { pcCtrl.close() } catch {}
  }

  function waitFor(predicate, timeoutMs, label) {
    return new Promise((resolve, reject) => {
      const start = performance.now()
      const tick = () => {
        if (predicate()) return resolve(undefined)
        if (performance.now() - start > timeoutMs) {
          return reject(new Error('timeout waiting for ' + label))
        }
        setTimeout(tick, 25)
      }
      tick()
    })
  }

  // Auto-start by default; tests override with ?manual=1 if they
  // want to inspect the page before the run.
  const params = new URLSearchParams(location.search)
  if (params.get('manual') !== '1') {
    run().catch(fail)
  }
  // Manual-trigger handle for tests that want to drive timing.
  window.__rcVp9_444Run = run