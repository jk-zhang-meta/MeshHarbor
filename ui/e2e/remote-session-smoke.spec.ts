/** Real H.264 RTP decoder smoke against an explicitly selected synthetic agent.
 * Fixed RTP settings intentionally cover this codec/render path, not the separate
 * WebCodecs/DC paths, input injection, or a human desktop. No currentTime oracle.
 */
import { test, expect, type Page } from '@playwright/test'
import { AGENT_ID, connectFixture, fixtureConfigured } from './fixtures/remote-fixture'

test.use({ headless: true, trace: 'off' })

type FrameSample = {
  key: string; framesDecoded: number; frameWidth: number; frameHeight: number
  videoWidth: number; videoHeight: number; presentedFrames: number
}

async function decodedVideo(page: Page): Promise<FrameSample[]> {
  return page.evaluate(async () => {
    const video = document.querySelector<HTMLVideoElement>('video.remote-video')
    const stream = video?.srcObject
    if (!video || !(stream instanceof MediaStream)) return []
    const trackIds = new Set(stream.getVideoTracks().map((track) => track.id))
    const pcs = (window as unknown as { __meshharborE2EPCs?: RTCPeerConnection[] })
      .__meshharborE2EPCs || []
    const samples: FrameSample[] = []
    for (const [index, pc] of pcs.entries()) {
      if (pc.connectionState === 'closed') continue
      for (const receiver of pc.getReceivers()) {
        if (!receiver.track || !trackIds.has(receiver.track.id)) continue
        const stats = await receiver.getStats()
        stats.forEach((report) => {
          if (report.type !== 'inbound-rtp' || report.kind !== 'video') return
          samples.push({
            key: `${index}:${report.id}:${receiver.track.id}`,
            framesDecoded: Number(report.framesDecoded || 0),
            frameWidth: Number(report.frameWidth || 0),
            frameHeight: Number(report.frameHeight || 0),
            videoWidth: video.videoWidth, videoHeight: video.videoHeight,
            presentedFrames: video.getVideoPlaybackQuality().totalVideoFrames,
          })
        })
      }
    }
    return samples
  })
}

test.describe('Remote session smoke against the synthetic agent-e2e harness', () => {
  test.skip(!fixtureConfigured, 'explicit fixture TENANT_ID and AGENT_ID are required')
  test.setTimeout(2 * 60 * 1000)

  test('receive positive-size decoded frames and observe sustained frame progress', async ({
    page, context,
  }, testInfo) => {
    // Test-only constructor observation; does not invent stats, expose a product
    // debug API, replace tracks, or attach to any existing browser/desktop.
    await page.addInitScript(({ agentId }) => {
      const observed: RTCPeerConnection[] = []
      ;(window as unknown as { __meshharborE2EPCs: RTCPeerConnection[] })
        .__meshharborE2EPCs = observed
      window.RTCPeerConnection = new Proxy(window.RTCPeerConnection, {
        construct(target, args, newTarget) {
          const pc = Reflect.construct(target, args, newTarget) as RTCPeerConnection
          observed.push(pc)
          return pc
        },
      })
      localStorage.setItem(`roomler-rc-codec.v1:${agentId}`, 'h264')
      localStorage.setItem('roomler-rc-h264-rtp', '1')
      localStorage.setItem('roomler-rc-render-path', 'video')
      localStorage.setItem('roomler-rc-video-transport.v2', 'webrtc')
    }, { agentId: AGENT_ID })
    await connectFixture(page, context)
    const video = page.locator('video.remote-video')
    await expect(video).toBeVisible({ timeout: 30_000 })
    let initial: FrameSample | undefined
    await expect.poll(async () => {
      initial = (await decodedVideo(page)).find((sample) =>
        sample.framesDecoded > 0 && sample.frameWidth > 0 && sample.frameHeight > 0 &&
        sample.videoWidth > 0 && sample.videoHeight > 0 && sample.presentedFrames > 0,
      )
      return Boolean(initial)
    }, { timeout: 30_000, message: 'no real inbound video decoded/presented at positive dimensions' })
      .toBe(true)
    const first = initial!
    let final: FrameSample | undefined
    await expect.poll(async () => {
      final = (await decodedVideo(page)).find((sample) => sample.key === first.key)
      return Boolean(final && final.framesDecoded >= first.framesDecoded + 5 &&
        final.presentedFrames >= first.presentedFrames + 5 && final.frameWidth > 0 &&
        final.frameHeight > 0 && final.videoWidth > 0 && final.videoHeight > 0)
    }, { timeout: 20_000, message: 'same remote track decoder/presentation failed to advance five frames' })
      .toBe(true)
    await testInfo.attach('decoded-frame-progress', {
      body: JSON.stringify({ initial: first, final }), contentType: 'application/json',
    })
  })
})
