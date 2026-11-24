// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-99 P1c — the viewer's side of privacy mode, over the session's
 * `privacy` DataChannel (`docs/fr/FR-99-privacy-mode.md` §3c).
 *
 * The curtain is drawn ON THE DEVICE, by the device, after its own gates
 * (the owner's switch, a curtain being possible there, the overlay keeping it
 * out of capture). This asks for it, follows it, and says why when the answer
 * is no — including the times the device takes it down unasked (the owner
 * switched privacy mode off).
 *
 * Channel-agnostic on purpose, like `useRemoteRecording`: `attach` takes any
 * `RTCDataChannel`-shaped object, so the unit tests drive the real protocol
 * code with no PeerConnection.
 */
import { ref } from 'vue'
import i18n from '@/plugins/i18n'

/** The part of an `RTCDataChannel` this uses. */
export interface PrivacyChannel {
  readyState: string
  send(data: string): void
  onmessage: ((ev: { data: unknown }) => void) | null
  onopen: (() => void) | null
  onclose: (() => void) | null
}

/**
 * One sentence per code: the server's strip reasons (`privacy_grant`, P1a)
 * and the device's refusals (`privacy.rs`, P1b). A code this build has never
 * heard of reads as itself.
 */
export const PRIVACY_REASONS: Record<string, string> = {
  // the server
  device_cannot_curtain: "this device can't cover its screen",
  break_glass: 'privacy mode is never available when consent was skipped',
  outside_the_org: "privacy mode is never available from outside the device's organization",
  device_not_opted_in: "this device's owner hasn't allowed privacy mode",
  // the device
  not_granted: "this session isn't allowed to cover the screen",
  disabled_on_device: "this device's owner hasn't allowed privacy mode",
  unavailable: "this device can't cover its screen right now",
  no_curtain: "the device couldn't put the privacy screen up",
  session_ended: 'the session ended',
}

export function describePrivacyReason(code: string | null | undefined): string {
  if (!code) return ''
  // FR-131 P3 — in the reader's language; the table above is the English.
  return code in PRIVACY_REASONS ? i18n.global.t(`remote.viewer.privacy.reason.${code}`) : code
}

/**
 * Does the session's EFFECTIVE grant (`rc:session.created`'s `permissions`)
 * hold PRIVACY? Never assumed: absent means no. Matched by equality, never as
 * a prefix.
 */
export function grantHoldsPrivacy(permissions: unknown): boolean {
  return (
    typeof permissions === 'string' &&
    permissions.split('|').some((p) => p.trim() === 'PRIVACY')
  )
}

/**
 * Does the device SERVE privacy mode — its owner allowed it — by its caps'
 * `rpc` words? Equality: `privacy-available` (a curtain is possible, the
 * owner has not allowed it) is a different promise and earns no request.
 */
export function deviceServesPrivacy(caps: unknown): boolean {
  const rpc = (caps as { rpc?: unknown } | null | undefined)?.rpc
  return Array.isArray(rpc) && rpc.some((w) => w === 'privacy-mode')
}

/**
 * The permissions a session request asks for: `PRIVACY` is added only when
 * the device serves it. Not "always asked for" like RECORD, for two reasons:
 * a granted PRIVACY puts a "may cover this screen" line on the person's
 * consent prompt, which a device whose owner never allowed it must not show;
 * and a server older than FR-99 P1a cannot parse the name at all.
 */
export function withPrivacyAsked(permissions: string, caps: unknown): string {
  if (!deviceServesPrivacy(caps) || grantHoldsPrivacy(permissions)) return permissions
  return `${permissions} | PRIVACY`
}

/**
 * Whether the toolbar shows a disabled privacy control for the server's strip
 * reason. Not for `device_cannot_curtain`: a device that can never cover its
 * screen (macOS, Linux, an agent before FR-99) has nothing to allow or refuse,
 * and a control there would explain, on every session, a feature nobody could
 * switch on.
 */
export function showsPrivacyRefusal(code: string | null | undefined): boolean {
  return !!code && code !== 'device_cannot_curtain'
}

/**
 * Open the session's `privacy` channel from its grant: once per
 * PeerConnection, and only on a grant that holds PRIVACY (the device answers
 * a channel without it `not_granted`). Called from `rc:session.created`, for
 * the reason `openRecordChannel` is.
 */
export function openPrivacyChannel(
  pc: Pick<RTCPeerConnection, 'createDataChannel'> | null,
  channels: Record<string, RTCDataChannel>,
  permissions: unknown,
): RTCDataChannel | null {
  if (!pc || channels.privacy || !grantHoldsPrivacy(permissions)) return null
  channels.privacy = pc.createDataChannel('privacy', { ordered: true })
  return channels.privacy
}

export function usePrivacyMode() {
  /** Is the curtain up for this session, by the device's last word? */
  const on = ref(false)
  /** A request is out and unanswered. */
  const pending = ref(false)
  /** Why the last request was refused, or why the curtain came down when
   *  nobody here asked; `null` when it did what was asked. */
  const reason = ref<string | null>(null)
  /** The channel is open: the control can act. */
  const ready = ref(false)
  /** FR-99 P4 — while the curtain is up: are the device's speakers muted?
   *  `false` when muting failed; `null` when the device did not say (the
   *  curtain is down, it has no speakers, or it predates P4). */
  const hostMuted = ref<boolean | null>(null)

  let channel: PrivacyChannel | null = null
  let seq = 0
  const newId = () => `pv-${Date.now().toString(36)}-${(seq++).toString(36)}`

  function send(v: Record<string, unknown>): boolean {
    if (!channel || channel.readyState !== 'open') return false
    try {
      channel.send(JSON.stringify(v))
      return true
    } catch {
      return false
    }
  }

  function onString(text: string) {
    let m: Record<string, unknown>
    try {
      m = JSON.parse(text)
    } catch {
      return
    }
    if (m.t !== 'rc:privacy.state') return
    on.value = m.on === true
    reason.value = typeof m.reason === 'string' ? m.reason : null
    hostMuted.value = on.value && typeof m.host_muted === 'boolean' ? m.host_muted : null
    pending.value = false
  }

  function attach(ch: PrivacyChannel) {
    channel = ch
    ready.value = ch.readyState === 'open'
    ch.onmessage = (ev) => {
      if (typeof ev.data === 'string') onString(ev.data)
    }
    ch.onopen = () => {
      ready.value = true
      send({ t: 'rc:privacy.status', id: newId() })
    }
    ch.onclose = () => {
      if (channel === ch) channel = null
      ready.value = false
      pending.value = false
      hostMuted.value = null
      // The device takes the curtain down when the session ends.
      if (on.value) {
        on.value = false
        reason.value = 'session_ended'
      }
    }
  }

  function detach() {
    if (channel) {
      channel.onmessage = null
      channel.onopen = null
      channel.onclose = null
    }
    channel = null
    ready.value = false
    pending.value = false
    on.value = false
    hostMuted.value = null
  }

  /** Cover the screen (`true`) or uncover it. The device answers either way. */
  function set(want: boolean) {
    reason.value = null
    if (!send({ t: 'rc:privacy.set', id: newId(), on: want })) {
      pending.value = false
      reason.value = 'session_ended'
      return
    }
    pending.value = true
  }

  return { on, pending, reason, ready, hostMuted, attach, detach, set }
}
