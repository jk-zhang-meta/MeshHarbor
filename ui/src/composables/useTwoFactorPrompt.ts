// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
/**
 * FR-129 — the remote-desktop viewer's code prompt, for a device that asks for
 * a code from its authenticator app on every connection and checks it itself.
 *
 * - Asked BEFORE the request when the device reports two-factor on.
 * - Asked AGAIN when the device ends the attempt with `two_factor_required` or
 *   `two_factor_invalid`, saying why. `two_factor_locked` is not asked again:
 *   the device refuses every code for a while, so its words are the answer.
 * - The code rides the next `rc:session.request` once (the RC composable
 *   clears it on send), and the code this page last sent is never sent again:
 *   the device takes a code once, so the person waits for the next one.
 * - Backing out clears a break-glass reason waiting for the next request, so a
 *   later ordinary Connect does not carry it.
 */
import { computed, ref, watch, type Ref } from 'vue'
import i18n from '@/plugins/i18n'
import {
  asksForCode,
  asTwoFactorRefusal,
  codeForWire,
  twoFactorRefusalText,
} from '@/utils/twoFactor'

export interface TwoFactorPromptDeps {
  /** The RC composable's one-shot fields and its last ending. */
  rc: {
    twoFactorCode: Ref<string>
    overrideReason: Ref<string>
    errorCode: Ref<string | null>
  }
  /** The device reports two-factor on. */
  isOn: () => boolean
  /** False where no code can be carried (an external login). */
  enabled: boolean
  /** Start the session for real. */
  connect: () => void
}

export function useTwoFactorPrompt(deps: TwoFactorPromptDeps) {
  const open = ref(false)
  const input = ref('')
  /** Why the code is asked for again (a refusal), or null on a first ask. */
  const note = ref<string | null>(null)
  let sent = ''
  const ready = computed(() => !!codeForWire(input.value))

  function ask(why: string | null) {
    input.value = ''
    note.value = why
    open.value = true
  }

  /** Connect, asking for a code first when the device wants one. */
  function start() {
    if (deps.enabled && deps.isOn()) {
      ask(null)
      return
    }
    deps.connect()
  }

  function submit() {
    const code = codeForWire(input.value)
    if (!code) return
    if (code === sent) {
      note.value = i18n.global.t('mh.tfa.code.reused')
      input.value = ''
      return
    }
    sent = code
    deps.rc.twoFactorCode.value = code
    open.value = false
    input.value = ''
    note.value = null
    deps.connect()
  }

  function cancel() {
    open.value = false
    input.value = ''
    note.value = null
    deps.rc.overrideReason.value = ''
  }

  watch(deps.rc.errorCode, (code) => {
    const refusal = asTwoFactorRefusal(code)
    if (!refusal || !deps.enabled || !asksForCode(refusal)) return
    ask(twoFactorRefusalText(refusal))
  })

  return { open, input, note, ready, start, submit, cancel }
}
