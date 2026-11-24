// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-90 P3-4e-3 — the answer to a vault approval card. Under the card's text:
// where the approval stands, and Approve / Deny for a driver who may answer
// it now, Approve only where the policy would take this person's yes. The
// server's refusal is shown in its own words, and a new stamp (the vault
// edited the card) reads the approval again.
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createI18n } from 'vue-i18n'
import en from '@/locales/en.json'

const hoisted = vi.hoisted(() => ({
  apiGet: vi.fn(),
  apiPost: vi.fn(),
}))
vi.mock('@/api/client', () => ({ api: { get: hoisted.apiGet, post: hoisted.apiPost } }))

import VaultApprovalCard from '@/components/vault/VaultApprovalCard.vue'
import MessageBubble from '@/components/chat/MessageBubble.vue'

const vuetify = createVuetify({ components, directives })
const i18n = () => createI18n({ legacy: false, locale: 'en', messages: { en } })

// jsdom has no ResizeObserver, which a busy button's spinner asks for.
beforeAll(() => {
  globalThis.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver
})

const PATH = '/tenant/t1/vault/approval/a1'

function approval(over: Record<string, unknown> = {}) {
  return {
    id: 'a1',
    status: 'pending',
    expires_at: '2026-10-19T14:05:00Z',
    may_answer: true,
    may_approve: true,
    ...over,
  }
}

async function render(first: Record<string, unknown>, stamp = 's1') {
  hoisted.apiGet.mockResolvedValue(approval(first))
  const w = mount(VaultApprovalCard, {
    props: { tenantId: 't1', approvalId: 'a1', stamp },
    global: { plugins: [vuetify, i18n()] },
  })
  await flushPromises()
  return w
}

const byTestId = (w: Awaited<ReturnType<typeof render>>, id: string) => w.find(`[data-testid="${id}"]`)

/** The card's message edited: a new stamp.
 *
 *  ⚠️ `setProps`' argument is typed from the component, and where vue-tsc
 *  resolves `.vue` through `env.d.ts`'s shim — the hosted image's build runs
 *  it in `oven/bun`, which has no `node` — the shim's props are `object`.
 *  An object literal naming a REAL prop then fails the excess-property check
 *  there and nowhere else (CI and local builds type it from the SFC). The
 *  prop is real; vitest exercises it at run time. */
function restamp(w: Awaited<ReturnType<typeof render>>, stamp: string) {
  return w.setProps({ stamp } as unknown as Parameters<typeof w.setProps>[0])
}

afterEach(() => {
  vi.clearAllMocks()
})

describe('VaultApprovalCard (FR-90 P3-4e-3)', () => {
  it('lets a driver whose yes counts approve, and then shows the answer', async () => {
    const w = await render({})
    expect(hoisted.apiGet).toHaveBeenCalledWith(PATH)
    expect(byTestId(w, 'vault-approval').attributes('data-status')).toBe('pending')
    expect(byTestId(w, 'vault-approval-status').text()).toBe('Waiting for a driver')
    expect(byTestId(w, 'vault-approval-deadline').exists()).toBe(true)
    const approve = byTestId(w, 'vault-approval-approve')
    expect(approve.attributes('disabled')).toBeUndefined()
    expect(byTestId(w, 'vault-approval-why').exists()).toBe(false)

    hoisted.apiPost.mockResolvedValue(
      approval({ status: 'approved', may_answer: false, may_approve: false }),
    )
    await approve.trigger('click')
    await flushPromises()
    expect(hoisted.apiPost).toHaveBeenCalledWith(PATH, { answer: 'approve' })
    expect(byTestId(w, 'vault-approval-status').text()).toBe('Approved')
    expect(byTestId(w, 'vault-approval-approve').exists()).toBe(false)
    expect(byTestId(w, 'vault-approval-deny').exists()).toBe(false)
  })

  it('keeps Approve off where the policy would not take this yes, and Deny on', async () => {
    const w = await render({ may_approve: false })
    const approve = byTestId(w, 'vault-approval-approve')
    expect(approve.attributes('disabled')).toBeDefined()
    expect(approve.attributes('title')).toBe(en.vault.approval.notAccepted)
    // FR-120 P1b — and says so as text: a disabled button's title reaches no one.
    expect(byTestId(w, 'vault-approval-why').text()).toBe(en.vault.approval.notAccepted)
    expect(byTestId(w, 'vault-approval-deny').attributes('disabled')).toBeUndefined()

    hoisted.apiPost.mockResolvedValue(approval({ status: 'denied', may_answer: false }))
    await byTestId(w, 'vault-approval-deny').trigger('click')
    await flushPromises()
    expect(hoisted.apiPost).toHaveBeenCalledWith(PATH, { answer: 'deny' })
    expect(byTestId(w, 'vault-approval-status').text()).toBe('Denied')
  })

  it('offers nothing to answer to someone who does not drive the session', async () => {
    const w = await render({ may_answer: false, may_approve: false })
    expect(byTestId(w, 'vault-approval-status').text()).toBe('Waiting for a driver')
    expect(byTestId(w, 'vault-approval-approve').exists()).toBe(false)
    expect(byTestId(w, 'vault-approval-deny').exists()).toBe(false)
    expect(byTestId(w, 'vault-approval-why').exists()).toBe(false)
  })

  it('shows a refusal in the server’s words, and reads the approval again', async () => {
    const w = await render({})
    hoisted.apiPost.mockRejectedValue(new Error('this approval is approved already'))
    hoisted.apiGet.mockResolvedValue(approval({ status: 'approved', may_answer: false }))
    await byTestId(w, 'vault-approval-approve').trigger('click')
    await flushPromises()
    expect(byTestId(w, 'vault-approval-refused').text()).toContain('this approval is approved already')
    expect(hoisted.apiGet).toHaveBeenCalledTimes(2)
    expect(byTestId(w, 'vault-approval-status').text()).toBe('Approved')
  })

  it('reads the approval again when the card is edited, and shows nothing it cannot read', async () => {
    const w = await render({})
    hoisted.apiGet.mockResolvedValue(approval({ status: 'expired', may_answer: false }))
    await restamp(w, 's2')
    await flushPromises()
    expect(hoisted.apiGet).toHaveBeenCalledTimes(2)
    expect(byTestId(w, 'vault-approval-status').text()).toBe('Expired')
    expect(byTestId(w, 'vault-approval-deadline').exists()).toBe(false)

    hoisted.apiGet.mockRejectedValue(new Error('Resource not found'))
    await restamp(w, 's3')
    await flushPromises()
    expect(byTestId(w, 'vault-approval').exists()).toBe(false)
  })
})

describe('MessageBubble and a vault card (FR-90 P3-4e-3)', () => {
  const message = (binding?: { module: string; ref: string }) => ({
    id: 'm1',
    author_id: 's1',
    author_name: 'Claude · mars',
    content: '🔐 **Approval needed**',
    is_pinned: false,
    is_edited: false,
    is_thread_root: false,
    reaction_summary: [],
    attachments: [],
    created_at: '2026-10-19T13:55:00Z',
    updated_at: '2026-10-19T13:55:00Z',
    binding,
  })

  it('puts the answer under a message bound to the vault, and under no other', async () => {
    hoisted.apiGet.mockResolvedValue(approval())
    const card = mount(MessageBubble, {
      props: { message: message({ module: 'vault', ref: 'a1' }), tenantId: 't1' },
      global: { plugins: [vuetify, i18n()] },
    })
    await flushPromises()
    expect(card.find('[data-testid="vault-approval"]').exists()).toBe(true)
    expect(hoisted.apiGet).toHaveBeenCalledWith(PATH)

    hoisted.apiGet.mockClear()
    const stub = mount(MessageBubble, {
      props: { message: message({ module: 'hive', ref: 's1!x' }), tenantId: 't1' },
      global: { plugins: [vuetify, i18n()] },
    })
    await flushPromises()
    expect(stub.find('[data-testid="vault-approval"]').exists()).toBe(false)
    expect(hoisted.apiGet).not.toHaveBeenCalled()
  })
})
