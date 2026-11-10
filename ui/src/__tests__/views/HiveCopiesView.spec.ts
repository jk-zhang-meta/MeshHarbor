// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-90 P2h-2 — agent copies. The policy is read back; every device that
// offers itself as an archive replica, and every designated one, is listed
// once; an administrator designates one by writing the whole policy from the
// revision read, and a stale write is read again and said so; "Add an
// archive replica" mints a token and shows how to run the image with it, and
// the token goes with the dialog; a server that copies no sessions is said
// to.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { createI18n } from 'vue-i18n'
import en from '@/locales/en.json'

const hoisted = vi.hoisted(() => {
  class ApiError extends Error {
    constructor(
      public status: number,
      public data: unknown,
    ) {
      super(`API error ${status}`)
    }
  }
  return {
    ApiError,
    fetchPolicy: vi.fn(),
    putPolicy: vi.fn(),
    fetchAgents: vi.fn(),
    fetchAgent: vi.fn(),
    issueEnrollmentToken: vi.fn(),
    ensureMyMembership: vi.fn(),
    tenant: { myPermissions: (1 << 23) as number | null, isOwner: false },
  }
})
vi.mock('@/api/client', () => ({ ApiError: hoisted.ApiError }))
vi.mock('@/stores/hive', () => ({
  HIVE_ARCHIVE_CAP: 'hive-archive',
  HIVE_MAX_MEMBERS: 8,
  HIVE_MAX_RETENTION_DAYS: 3650,
  HIVE_PREFER_OWNER_DEVICES: 'owner_devices',
  useHiveStore: () => ({ fetchPolicy: hoisted.fetchPolicy, putPolicy: hoisted.putPolicy }),
}))
vi.mock('@/stores/agents', () => ({
  useAgentStore: () => ({
    agents: [
      // Offers itself, online, not designated yet.
      { id: 'd1', name: 'archive-1', is_online: true, capabilities: { rpc: ['hive', 'hive-replica', 'hive-archive'] } },
      // Designated, but its owner turned hive_archive off.
      { id: 'd2', name: 'old-archive', display_name: 'Old archive', is_online: true, capabilities: { rpc: ['hive', 'hive-replica'] } },
      // Neither: not listed. Its tags are offered as restricted tags (P2j-4).
      { id: 'd3', name: 'laptop', is_online: true, tags: ['pci', 'prod'], capabilities: { rpc: ['hive', 'hive-replica'] } },
      // `hive-archives` is not `hive-archive`: words match by equality.
      { id: 'd4', name: 'lookalike', is_online: true, capabilities: { rpc: ['hive-archives'] } },
    ],
    fetchAgents: hoisted.fetchAgents,
    fetchAgent: hoisted.fetchAgent,
    issueEnrollmentToken: hoisted.issueEnrollmentToken,
  }),
}))
vi.mock('@/stores/tenant', () => ({
  useTenantStore: () => ({ ...hoisted.tenant, ensureMyMembership: hoisted.ensureMyMembership }),
}))
vi.mock('vue-router', () => ({ useRoute: () => ({ params: { tenantId: 't1' } }) }))

import HiveCopiesView from '@/views/hive/HiveCopiesView.vue'

const vuetify = createVuetify({ components, directives })

/** The dialog inline, its content always there: Vuetify keeps a closed
 *  dialog's content mounted, so what is shown must go when it closes. */
const DialogStub = { props: ['modelValue'], template: '<div><slot /></div>' }
/** A switch is one click, its state on `data-on`. */
const SwitchStub = {
  props: ['modelValue', 'disabled', 'label'],
  emits: ['update:modelValue'],
  template: '<button :disabled="disabled" :data-on="String(modelValue)" @click="$emit(\'update:modelValue\', !modelValue)" />',
}

const rules = { min: 2, max: 4, archive: true, prefer: ['owner_devices'], restricted_tags: ['prod'] }
const policy = (archive_devices: string[], revision = 3) => ({
  replicaset: rules,
  retention_days: 90,
  archive_devices,
  revision,
  is_default: false,
})

async function render(opts: { designated?: string[] } = {}) {
  hoisted.fetchPolicy.mockResolvedValue(policy(opts.designated ?? ['d2', 'd9']))
  // `d9` is beyond the agents page: read on its own, and gone.
  hoisted.fetchAgent.mockRejectedValue(new hoisted.ApiError(404, null))
  const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
  const w = mount(HiveCopiesView, {
    global: { plugins: [vuetify, i18n], stubs: { VDialog: DialogStub, VSwitch: SwitchStub } },
  })
  await flushPromises()
  return w
}

const row = (w: Awaited<ReturnType<typeof render>>, id: string) => w.find(`[data-testid="hive-copies-device-${id}"]`)
const sw = (w: Awaited<ReturnType<typeof render>>, id: string) => w.find(`[data-testid="hive-copies-designate-${id}"]`)

// jsdom has no ResizeObserver; a button's spinner needs one.
beforeEach(() => {
  vi.stubGlobal(
    'ResizeObserver',
    class {
      observe() {}
      unobserve() {}
      disconnect() {}
    },
  )
})

afterEach(() => {
  vi.clearAllMocks()
  vi.unstubAllGlobals()
  hoisted.tenant.myPermissions = 1 << 23
  hoisted.tenant.isOwner = false
})

describe('HiveCopiesView (FR-90 P2h-2)', () => {
  it('reads the policy back and lists each device that offers itself, or is designated, once', async () => {
    const w = await render()
    expect(hoisted.fetchPolicy).toHaveBeenCalledWith('t1')
    expect(hoisted.fetchAgents).toHaveBeenCalledWith('t1')
    expect(hoisted.fetchAgent).toHaveBeenCalledWith('t1', 'd9')
    expect(w.find('[data-testid="hive-copies-policy-copies"]').text()).toContain('2 to 4 copies of each session')
    expect(w.find('[data-testid="hive-copies-policy-retention"]').text()).toContain('Kept 90 days')
    expect(w.find('[data-testid="hive-copies-policy"]').text()).toContain('tagged prod')

    // The designated first, then those that offer themselves.
    const ids = w.findAll('[data-testid^="hive-copies-device-"]').map((r) => r.attributes('data-testid'))
    expect(ids.slice(0, 2).sort()).toEqual(['hive-copies-device-d2', 'hive-copies-device-d9'])
    expect(ids.slice(2)).toEqual(['hive-copies-device-d1'])
    expect(row(w, 'd2').text()).toContain('Old archive')
    expect(row(w, 'd2').text()).toContain('Does not offer itself')
    expect(row(w, 'd9').text()).toContain('No longer a device of this organization')
    expect(row(w, 'd1').text()).toContain('Offers itself as an archive replica')
    expect(sw(w, 'd2').attributes('data-on')).toBe('true')
    expect(sw(w, 'd1').attributes('data-on')).toBe('false')
    expect(row(w, 'd3').exists()).toBe(false)
    expect(row(w, 'd4').exists()).toBe(false)
    // No designated archive replica that offers itself is online.
    expect(w.find('[data-testid="hive-copies-unreadable"]').exists()).toBe(true)
  })

  it('designates a device by writing the whole policy from the revision read', async () => {
    const w = await render()
    hoisted.putPolicy.mockResolvedValue(policy(['d2', 'd9', 'd1'], 4))
    await sw(w, 'd1').trigger('click')
    await flushPromises()
    expect(hoisted.putPolicy).toHaveBeenCalledWith('t1', {
      replicaset: rules,
      retention_days: 90,
      archive_devices: ['d2', 'd9', 'd1'],
      revision: 3,
    })
    expect(sw(w, 'd1').attributes('data-on')).toBe('true')
    // Designated, offering and online: a session is readable without its members.
    expect(w.find('[data-testid="hive-copies-unreadable"]').exists()).toBe(false)
  })

  it('stops designating one by writing the policy without it', async () => {
    const w = await render()
    hoisted.putPolicy.mockResolvedValue(policy(['d9'], 4))
    await sw(w, 'd2').trigger('click')
    await flushPromises()
    expect(hoisted.putPolicy).toHaveBeenCalledWith(
      't1',
      expect.objectContaining({ archive_devices: ['d9'], revision: 3 }),
    )
  })

  it('reads a policy changed meanwhile again, and says so', async () => {
    const w = await render()
    hoisted.putPolicy.mockRejectedValue(new hoisted.ApiError(409, null))
    hoisted.fetchPolicy.mockResolvedValue(policy(['d2', 'd9'], 7))
    await sw(w, 'd1').trigger('click')
    await flushPromises()
    expect(hoisted.fetchPolicy).toHaveBeenCalledTimes(2)
    expect(w.find('[data-testid="hive-copies-archive-error"]').text()).toContain('The policy changed since it was read')
    expect(sw(w, 'd1').attributes('data-on')).toBe('false')
  })

  it("shows any other refusal in the server's words", async () => {
    const w = await render()
    hoisted.putPolicy.mockRejectedValue(new Error('d1 is an ephemeral device, which is never an archive replica'))
    await sw(w, 'd1').trigger('click')
    await flushPromises()
    expect(w.find('[data-testid="hive-copies-archive-error"]').text()).toContain('ephemeral device')
  })

  it('gives a member who is no administrator the list, and nothing to change it with', async () => {
    hoisted.tenant.myPermissions = 0
    const w = await render()
    expect(w.find('[data-testid="hive-copies-add"]').exists()).toBe(false)
    expect(sw(w, 'd1').attributes('disabled')).toBeDefined()
    expect(sw(w, 'd2').attributes('disabled')).toBeDefined()
  })

  it('knows nothing of the caller until membership loads, and offers nothing meanwhile', async () => {
    hoisted.tenant.myPermissions = null
    const w = await render()
    expect(w.find('[data-testid="hive-copies-add"]').exists()).toBe(false)
  })

  it('adds an archive replica: a token minted, and how to run the image with it; the token goes with the dialog', async () => {
    const w = await render()
    hoisted.issueEnrollmentToken.mockResolvedValue({ enrollment_token: 'tok-123', expires_in: 600, jti: 'j1' })
    await w.find('[data-testid="hive-copies-add"]').trigger('click')
    await w.find('[data-testid="hive-copies-mint"]').trigger('click')
    await flushPromises()
    expect(hoisted.issueEnrollmentToken).toHaveBeenCalledWith('t1')
    expect(w.find('[data-testid="hive-copies-token-note"]').text()).toContain('works once, for 10 minutes')
    const docker = w.find('[data-testid="hive-copies-snippet-docker"]').text()
    expect(docker).toContain(`-e MESHHARBOR_SERVER=${window.location.origin}`)
    expect(docker).toContain('-e MESHHARBOR_ENROLL_TOKEN=tok-123')
    expect(docker).toContain('--hostname hive-archive-1')
    expect(docker).toContain('-v hive-archive:/data')
    expect(docker).toContain('ghcr.io/jk-zhang-meta/meshharbor/hive-archive:latest')
    const compose = w.find('[data-testid="hive-copies-snippet-compose"]').text()
    expect(compose).toContain('MESHHARBOR_ENROLL_TOKEN: tok-123')
    expect(compose).toContain('hostname: hive-archive-1')

    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    await w.find('[data-testid="hive-copies-copy-docker"]').trigger('click')
    await flushPromises()
    expect(writeText).toHaveBeenCalledWith(docker)
    expect(w.find('[data-testid="hive-copies-copy-docker"]').text()).toContain('Copied')

    await w.find('[data-testid="hive-copies-add-close"]').trigger('click')
    // Closed: the token is gone from the page, not just hidden.
    expect(w.find('[data-testid="hive-copies-snippet-docker"]').exists()).toBe(false)
    expect(w.find('[data-testid="hive-copies-mint"]').exists()).toBe(true)
    await w.find('[data-testid="hive-copies-add"]').trigger('click')
    expect(w.find('[data-testid="hive-copies-snippet-docker"]').exists()).toBe(false)
    expect(w.find('[data-testid="hive-copies-mint"]').exists()).toBe(true)
  })

  it('says where the server copies no sessions, and shows nothing else', async () => {
    hoisted.fetchPolicy.mockRejectedValue(new hoisted.ApiError(404, null))
    const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
    const w = mount(HiveCopiesView, {
      global: { plugins: [vuetify, i18n], stubs: { VDialog: DialogStub, VSwitch: SwitchStub } },
    })
    await flushPromises()
    expect(w.find('[data-testid="hive-copies-off"]').exists()).toBe(true)
    expect(w.find('[data-testid="hive-copies-archive"]').exists()).toBe(false)
  })
})

// FR-90 P2j-4 — the policy's rules, edited in place by an administrator: the
// whole policy written, the rules as edited and the rest as read, at the
// revision the form was opened on; a policy changed meanwhile is read again
// and shown as it is now, never written over in silence; any other refusal
// is the server's words, the draft kept.
describe("HiveCopiesView — the policy's rules (FR-90 P2j-4)", () => {
  type W = Awaited<ReturnType<typeof render>>
  const by = (w: W, id: string) => w.find(`[data-testid="hive-copies-rules-${id}"]`)
  /** An element's text, or '' where it is not shown. */
  const textOf = (w: W, id: string) => (by(w, id).exists() ? by(w, id).text() : '')
  const save = (w: W) => by(w, 'save')
  const selects = (w: W) => w.findAllComponents({ name: 'VSelect' })
  const combo = (w: W) => w.findComponent({ name: 'VCombobox' })
  async function edit(w: W) {
    await by(w, 'edit').trigger('click')
    await flushPromises()
  }

  it('writes the whole policy, the rules as edited and the rest as read, at the revision read', async () => {
    const w = await render()
    expect(by(w, 'edit').exists(), 'an administrator may edit it').toBe(true)
    await edit(w)
    expect(save(w).attributes('disabled'), 'nothing changed yet').toBeDefined()
    expect(combo(w).props('items'), "the org's device tags are offered").toEqual(['pci', 'prod'])

    await selects(w)[0].setValue(3)
    await selects(w)[1].setValue(5)
    await by(w, 'archive').trigger('click')
    await by(w, 'prefer').trigger('click')
    await combo(w).setValue(['prod', 'pci'])
    await w.find('[data-testid="hive-copies-rules-retention"] input').setValue('30')
    expect(save(w).attributes('disabled'), 'changed, and valid').toBeUndefined()

    hoisted.putPolicy.mockResolvedValue({
      ...policy(['d2', 'd9'], 4),
      replicaset: { min: 3, max: 5, archive: false, prefer: [], restricted_tags: ['prod', 'pci'] },
      retention_days: 30,
    })
    await save(w).trigger('click')
    await flushPromises()
    expect(hoisted.putPolicy).toHaveBeenCalledTimes(1)
    const [tid, body] = hoisted.putPolicy.mock.calls[0]
    expect(tid).toBe('t1')
    expect(body.revision, 'at the revision read').toBe(3)
    expect(body, 'the whole policy, the rules as edited and the rest as read').toEqual({
      replicaset: { min: 3, max: 5, archive: false, prefer: [], restricted_tags: ['prod', 'pci'] },
      retention_days: 30,
      archive_devices: ['d2', 'd9'],
      revision: 3,
    })
    expect(by(w, 'save').exists(), 'the form closes').toBe(false)
    expect(w.find('[data-testid="hive-copies-policy-copies"]').text(), 'the stored policy shown').toContain(
      '3 to 5 copies',
    )
    expect(w.find('[data-testid="hive-copies-policy-retention"]').text()).toContain('Kept 30 days')
    expect(textOf(w, 'saved'), 'said it is applied').toContain('placed again under it')
  })

  it('saves nothing the server would refuse, and nothing unchanged', async () => {
    const w = await render()
    await edit(w)
    await selects(w)[0].setValue(5)
    expect(textOf(w, 'max'), 'at most below at least').toContain('At most is fewer than at least')
    expect(save(w).attributes('disabled'), 'at most below at least: no save').toBeDefined()
    await selects(w)[1].setValue(5)
    expect(save(w).attributes('disabled'), 'at most up to it').toBeUndefined()

    const retention = w.find('[data-testid="hive-copies-rules-retention"] input')
    for (const bad of ['', '-1', '1.5', '3651', 'ten']) {
      await retention.setValue(bad)
      expect(save(w).attributes('disabled'), `${JSON.stringify(bad)} days`).toBeDefined()
      expect(textOf(w, 'retention'), `${JSON.stringify(bad)} said`).toContain('A whole number of days, from 0 to 3650')
    }
    await retention.setValue('0')
    expect(save(w).attributes('disabled'), 'for good').toBeUndefined()

    // Back to what was read: nothing to write.
    await selects(w)[0].setValue(2)
    await selects(w)[1].setValue(4)
    await retention.setValue('90')
    expect(save(w).attributes('disabled'), 'as read').toBeDefined()
    expect(hoisted.putPolicy).not.toHaveBeenCalled()
  })

  it('reads a policy changed meanwhile again, shows it as it is now, and says so', async () => {
    const w = await render()
    await edit(w)
    await selects(w)[1].setValue(6)
    hoisted.putPolicy.mockRejectedValueOnce(new hoisted.ApiError(409, null))
    hoisted.fetchPolicy.mockResolvedValue({ ...policy(['d2', 'd9'], 7), replicaset: { ...rules, min: 1, max: 2 } })
    await save(w).trigger('click')
    await flushPromises()
    expect(hoisted.fetchPolicy, 'read again').toHaveBeenCalledTimes(2)
    expect(selects(w).length, 'the form stays open').toBe(2)
    expect(textOf(w, 'error'), 'said so').toContain('It is shown as it is now: make your change again')
    expect(selects(w)[0].props('modelValue'), 'what is stored now').toBe(1)
    expect(selects(w)[1].props('modelValue'), 'the draft is not re-based in silence').toBe(2)
    expect(save(w).attributes('disabled'), 'nothing changed from what is stored now').toBeDefined()

    await selects(w)[1].setValue(3)
    hoisted.putPolicy.mockResolvedValue(policy(['d2', 'd9'], 8))
    await save(w).trigger('click')
    await flushPromises()
    expect(hoisted.putPolicy).toHaveBeenLastCalledWith(
      't1',
      expect.objectContaining({ revision: 7, replicaset: expect.objectContaining({ min: 1, max: 3 }) }),
    )
  })

  it("keeps the draft, and shows the server's words, on any other refusal", async () => {
    const w = await render()
    await edit(w)
    await combo(w).setValue(['x'.repeat(41)])
    hoisted.putPolicy.mockRejectedValue(new Error('restricted_tags: Tag too long (max 40 chars)'))
    await save(w).trigger('click')
    await flushPromises()
    expect(combo(w).exists(), 'the form stays open').toBe(true)
    expect(textOf(w, 'error'), "the server's words").toContain('Tag too long')
    expect(combo(w).props('modelValue'), 'the draft kept').toEqual(['x'.repeat(41)])
    expect(save(w).attributes('disabled'), 'to fix and save again').toBeUndefined()
    expect(hoisted.fetchPolicy, 'nothing read again').toHaveBeenCalledTimes(1)
  })

  it('carries what it does not edit as read: a prefer word, and a rule, from a newer server', async () => {
    const newer = { ...rules, prefer: ['owner_devices', 'same_site'], spread: 'zones' }
    hoisted.fetchPolicy.mockResolvedValue({ ...policy(['d2']), replicaset: newer })
    const i18n = createI18n({ legacy: false, locale: 'en', messages: { en } })
    const w = mount(HiveCopiesView, {
      global: { plugins: [vuetify, i18n], stubs: { VDialog: DialogStub, VSwitch: SwitchStub } },
    })
    await flushPromises()
    await edit(w)
    await by(w, 'archive').trigger('click')
    hoisted.putPolicy.mockResolvedValue({ ...policy(['d2'], 4), replicaset: { ...newer, archive: false } })
    await save(w).trigger('click')
    await flushPromises()
    const written = hoisted.putPolicy.mock.calls[0][1].replicaset
    expect(written.prefer, 'every prefer word as read').toEqual(['owner_devices', 'same_site'])
    expect(written, 'and a rule it does not know').toEqual({ ...newer, archive: false })

    await edit(w)
    await by(w, 'prefer').trigger('click')
    await save(w).trigger('click')
    await flushPromises()
    expect(hoisted.putPolicy.mock.calls[1][1].replicaset.prefer, 'only its own word goes').toEqual(['same_site'])
    expect(hoisted.putPolicy.mock.calls[1][1].revision, 'from the revision the save stored').toBe(4)
  })

  it('locks the designations while the form is open', async () => {
    const w = await render()
    expect(sw(w, 'd1').attributes('disabled')).toBeUndefined()
    await edit(w)
    expect(sw(w, 'd1').attributes('disabled'), 'one write at a time, from one revision').toBeDefined()
    await by(w, 'cancel').trigger('click')
    expect(sw(w, 'd1').attributes('disabled'), 'unlocked once it closes').toBeUndefined()
    expect(by(w, 'save').exists(), 'cancelled').toBe(false)
    expect(hoisted.putPolicy).not.toHaveBeenCalled()
  })

  it('offers no edit to a member who is no administrator, or before membership loads', async () => {
    hoisted.tenant.myPermissions = 0
    let w = await render()
    expect(by(w, 'edit').exists(), 'no administrator').toBe(false)
    w.unmount()
    hoisted.tenant.myPermissions = null
    w = await render()
    expect(by(w, 'edit').exists(), 'membership not loaded').toBe(false)
  })
})
