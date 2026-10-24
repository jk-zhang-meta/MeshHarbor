// SPDX-License-Identifier: AGPL-3.0-only
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mount, flushPromises, type VueWrapper } from '@vue/test-utils'
import { api } from '@/api/client'
import { useRemoteControl } from '@/composables/useRemoteControl'
import SharedRemoteView from '@/views/remote/SharedRemoteView.vue'
vi.mock('@/api/client', () => ({ api: { get: vi.fn() } }))
vi.mock('vue-router', () => ({ useRoute: () => ({ params: { shareId: 'share-fixture' } }) }))
vi.mock('@/stores/auth', () => ({ useAuthStore: () => ({ user: { id: 'recipient-fixture' } }) }))
vi.mock('@/composables/useRemoteControl', async () => {
 const { ref } = await import('vue')
 const rc = { error: ref(''), phase: ref('connected'), webcodecsActive: ref(false),
  remoteStream: ref(null), webcodecsCanvasEl: ref(null), disconnect: vi.fn(),
  attachInput: vi.fn(), connect: vi.fn(), listDir: vi.fn(), uploadFile: vi.fn(),
  uploadFiles: vi.fn(), downloadFile: vi.fn() }
 return { useRemoteControl: () => rc }
})
const rc = useRemoteControl(null as never) as unknown as {
 listDir: ReturnType<typeof vi.fn>; uploadFile: ReturnType<typeof vi.fn>;
 uploadFiles: ReturnType<typeof vi.fn>; connect: ReturnType<typeof vi.fn>
}
const stubs = {
 VContainer: { template: '<div><slot /></div>' }, VAlert: { template: '<div><slot /></div>' },
 VBtn: { props: ['disabled'], emits: ['click'], template: '<button :disabled="disabled" @click="$emit(\'click\')"><slot /></button>' },
 VTextField: { props: ['modelValue'], emits: ['update:modelValue'], template: '<input :value="modelValue" @input="$emit(\'update:modelValue\', $event.target.value)" />' },
 VTable: { template: '<table><slot /></table>' },
}
let wrapper: VueWrapper | undefined
async function open() {
 wrapper = mount(SharedRemoteView, { global: { stubs } }); await flushPromises(); return wrapper
}
async function upload(w: VueWrapper) {
 const input = w.get('input[type="file"]')
 Object.defineProperty(input.element, 'files', { configurable: true, value: [new File(['fixture'], 'fixture.txt')] })
 await input.trigger('change'); await flushPromises()
}
beforeEach(() => {
 vi.clearAllMocks()
 vi.mocked(api.get).mockResolvedValue({ id: 'device-fixture', name: 'Shared fixture', os: 'linux', capabilities: [], peer_auth_key: null,
  permissions: { ssh: false, desktop_view: true, desktop_control: false, files_read: true, files_write: true } })
 rc.listDir.mockResolvedValue({ path: '/canonical/task-dir', parent: '/canonical', entries: [] })
 rc.uploadFile.mockResolvedValue({ path: '/Downloads/fixture.txt', bytes: 7 })
 rc.uploadFiles.mockResolvedValue([{ ok: true, name: 'fixture.txt', path: '/canonical/task-dir/fixture.txt', bytes: 7 }])
})
afterEach(() => { wrapper?.unmount(); wrapper = undefined })
describe('shared-device upload destination', () => {
 it('uses the confirmed canonical browse path, not a later unconfirmed text edit', async () => {
  const w = await open()
  await w.get('input:not([type="file"])').setValue('/requested/task-dir')
  await w.findAll('button').find(b => b.text() === 'Browse')!.trigger('click'); await flushPromises()
  expect(rc.listDir).toHaveBeenCalledWith('/requested/task-dir')
  await w.get('input:not([type="file"])').setValue('/unconfirmed-other-dir')
  await upload(w)
  expect(rc.uploadFiles).toHaveBeenCalledWith([expect.objectContaining({ name: 'fixture.txt' })], { destPath: '/canonical/task-dir' })
  expect(rc.uploadFile).not.toHaveBeenCalled()
  expect(w.text()).toContain('Uploaded 7 bytes to /canonical/task-dir/fixture.txt')
 })
 it('preserves the existing default destination before a directory has been browsed', async () => {
  const w = await open(); await upload(w)
  expect(rc.uploadFiles).toHaveBeenCalledWith([expect.objectContaining({ name: 'fixture.txt' })], { destPath: undefined })
 })
 it('reports a per-file transport failure instead of claiming upload success', async () => {
  rc.uploadFiles.mockResolvedValue([{ ok: false, name: 'fixture.txt', error: 'destination is read-only' }])
  const w = await open(); await upload(w)
  expect(w.text()).toContain('destination is read-only'); expect(w.text()).not.toContain('Uploaded')
 })
})
