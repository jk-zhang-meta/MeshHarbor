// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//
// FR-129 — the web console on a device that asks for a code with every
// command. The code goes with the request once; a device refusal asks for a
// fresh one, and the spent code is never sent again.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import type { Agent, ExecResult } from '@/stores/agents'

const hoisted = vi.hoisted(() => ({
  execOnAgent: vi.fn(),
}))
vi.mock('@/stores/agents', () => ({
  useAgentStore: () => ({
    orgExecEnabled: true,
    fetchOrgExecEnabled: vi.fn(),
    execOnAgent: hoisted.execOnAgent,
    cancelExec: vi.fn(),
  }),
}))

import DeviceConsoleDialog from '@/components/admin/DeviceConsoleDialog.vue'

const vuetify = createVuetify({ components, directives })
const DialogStub = { props: ['modelValue'], template: '<div v-if="modelValue"><slot /></div>' }

function agent(caps: Record<string, unknown>): Agent {
  return {
    id: 'a1',
    name: 'gpu',
    os: 'linux',
    is_online: true,
    presence: 'online',
    agent_version: '0.4.212',
    exec_policy: { mode: 'on' },
    capabilities: { rpc: ['exec', 'two-factor'], ...caps },
  } as unknown as Agent
}

function result(error: string | null): ExecResult {
  return {
    request_id: 'r',
    agent_id: 'a1',
    agent_name: 'gpu',
    exit_code: error ? null : 0,
    stdout: error ? '' : 'up 3 days',
    stderr: '',
    truncated: false,
    duration_ms: 12,
    error,
  }
}

function render(a: Agent) {
  return mount(DeviceConsoleDialog, {
    props: { modelValue: true, tenantId: 't1', agent: a },
    global: { plugins: [vuetify], stubs: { VDialog: DialogStub } },
  })
}

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
})

describe('DeviceConsoleDialog two-factor (FR-129)', () => {
  it('sends the code with the command, asks again on a refusal, and never resends a spent code', async () => {
    const w = render(agent({ two_factor: true }))
    const run = () => w.find('[data-testid="console-run"]')
    expect(w.find('[data-testid="console-tfa"]').exists()).toBe(true)
    await w.find('textarea').setValue('uptime')
    expect(run().attributes('disabled'), 'no code yet').toBeDefined()

    hoisted.execOnAgent.mockResolvedValueOnce(
      result('two_factor_invalid: the two-factor code is wrong, expired or already used'),
    )
    await w.find('[data-testid="tfa-code-input"] input').setValue('123456')
    await run().trigger('click')
    await flushPromises()
    expect(hoisted.execOnAgent).toHaveBeenLastCalledWith('t1', 'a1', expect.objectContaining({
      command: 'uptime',
      two_factor_code: '123456',
    }))
    expect(w.find('[data-testid="console-tfa"]').text()).toContain('wrong, expired or already used')
    expect((w.find('[data-testid="tfa-code-input"] input').element as HTMLInputElement).value).toBe('')

    await w.find('[data-testid="tfa-code-input"] input').setValue('123456')
    await run().trigger('click')
    await flushPromises()
    expect(hoisted.execOnAgent).toHaveBeenCalledTimes(1)
    expect(w.find('[data-testid="console-tfa"]').text()).toContain('already tried')

    hoisted.execOnAgent.mockResolvedValueOnce(result(null))
    await w.find('[data-testid="tfa-code-input"] input').setValue('654321')
    await run().trigger('click')
    await flushPromises()
    expect(hoisted.execOnAgent).toHaveBeenCalledTimes(2)
    expect(hoisted.execOnAgent.mock.calls[1]![2].two_factor_code).toBe('654321')
    expect(w.text()).toContain('up 3 days')
  })

  it('sends no code to a device without two-factor, and asks once the device wants one', async () => {
    const w = render(agent({}))
    expect(w.find('[data-testid="console-tfa"]').exists()).toBe(false)
    hoisted.execOnAgent.mockResolvedValueOnce(result('two_factor_required: this device asks for a two-factor code'))
    await w.find('textarea').setValue('uptime')
    await w.find('[data-testid="console-run"]').trigger('click')
    await flushPromises()
    expect(hoisted.execOnAgent.mock.calls[0]![2]).not.toHaveProperty('two_factor_code')
    expect(w.find('[data-testid="console-tfa"]').exists()).toBe(true)
    expect(w.find('[data-testid="console-tfa"]').text()).toContain('asks for a two-factor code')
  })
})
