// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

vi.mock('@/api/client', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}))

import { useCapabilitiesStore } from '@/stores/capabilities'
import { ALL_MODULES, parseBuiltModules, withDependencies } from '@/modules/registry'
import { api } from '@/api/client'

const mockApi = vi.mocked(api)

describe('modules/registry', () => {
  it('contains only the 0.5.0 core modules', () => {
    expect(ALL_MODULES).toEqual(['fleet', 'remote', 'network'])
  })

  it('an unset VITE_MODULES builds every module', () => {
    expect(parseBuiltModules(undefined)).toEqual(ALL_MODULES)
    expect(parseBuiltModules('')).toEqual(ALL_MODULES)
    expect(parseBuiltModules('   ')).toEqual(ALL_MODULES)
  })

  it('a list prunes to the named modules, in graph order, ignoring unknown names', () => {
    expect(parseBuiltModules('network, fleet')).toEqual(['fleet', 'network'])
    expect(parseBuiltModules('remote,does-not-exist')).toEqual(['remote'])
  })

  it('a list naming nothing known keeps everything (misconfiguration, not an empty product)', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    expect(parseBuiltModules('bogus')).toEqual(ALL_MODULES)
    expect(warn).toHaveBeenCalledTimes(1)
    warn.mockRestore()
  })

  it('withDependencies closes over the graph edges', () => {
    expect(withDependencies(['remote'])).toEqual(['fleet', 'remote'])
    expect(withDependencies(['network'])).toEqual(['fleet', 'network'])
    expect(withDependencies(['network', 'remote'])).toEqual(['fleet', 'remote', 'network'])
  })
})

describe('useCapabilitiesStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('fails OPEN before the server has answered', () => {
    const store = useCapabilitiesStore()
    expect(store.loaded).toBe(false)
    expect(store.has('fleet')).toBe(true)
    expect(store.has('remote')).toBe(true)
    expect(store.has('network')).toBe(true)
  })

  it('gates on the mounted set once loaded', async () => {
    mockApi.get.mockResolvedValueOnce({
      version: '0.5.0',
      modules: ['fleet', 'network'],
      compiled: ['fleet', 'network'],
      switched_off: [],
    })
    const store = useCapabilitiesStore()
    await store.load()
    expect(mockApi.get).toHaveBeenCalledWith('/capabilities')
    expect(store.loaded).toBe(true)
    expect(store.has('fleet')).toBe(true)
    expect(store.has('network')).toBe(true)
    expect(store.has('remote')).toBe(false)
    expect(store.version).toBe('0.5.0')
  })

  it('a feature is on only when the server said true', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    const store = useCapabilitiesStore()
    expect(store.feature('session_feedback')).toBe(false)

    mockApi.get.mockRejectedValueOnce(new Error('503'))
    await store.load()
    expect(store.feature('session_feedback')).toBe(false)

    store.reset()
    mockApi.get.mockResolvedValueOnce({ version: 'x', modules: ['remote'] })
    await store.load()
    expect(store.feature('session_feedback')).toBe(false)

    store.reset()
    mockApi.get.mockResolvedValueOnce({
      version: 'x',
      modules: ['remote'],
      features: { session_feedback: true, other: 'yes', off: false },
    })
    await store.load()
    expect(store.feature('session_feedback')).toBe(true)
    expect(store.feature('other')).toBe(false)
    expect(store.feature('off')).toBe(false)
    expect(store.summary.features).toEqual({ session_feedback: true, off: false })

    store.reset()
    expect(store.feature('session_feedback')).toBe(false)
    warn.mockRestore()
  })

  it('ignores module names it does not know (a newer or legacy server)', async () => {
    mockApi.get.mockResolvedValueOnce({ version: 'x', modules: ['fleet', 'holograms', 'chat'] })
    const store = useCapabilitiesStore()
    await store.load()
    expect(store.modules).toEqual(['fleet'])
    expect(store.has('fleet')).toBe(true)
  })

  it('fails OPEN, loudly, when the request fails', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    mockApi.get.mockRejectedValueOnce(new Error('503'))
    const store = useCapabilitiesStore()
    await store.load()
    expect(store.loaded).toBe(true)
    expect(store.failed).toBe(true)
    expect(store.has('remote')).toBe(true)
    expect(warn).toHaveBeenCalledTimes(1)
    warn.mockRestore()
  })

  it('shares one in-flight request and does not refetch once loaded', async () => {
    mockApi.get.mockResolvedValueOnce({ version: 'x', modules: ['fleet'] })
    const store = useCapabilitiesStore()
    await Promise.all([store.load(), store.ready(), store.load()])
    await store.ready()
    expect(mockApi.get).toHaveBeenCalledTimes(1)
  })

  it('reset forgets the answer and fails open again', async () => {
    mockApi.get.mockResolvedValueOnce({ version: 'x', modules: ['fleet'] })
    const store = useCapabilitiesStore()
    await store.load()
    expect(store.has('network')).toBe(false)
    store.reset()
    expect(store.has('network')).toBe(true)
  })
})
