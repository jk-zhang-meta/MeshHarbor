// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

vi.mock('@/plugins/router', () => ({
  default: { push: vi.fn() },
}))

vi.mock('@/composables/usePush', () => ({
  subscribePush: vi.fn(() => Promise.resolve()),
  unsubscribePush: vi.fn(() => Promise.resolve()),
}))

vi.mock('@/api/client', () => ({
  api: {
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  },
}))

vi.mock('@/stores/notification', () => ({
  useNotificationStore: vi.fn(() => ({
    addFromWs: vi.fn(),
    setUnreadCount: vi.fn(),
  })),
}))

vi.mock('@/stores/tasks', () => ({
  useTaskStore: vi.fn(() => ({
    updateFromWs: vi.fn(),
  })),
}))

class MockWebSocket {
  static CONNECTING = 0
  static OPEN = 1
  static CLOSING = 2
  static CLOSED = 3

  readyState = MockWebSocket.CONNECTING
  onopen: (() => void) | null = null
  onmessage: ((event: { data: string }) => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  sentMessages: string[] = []

  send(data: string) {
    this.sentMessages.push(data)
  }

  close() {
    this.readyState = MockWebSocket.CLOSED
  }

  simulateOpen() {
    this.readyState = MockWebSocket.OPEN
    this.onopen?.()
  }

  simulateMessage(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) })
  }

  simulateClose() {
    this.readyState = MockWebSocket.CLOSED
    this.onclose?.()
  }
}

let mockWsInstance: MockWebSocket

const OriginalMockWebSocket = MockWebSocket
const WebSocketProxy = new Proxy(OriginalMockWebSocket, {
  construct(_target, args) {
    mockWsInstance = new OriginalMockWebSocket()
    ;(mockWsInstance as unknown as Record<string, unknown>).url = args[0]
    return mockWsInstance
  },
})
Object.defineProperty(WebSocketProxy, 'CONNECTING', { value: 0 })
Object.defineProperty(WebSocketProxy, 'OPEN', { value: 1 })
Object.defineProperty(WebSocketProxy, 'CLOSING', { value: 2 })
Object.defineProperty(WebSocketProxy, 'CLOSED', { value: 3 })

vi.stubGlobal('WebSocket', WebSocketProxy)
vi.stubGlobal('location', { protocol: 'http:', host: 'localhost:5000' })

import { useWsStore } from '@/stores/ws'
import { useTenantStore } from '@/stores/tenant'
import { useOrgBadgesStore } from '@/stores/orgBadges'
import { useAgentStore } from '@/stores/agents'
import { useDeviceStore } from '@/stores/devices'

describe('useWsStore', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  describe('status transitions', () => {
    it('should start as disconnected', () => {
      const store = useWsStore()
      expect(store.status).toBe('disconnected')
    })

    it('should transition to connecting when connect is called', () => {
      const store = useWsStore()
      store.connect()
      expect(store.status).toBe('connecting')
    })

    it('should transition to connected on WebSocket open', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()
      expect(store.status).toBe('connected')
    })

    it('should transition to disconnected on WebSocket close', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()
      expect(store.status).toBe('connected')

      mockWsInstance.simulateClose()
      expect(store.status).toBe('disconnected')
    })

    it('should transition to disconnected on explicit disconnect', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      store.disconnect()
      expect(store.status).toBe('disconnected')
    })
  })

  describe('handshake URL', () => {
    it('carries no credential in the query string', () => {
      const store = useWsStore()
      store.connect()
      const url = (mockWsInstance as unknown as Record<string, unknown>).url as string
      expect(url).not.toContain('token=')
      expect(url).toContain('/ws')
    })

    it('still carries the tenant-affinity key, which is not a credential', () => {
      const store = useWsStore()
      store.setTenantAffinity('0123456789abcdef01234567')
      store.connect()
      const url = (mockWsInstance as unknown as Record<string, unknown>).url as string
      expect(url).toContain('?tid=0123456789abcdef01234567')
      expect(url).not.toContain('token=')
    })
  })

  describe('send', () => {
    it('should send JSON-serialized message', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      store.send('custom:event', { foo: 'bar' })

      const sent = JSON.parse(mockWsInstance.sentMessages[0])
      expect(sent).toEqual({ type: 'custom:event', data: { foo: 'bar' } })
    })
  })

  describe('P4 cross-org routing', () => {
    function openSocketWithActiveOrg(activeTenantId: string) {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()
      useTenantStore().setCurrent({ id: activeTenantId, name: 'Org', slug: 'org' } as never)
      return store
    }

    it('bumps the foreign-org badge for notification:new with a non-active tenant_id', () => {
      openSocketWithActiveOrg('org-a')
      const badges = useOrgBadgesStore()
      const spy = vi.spyOn(badges, 'noteForeignNotification')

      mockWsInstance.simulateMessage({
        type: 'notification:new',
        data: { id: 'n1', tenant_id: 'org-b', notification_type: 'consent_request', title: 't', body: 'b' },
      })

      expect(spy).toHaveBeenCalledWith('org-b', 'consent_request')
      expect(badges.summaries['org-b']?.consents).toBe(1)
    })

    it('routes device-name evidence to both stores without accepting foreign or stale events', () => {
      openSocketWithActiveOrg('org-a')
      const agents = useAgentStore()
      const devices = useDeviceStore()
      const sync = { revision: '2', acked_revision: null, event_seq: '2', state: 'pending' as const }
      agents.agents = [{ id: 'ag1', tenant_id: 'org-a', name: 'old', name_sync: sync } as never]
      devices.items = [{ kind: 'agent', id: 'ag1', name: 'old', name_sync: sync } as never]
      const data = { tenant_id: 'org-a', agent_id: 'ag1', name: 'new', name_sync: { ...sync, acked_revision: '2', event_seq: '3', state: 'synced' } }
      mockWsInstance.simulateMessage({ type: 'device:name', data })
      expect(agents.agents[0]!.name).toBe('new')
      expect(devices.items[0]!.name_sync?.state).toBe('synced')
      mockWsInstance.simulateMessage({ type: 'device:name', data: { ...data, name: 'stale', name_sync: sync } })
      mockWsInstance.simulateMessage({ type: 'device:name', data: { ...data, tenant_id: 'org-b', name: 'foreign', name_sync: { ...data.name_sync, event_seq: '4' } } })
      expect(agents.agents[0]!.name).toBe('new')
      expect(devices.items[0]!.name).toBe('new')
    })

    it('patches the agents store for active-org device:presence and badges foreign orgs', () => {
      openSocketWithActiveOrg('org-a')
      const agentStore = useAgentStore()
      agentStore.agents = [
        { id: 'ag1', presence: 'online', is_online: true } as never,
      ]
      const badges = useOrgBadgesStore()
      const badgeSpy = vi.spyOn(badges, 'noteDevicePresence')

      mockWsInstance.simulateMessage({
        type: 'device:presence',
        data: {
          tenant_id: 'org-a',
          agents: [{ agent_id: 'ag1', name: 'box', presence: 'offline' }],
        },
      })
      expect(agentStore.agents[0]?.presence).toBe('offline')
      expect(agentStore.agents[0]?.is_online).toBe(false)
      expect(badgeSpy).not.toHaveBeenCalled()

      mockWsInstance.simulateMessage({
        type: 'device:presence',
        data: {
          tenant_id: 'org-b',
          agents: [{ agent_id: 'ag9', name: 'other', presence: 'offline' }],
        },
      })
      expect(badgeSpy).toHaveBeenCalledWith('org-b', [
        { agent_id: 'ag9', name: 'other', presence: 'offline' },
      ])
      expect(badges.hasDeviceEvents('org-b')).toBe(true)
    })
  })

  describe('ping interval', () => {
    it('should send ping every 30 seconds after connecting', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      vi.advanceTimersByTime(30_000)

      expect(mockWsInstance.sentMessages).toHaveLength(1)
      const ping = JSON.parse(mockWsInstance.sentMessages[0])
      expect(ping).toEqual({ type: 'ping' })
    })
  })

  describe('rc:* signalling channel', () => {
    it('routes rc:* messages to onRcMessage handlers, not handleMessage', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const handler = vi.fn()
      store.onRcMessage('rc:sdp.answer', handler)

      mockWsInstance.simulateMessage({
        t: 'rc:sdp.answer',
        session_id: 'abc',
        sdp: 'v=0...',
      })

      expect(handler).toHaveBeenCalledTimes(1)
      expect(handler).toHaveBeenCalledWith(
        expect.objectContaining({ t: 'rc:sdp.answer', session_id: 'abc' }),
      )
    })

    it('ignores rc:* messages with no registered handler', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      expect(() =>
        mockWsInstance.simulateMessage({ t: 'rc:unknown', foo: 1 }),
      ).not.toThrow()
    })

    it('offRcMessage removes the handler', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const handler = vi.fn()
      store.onRcMessage('rc:terminate', handler)
      store.offRcMessage('rc:terminate')

      mockWsInstance.simulateMessage({ t: 'rc:terminate', session_id: 'x' })
      expect(handler).not.toHaveBeenCalled()
    })

    it('dispatches one rc:* message to EVERY subscriber of the type', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const a = vi.fn()
      const b = vi.fn()
      store.onRcMessage('rc:terminate', a)
      store.onRcMessage('rc:terminate', b)

      mockWsInstance.simulateMessage({ t: 'rc:terminate', session_id: 'x' })
      expect(a).toHaveBeenCalledTimes(1)
      expect(b).toHaveBeenCalledTimes(1)
    })

    it('the returned unsubscribe removes only its own handler', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const a = vi.fn()
      const b = vi.fn()
      const unA = store.onRcMessage('rc:ice', a)
      store.onRcMessage('rc:ice', b)

      unA()
      mockWsInstance.simulateMessage({ t: 'rc:ice', session_id: 'x' })
      expect(a).not.toHaveBeenCalled()
      expect(b).toHaveBeenCalledTimes(1)

      const c = vi.fn()
      store.onRcMessage('rc:ice', c)
      store.offRcMessage('rc:ice', b)
      mockWsInstance.simulateMessage({ t: 'rc:ice', session_id: 'y' })
      expect(b).toHaveBeenCalledTimes(1)
      expect(c).toHaveBeenCalledTimes(1)
    })

    it('sendRaw sends the object without a {type,data} envelope', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      store.sendRaw({ t: 'rc:session.request', agent_id: 'aid', permissions: 'VIEW | INPUT' })
      expect(mockWsInstance.sentMessages).toHaveLength(1)
      const sent = JSON.parse(mockWsInstance.sentMessages[0]!)
      expect(sent).toEqual({
        t: 'rc:session.request',
        agent_id: 'aid',
        permissions: 'VIEW | INPUT',
      })
      expect(sent.type).toBeUndefined()
      expect(sent.data).toBeUndefined()
    })

    it('rcHandlers are cleared on disconnect', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const handler = vi.fn()
      store.onRcMessage('rc:ice', handler)
      store.disconnect()

      store.connect()
      mockWsInstance.simulateOpen()
      mockWsInstance.simulateMessage({ t: 'rc:ice', session_id: 'x', candidate: {} })

      expect(handler).not.toHaveBeenCalled()
    })
  })
})

describe('useWsStore tenant affinity (PR-1)', () => {
  const org = '69a1dbbad2000f26adc875ce'
  const other = '68eeeeeeeeeeeeeeeeeeeeee'

  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
    vi.useFakeTimers()
    globalThis.localStorage?.clear?.()
    vi.stubGlobal('location', { protocol: 'http:', host: 'localhost:5000', pathname: '/' })
  })

  afterEach(() => {
    vi.useRealTimers()
    globalThis.localStorage?.clear?.()
  })

  function dialedUrl(): string {
    return String((mockWsInstance as unknown as Record<string, unknown>).url)
  }

  it('seeds tid from the URL path on a deep link (first dial is keyed)', () => {
    vi.stubGlobal('location', {
      protocol: 'http:',
      host: 'localhost:5000',
      pathname: `/tenant/${org}/agent/6a6c974930177702c77e3430/remote`,
    })
    const store = useWsStore()
    store.connect()
    expect(dialedUrl()).toContain(`?tid=${org}`)
    expect(store.getDialedTid()).toBe(org)
  })

  it('prefers the app-set affinity over the URL path', () => {
    vi.stubGlobal('location', {
      protocol: 'http:',
      host: 'localhost:5000',
      pathname: `/tenant/${org}/dashboard`,
    })
    const store = useWsStore()
    store.setTenantAffinity(other)
    store.connect()
    expect(dialedUrl()).toContain(`?tid=${other}`)
  })

  it('falls back to the persisted tenant when off tenant pages', () => {
    globalThis.localStorage.setItem('meshharbor-current-tenant', org)
    const store = useWsStore()
    store.connect()
    expect(dialedUrl()).toContain(`?tid=${org}`)
  })

  it('dials key-less only when nothing is known', () => {
    const store = useWsStore()
    store.connect()
    expect(dialedUrl()).not.toContain('tid=')
    expect(store.getDialedTid()).toBeNull()
  })

  it('setTenantAffinity is lazy: no redial of the live socket', () => {
    const store = useWsStore()
    store.connect()
    mockWsInstance.simulateOpen()
    const live = mockWsInstance
    store.setTenantAffinity(other)
    expect(mockWsInstance).toBe(live)
    expect(store.status).toBe('connected')
    expect(store.getDialedTid()).toBeNull()
  })

  it('forceRedial dials a fresh socket carrying the current affinity', () => {
    const store = useWsStore()
    store.connect()
    mockWsInstance.simulateOpen()
    const first = mockWsInstance

    store.setTenantAffinity(other)
    store.forceRedial()

    expect(mockWsInstance).not.toBe(first)
    expect(dialedUrl()).toContain(`?tid=${other}`)
    expect(store.getDialedTid()).toBe(other)
  })
})
