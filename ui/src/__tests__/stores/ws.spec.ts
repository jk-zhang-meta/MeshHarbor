// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

// Mock router
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

// Mock dependent stores used inside handleMessage
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

vi.mock('@/stores/conference', () => ({
  useConferenceStore: vi.fn(() => ({
    isInCall: false,
    roomId: null,
    leaveRoom: vi.fn(),
  })),
}))

// WebSocket mock
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

  // Test helpers
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

// Replace globalThis WebSocket with our mock class.
// We use a subclass so `new WebSocket(url)` works with Reflect.construct.
const OriginalMockWebSocket = MockWebSocket
const WebSocketProxy = new Proxy(OriginalMockWebSocket, {
  construct(_target, args) {
    mockWsInstance = new OriginalMockWebSocket()
    // Store the URL for potential assertions
    ;(mockWsInstance as unknown as Record<string, unknown>).url = args[0]
    return mockWsInstance
  },
})
// Copy static constants
Object.defineProperty(WebSocketProxy, 'CONNECTING', { value: 0 })
Object.defineProperty(WebSocketProxy, 'OPEN', { value: 1 })
Object.defineProperty(WebSocketProxy, 'CLOSING', { value: 2 })
Object.defineProperty(WebSocketProxy, 'CLOSED', { value: 3 })

vi.stubGlobal('WebSocket', WebSocketProxy)

// Stub import.meta.env.DEV
vi.stubGlobal('location', { protocol: 'http:', host: 'localhost:5000' })

import { useWsStore } from '@/stores/ws'
import { useMessageStore } from '@/stores/messages'
import { useRoomStore } from '@/stores/rooms'
import { useTenantStore } from '@/stores/tenant'
import { useOrgBadgesStore } from '@/stores/orgBadges'
import { useAgentStore } from '@/stores/agents'
import { useConferenceStore } from '@/stores/conference'
import { useSnackbar } from '@/composables/useSnackbar'

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
      // The session cookie is the credential now. A token here would be
      // written to every access log the handshake passes through and kept in
      // browser history — and this socket reconnects constantly, so it wrote a
      // live 7-day credential to disk on every reconnect.
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

  describe('sendTyping', () => {
    it('should send correct message format', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      store.sendTyping('room-123')

      expect(mockWsInstance.sentMessages).toHaveLength(1)
      const sent = JSON.parse(mockWsInstance.sentMessages[0])
      expect(sent).toEqual({
        type: 'typing:start',
        data: { room_id: 'room-123' },
      })
    })

    it('should not send when socket is not open', () => {
      const store = useWsStore()
      store.connect()
      // Don't simulate open — socket is still CONNECTING

      store.sendTyping('room-123')

      expect(mockWsInstance.sentMessages).toHaveLength(0)
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

  describe('message routing', () => {
    it('should route message:create to messageStore.addMessageFromWs', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const messageStore = useMessageStore()
      const spy = vi.spyOn(messageStore, 'addMessageFromWs')

      const msgData = { id: 'm1', room_id: 'r1', content: 'hi' }
      mockWsInstance.simulateMessage({ type: 'message:create', data: msgData })

      expect(spy).toHaveBeenCalledWith(msgData)
    })

    it('should route message:update to messageStore.updateMessageFromWs', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const messageStore = useMessageStore()
      const spy = vi.spyOn(messageStore, 'updateMessageFromWs')

      const msgData = { id: 'm1', content: 'edited' }
      mockWsInstance.simulateMessage({ type: 'message:update', data: msgData })

      expect(spy).toHaveBeenCalledWith(msgData)
    })

    it('should route message:delete to messageStore.removeMessageFromWs', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const messageStore = useMessageStore()
      const spy = vi.spyOn(messageStore, 'removeMessageFromWs')

      const msgData = { id: 'm1', room_id: 'r1' }
      mockWsInstance.simulateMessage({ type: 'message:delete', data: msgData })

      expect(spy).toHaveBeenCalledWith(msgData)
    })

    it('should route message:reaction to messageStore.handleReactionFromWs', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const messageStore = useMessageStore()
      const spy = vi.spyOn(messageStore, 'handleReactionFromWs')

      const data = { action: 'add', message_id: 'm1', emoji: '👍', user_id: 'u1' }
      mockWsInstance.simulateMessage({ type: 'message:reaction', data })

      expect(spy).toHaveBeenCalledWith(data)
    })

    it('should route message:pin and message:unpin to messageStore.pinFromWs', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const messageStore = useMessageStore()
      const spy = vi.spyOn(messageStore, 'pinFromWs')

      const pin = { message_id: 'm1', room_id: 'r1', pinned: true }
      const unpin = { message_id: 'm1', room_id: 'r1', pinned: false }
      mockWsInstance.simulateMessage({ type: 'message:pin', data: pin })
      mockWsInstance.simulateMessage({ type: 'message:unpin', data: unpin })

      expect(spy).toHaveBeenNthCalledWith(1, pin)
      expect(spy).toHaveBeenNthCalledWith(2, unpin)
    })

    it('should increment unread for message:create in a non-current room', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const roomStore = useRoomStore()
      roomStore.setCurrent({ id: 'current-room' } as never)
      const spy = vi.spyOn(roomStore, 'incrementUnread')

      mockWsInstance.simulateMessage({
        type: 'message:create',
        data: { id: 'm1', room_id: 'other-room', content: 'hi' },
      })

      expect(spy).toHaveBeenCalledWith('other-room')
    })

    it('should NOT increment unread for message:create in the current room', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const roomStore = useRoomStore()
      roomStore.setCurrent({ id: 'current-room' } as never)
      const spy = vi.spyOn(roomStore, 'incrementUnread')

      mockWsInstance.simulateMessage({
        type: 'message:create',
        data: { id: 'm1', room_id: 'current-room', content: 'hi' },
      })

      expect(spy).not.toHaveBeenCalled()
    })

    it('should route room:call_started to roomStore.updateRoomCallStatus', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const roomStore = useRoomStore()
      const spy = vi.spyOn(roomStore, 'updateRoomCallStatus')

      mockWsInstance.simulateMessage({
        type: 'room:call_started',
        data: { room_id: 'r1', room_name: 'Room', started_by: 'u1' },
      })

      expect(spy).toHaveBeenCalledWith('r1', 'in_progress')
    })

    it('should route room:call_ended to roomStore.updateRoomCallStatus with null', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const roomStore = useRoomStore()
      const spy = vi.spyOn(roomStore, 'updateRoomCallStatus')

      mockWsInstance.simulateMessage({
        type: 'room:call_ended',
        data: { room_id: 'r1' },
      })

      expect(spy).toHaveBeenCalledWith('r1', null, 0)
    })
  })

  // FR-115 P5 — the meeting-length cap's warning, and its end.
  describe('meeting cap', () => {
    function inCall(roomId: string) {
      const leaveRoom = vi.fn()
      vi.mocked(useConferenceStore).mockReturnValueOnce({
        isInCall: true,
        roomId,
        leaveRoom,
      } as unknown as ReturnType<typeof useConferenceStore>)
      return leaveRoom
    }

    function connected() {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()
    }

    beforeEach(() => {
      const snackbar = useSnackbar()
      snackbar.hideSnackbar()
      snackbar.state.text = ''
    })

    it('warns the participants of the capped meeting', () => {
      connected()
      inCall('r1')
      mockWsInstance.simulateMessage({
        type: 'room:call_ending_soon',
        data: { room_id: 'r1', ends_at: Date.now() + 5 * 60_000, max_minutes: 60, plan: 'free' },
      })

      const { state } = useSnackbar()
      expect(state.show).toBe(true)
      expect(state.color).toBe('warning')
      expect(state.text).toContain('This meeting ends in 5 minutes.')
      expect(state.text).toContain('on the Free plan run up to 60 minutes')
    })

    it('says nothing to a member who is not in that meeting', () => {
      connected()
      inCall('r2')
      mockWsInstance.simulateMessage({
        type: 'room:call_ending_soon',
        data: { room_id: 'r1', ends_at: Date.now() + 5 * 60_000, max_minutes: 60, plan: 'free' },
      })

      expect(useSnackbar().state.show).toBe(false)
    })

    it('says why when the cap ends the meeting, and leaves it', () => {
      connected()
      const leaveRoom = inCall('r1')
      mockWsInstance.simulateMessage({
        type: 'room:call_ended',
        data: { room_id: 'r1', reason: 'plan_limit', max_minutes: 60, plan: 'free' },
      })

      expect(leaveRoom).toHaveBeenCalled()
      const { state } = useSnackbar()
      expect(state.show).toBe(true)
      expect(state.color).toBe('info')
      expect(state.text).toContain("the Free plan's 60-minute limit")
    })

    it('stays quiet when a person ended the meeting', () => {
      connected()
      const leaveRoom = inCall('r1')
      mockWsInstance.simulateMessage({ type: 'room:call_ended', data: { room_id: 'r1' } })

      expect(leaveRoom).toHaveBeenCalled()
      expect(useSnackbar().state.show).toBe(false)
    })
  })

  // P4 — events carrying a tenant_id that is NOT the active org must feed
  // the org-badge store, not the active org's stores (pre-P4 a cross-org
  // message:create inflated totalUnread with a phantom room key).
  describe('P4 cross-org routing', () => {
    function openSocketWithActiveOrg(activeTenantId: string) {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()
      useTenantStore().setCurrent({ id: activeTenantId, name: 'Org', slug: 'org' } as never)
      return store
    }

    it('routes a foreign-org message:create into the badge store, not the active stores', () => {
      openSocketWithActiveOrg('org-a')
      const messageStore = useMessageStore()
      const roomStore = useRoomStore()
      const badges = useOrgBadgesStore()
      const addSpy = vi.spyOn(messageStore, 'addMessageFromWs')
      const unreadSpy = vi.spyOn(roomStore, 'incrementUnread')
      const badgeSpy = vi.spyOn(badges, 'noteForeignMessage')

      mockWsInstance.simulateMessage({
        type: 'message:create',
        data: { id: 'm1', tenant_id: 'org-b', room_id: 'r-foreign', author_id: 'other' },
      })

      expect(badgeSpy).toHaveBeenCalledWith('org-b')
      expect(addSpy).not.toHaveBeenCalled()
      expect(unreadSpy).not.toHaveBeenCalled()
      expect(badges.badgeCount('org-b')).toBe(1)
    })

    it('keeps active-org and legacy (no tenant_id) message:create on the normal path', () => {
      openSocketWithActiveOrg('org-a')
      const messageStore = useMessageStore()
      const addSpy = vi.spyOn(messageStore, 'addMessageFromWs')

      mockWsInstance.simulateMessage({
        type: 'message:create',
        data: { id: 'm1', tenant_id: 'org-a', room_id: 'r1', author_id: 'other' },
      })
      mockWsInstance.simulateMessage({
        type: 'message:create',
        data: { id: 'm2', room_id: 'r1', author_id: 'other' },
      })

      expect(addSpy).toHaveBeenCalledTimes(2)
    })

    it('bumps the foreign-org badge for notification:new with a non-active tenant_id', () => {
      openSocketWithActiveOrg('org-a')
      const badges = useOrgBadgesStore()
      const spy = vi.spyOn(badges, 'noteForeignNotification')

      mockWsInstance.simulateMessage({
        type: 'notification:new',
        data: { id: 'n1', tenant_id: 'org-b', notification_type: 'mention', title: 't', body: 'b' },
      })

      expect(spy).toHaveBeenCalledWith('org-b', 'mention')
      expect(badges.summaries['org-b']?.mentions).toBe(1)
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

  describe('media handlers', () => {
    it('should register and invoke persistent media handlers', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const handler = vi.fn()
      store.onMediaMessage('media:produce', handler)

      mockWsInstance.simulateMessage({ type: 'media:produce', data: { id: 'p1' } })

      expect(handler).toHaveBeenCalledWith({ id: 'p1' })
    })

    it('should remove media handler with offMediaMessage', () => {
      const store = useWsStore()
      store.connect()
      mockWsInstance.simulateOpen()

      const handler = vi.fn()
      store.onMediaMessage('media:consume', handler)
      store.offMediaMessage('media:consume')

      mockWsInstance.simulateMessage({ type: 'media:consume', data: {} })

      expect(handler).not.toHaveBeenCalled()
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

      // Should not throw / not dispatch through handleMessage.
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

    // Multi-user P3 — the registry is multi-subscriber: a second mounted
    // RC surface must not clobber the first, and each unsubscribe removes
    // only its own handler.
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

      // Targeted off with the handler arg removes just that one too.
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
      // No accidental wrapping.
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

      // Reconnect and send — handler from the prior session must not fire.
      store.connect()
      mockWsInstance.simulateOpen()
      mockWsInstance.simulateMessage({ t: 'rc:ice', session_id: 'x', candidate: {} })

      expect(handler).not.toHaveBeenCalled()
    })
  })
})

// PR-1: tenant-affinity seeding + lazy affinity + dialedTid tracking.
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
    expect(store.getDialedTid()).toBeNull() // still the dialed key, not the pending one
  })

  it('forceRedial dials a fresh socket carrying the current affinity', () => {
    const store = useWsStore()
    store.connect()
    mockWsInstance.simulateOpen()
    const old = mockWsInstance
    store.setTenantAffinity(other)
    store.forceRedial()
    expect(mockWsInstance).not.toBe(old)
    expect(dialedUrl()).toContain(`?tid=${other}`)
    expect(store.getDialedTid()).toBe(other)
  })
})
