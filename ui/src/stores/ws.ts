// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { APP_BASE_PATH, appRoutePath } from '@/utils/deployment'
import { deploymentWebSocketUrl } from '@/utils/deploymentPath'
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { useAuthStore } from './auth'
import { useRoomStore } from './rooms'
import { useMessageStore } from './messages'
import { useNotificationStore } from './notification'
import { useTaskStore } from './tasks'
import { useConferenceStore } from './conference'
import { useTenantStore } from './tenant'
import { useOrgBadgesStore } from './orgBadges'
import { useAgentStore } from './agents'
import { useDeviceStore } from './devices'
import { useSnackbar } from '@/composables/useSnackbar'
import { callEndedByPlanMessage, callEndingSoonMessage } from '@/utils/meetingCap'

type WsStatus = 'disconnected' | 'connecting' | 'connected'

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type MediaMessageHandler = (data: any) => void

export const useWsStore = defineStore('ws', () => {
  const status = ref<WsStatus>('disconnected')
  // Server-minted id of THIS WebSocket connection (from the `connected`
  // frame). Scopes call sessions per connection (call/join + call/leave
  // bodies) so the same user can be in a call from several browsers.
  // Re-minted on every redial — always read the current value at call time.
  const connectionId = ref<string | null>(null)
  let socket: WebSocket | null = null
  let pingInterval: ReturnType<typeof setInterval> | null = null
  let reconnectTimeout: ReturnType<typeof setTimeout> | null = null

  // Pending one-shot message waiters (resolve on first matching message)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const pendingWaiters = new Map<string, { resolve: (data: any) => void; reject: (err: Error) => void }>()

  // Persistent media message handlers
  const mediaHandlers = new Map<string, MediaMessageHandler>()

  // Remote-control message handlers — rc:* messages use a `t` discriminator
  // instead of the `{type, data}` envelope, so they get their own channel.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  type RcHandler = (msg: any) => void
  // Multi-user P3: MULTI-subscriber per rc:* type. This was
  // one-handler-per-type — a second mounted RC surface (a device modal
  // over the RC page, two composable instances after an HMR remount)
  // silently CLOBBERED the first's handlers, and its unmount cleanup then
  // deleted the survivor's. Each subscriber now gets its own slot and an
  // unsubscribe that removes only itself; per-session demux stays in the
  // subscribers (`sessionGateAllows` in useRemoteControl).
  const rcHandlers = new Map<string, Set<RcHandler>>()

  // S6 — tenant-affinity key. Carried as `tid=` on the WS URL so the
  // front load-balancer hashes this connection onto the pod that owns
  // the active tenant (rc-hub / tunnel-hub / mediasoup are pod-local).
  // The server validates membership; other-tenant notifications still
  // arrive via the Redis fan-out, so a multi-tenant user loses nothing.
  let affinityTid: string | null = null
  // The affinity the LIVE socket was actually dialed with. `affinityTid`
  // can move ahead of it (lazy affinity — org switches don't redial);
  // placement-critical flows (rc pre-flight) compare against THIS.
  let dialedTid: string | null = null
  // Whether a session has ever been dialed on this store. Replaces the old
  // `lastToken`: the credential is a cookie now, so there is no token to hold
  // — but `forceRedial` still needs to know there is something to redial.
  let dialedOnce = false
  // True once a socket has opened — a later open is a RE-connect and the
  // shell must resync state that WS pushes would have delivered meanwhile.
  let hadConnection = false

  /**
   * The affinity key an about-to-happen dial should carry. Resolution:
   * app-set affinity (active org of THIS tab; also how the rc
   * pre-flight pins a cross-org agent's tenant over the page URL) →
   * URL path (synchronously correct before the router/pinia boot —
   * THE deep-link fix: the first dial used to go out key-less and hash
   * on client IP, landing tenants on the wrong pod 50% of the time) →
   * persisted last tenant (may be a sibling tab's org — harmless, the
   * rc pre-flight corrects).
   */
  function effectiveTid(): string | null {
    if (affinityTid) return affinityTid
    const fromPath = appRoutePath(location.pathname ?? '').match(/^\/tenant\/([0-9a-f]{24})\b/)?.[1]
    if (fromPath) return fromPath
    try {
      return globalThis.localStorage?.getItem('roomler-current-tenant') ?? null
    } catch {
      return null
    }
  }

  /**
   * The handshake carries NO credential in the URL.
   *
   * The browser attaches the `access_token` session cookie automatically —
   * it is `HttpOnly` and set by login / OAuth / refresh, and the server reads
   * it on the upgrade (see `ws::handler::session_cookie`). A query string is
   * written to every access log it passes through and kept in browser history,
   * and a socket that reconnects every few seconds wrote a live 7-day
   * credential to disk each time.
   *
   * Both Vite's development proxy and the production reverse proxy expose
   * this deployment's own /ws prefix. The backend origin check still uses
   * app.frontend_url. Cookie Path isolation is configured by the reverse proxy.
   */
  function wsUrl(tid: string | null): string {
    // Same-origin in development too: Vite's prefix-aware WS proxy strips
    // the outer base, exactly as the production reverse proxy does.
    return deploymentWebSocketUrl(`${location.protocol}//${location.host}`, tid, APP_BASE_PATH)
  }

  /**
   * Set (or clear) the tenant-affinity key — LAZILY. The next natural
   * dial (drop-reconnect, forceRedial) carries it; nothing on this
   * socket is placement-critical outside the rc pre-flight, which does
   * its own compare-and-redial against `dialedTid`. Eagerly redialing
   * here (the pre-lazy behavior) killed live rc sessions and conference
   * calls on every org switch, and cross-org pushes ride the Redis
   * fan-out regardless of which pod holds the socket.
   */
  function setTenantAffinity(tid: string | null) {
    affinityTid = tid
  }

  /** The affinity key the LIVE socket was dialed with (null = key-less). */
  function getDialedTid(): string | null {
    return dialedTid
  }

  /**
   * C-2 — immediate redial with the CURRENT affinity, even when the tid
   * didn't change. The rehome path needs this: after a server roll a
   * socket can sit PARKED on a pod the LB no longer maps this tenant to —
   * the affinity value is right, the placement is wrong, and only a fresh
   * dial re-hashes it. No-op when no socket is live.
   */
  function forceRedial() {
    if (socket && socket.readyState <= WebSocket.OPEN && dialedOnce) {
      const old = socket
      // This close is intentional — detach the handlers so the normal
      // onclose auto-reconnect (3 s) doesn't race our immediate redial.
      old.onclose = null
      old.onmessage = null
      old.onerror = null
      socket = null
      cleanup()
      try {
        old.close()
      } catch {
        /* ignore */
      }
      connect()
    }
  }

  /**
   * Open the socket. Takes no credential: the session cookie is the
   * credential, and the browser attaches it to a same-site handshake.
   */
  function connect() {
    if (socket && socket.readyState <= WebSocket.OPEN) return

    status.value = 'connecting'
    dialedOnce = true
    dialedTid = effectiveTid()
    socket = new WebSocket(wsUrl(dialedTid))

    socket.onopen = () => {
      status.value = 'connected'
      // Anything that arrived while the socket was down is lost — let the
      // shell (AppLayout) refetch rooms/unread/current messages on re-open.
      if (hadConnection) {
        window.dispatchEvent(new CustomEvent('ws:reconnected'))
      }
      hadConnection = true
      pingInterval = setInterval(() => {
        if (socket?.readyState === WebSocket.OPEN) {
          socket.send(JSON.stringify({ type: 'ping' }))
        }
      }, 30_000)
    }

    socket.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type?.startsWith('media:') || msg.type === 'connected') {
          console.log('[WS] received:', msg.type)
        }
        if (msg.type === 'connected' && typeof msg.connection_id === 'string') {
          connectionId.value = msg.connection_id
        }
        // rc:* messages use the flat `{t, ...}` shape from the signalling
        // protocol and don't go through the main dispatch.
        if (typeof msg.t === 'string' && msg.t.startsWith('rc:')) {
          const hs = rcHandlers.get(msg.t)
          if (hs) {
            // Snapshot: a handler may (un)subscribe during dispatch.
            for (const h of [...hs]) h(msg)
          }
          return
        }
        handleMessage(msg)
      } catch {
        // ignore malformed messages
      }
    }

    socket.onclose = () => {
      cleanup()
      status.value = 'disconnected'
      connectionId.value = null
      reconnectTimeout = setTimeout(() => connect(), 3000)
    }

    socket.onerror = () => {
      socket?.close()
    }
  }

  function handleMessage(msg: { type: string; data?: unknown }) {
    const roomStore = useRoomStore()
    const messageStore = useMessageStore()
    const notificationStore = useNotificationStore()
    const taskStore = useTaskStore()

    // Check pending waiters first
    const waiter = pendingWaiters.get(msg.type)
    if (waiter) {
      pendingWaiters.delete(msg.type)
      waiter.resolve(msg.data)
      return
    }

    // Check persistent media handlers
    const handler = mediaHandlers.get(msg.type)
    if (handler) {
      handler(msg.data)
      return
    }

    switch (msg.type) {
      case 'message:create': {
        const msgData = msg.data as { room_id?: string; author_id?: string; tenant_id?: string }
        const selfId = useAuthStore().user?.id
        const isOwn = !!selfId && msgData.author_id === selfId
        // P4 — cross-org routing: an event for an org this UI is NOT showing
        // feeds the org-switcher badge store. Pre-P4 it fell through into the
        // ACTIVE org's stores, inflating totalUnread with phantom room keys
        // the sidebar could never render or navigate to.
        const activeTid = useTenantStore().current?.id
        if (msgData.tenant_id && activeTid && msgData.tenant_id !== activeTid) {
          if (!isOwn) useOrgBadgesStore().noteForeignMessage(msgData.tenant_id)
          break
        }
        messageStore.addMessageFromWs(msg.data as never)
        // Increment unread count if user is not viewing this room — but
        // NEVER for the user's own messages: since 2026-08-04 the server
        // broadcasts to ALL members including the sender (so their other
        // browsers get realtime), and a self-echo must not inflate badges.
        if (msgData.room_id && !isOwn && roomStore.current?.id !== msgData.room_id) {
          roomStore.incrementUnread(msgData.room_id)
        }
        break
      }
      case 'message:update':
        messageStore.updateMessageFromWs(msg.data as never)
        break
      case 'message:delete':
        messageStore.removeMessageFromWs(msg.data as never)
        break
      case 'message:reaction':
        messageStore.handleReactionFromWs(msg.data as never)
        break
      case 'message:pin':
      case 'message:unpin':
        messageStore.pinFromWs(msg.data as never)
        break
      case 'task:update':
        taskStore.updateFromWs(msg.data as never)
        break
      case 'notification:new': {
        // The bell is user-scoped (cross-org), so the row always lands there;
        // a non-active-org notification ADDITIONALLY bumps that org's badge.
        notificationStore.addFromWs(msg.data as never)
        const nData = msg.data as { tenant_id?: string; notification_type?: string }
        const activeNotifTid = useTenantStore().current?.id
        if (nData.tenant_id && activeNotifTid && nData.tenant_id !== activeNotifTid) {
          useOrgBadgesStore().noteForeignNotification(nData.tenant_id, nData.notification_type)
        }
        break
      }
      case 'notification:unread_count': {
        const ncData = msg.data as { count: number }
        notificationStore.setUnreadCount(ncData.count)
        break
      }
      case 'device:presence': {
        // P4 — realtime device transitions. Active org → patch the agents
        // store in place; any other org → attention marker on its switcher
        // row. Replaces most of the 30 s presence poll (a slow poll stays
        // as belt).
        const dp = msg.data as {
          tenant_id?: string
          agents?: Array<{ agent_id: string; name: string; presence: 'online' | 'stale' | 'offline' }>
        }
        if (!dp.tenant_id || !dp.agents?.length) break
        if (dp.tenant_id === useTenantStore().current?.id) {
          useAgentStore().applyPresence(dp.agents)
          // The unified devices grid renders from its own row feed — patch
          // it too so presence dots stay live without a refetch.
          useDeviceStore().applyPresence(dp.agents)
        } else {
          useOrgBadgesStore().noteDevicePresence(dp.tenant_id, dp.agents)
        }
        break
      }
      case 'room:call_started': {
        const csData = msg.data as { room_id: string; room_name: string; started_by: string }
        roomStore.updateRoomCallStatus(csData.room_id, 'in_progress')
        window.dispatchEvent(new CustomEvent('room:call_started', { detail: csData }))
        break
      }
      case 'room:call_ending_soon': {
        // FR-115 P5 — the plan's meeting-length cap warns before it ends the
        // meeting; only that meeting's participants are told.
        const soon = msg.data as { room_id: string; ends_at: number; max_minutes: number; plan?: string }
        const confStore = useConferenceStore()
        if (confStore.isInCall && confStore.roomId === soon.room_id) {
          useSnackbar().showSnackbar(
            callEndingSoonMessage(soon.ends_at, soon.max_minutes, soon.plan),
            'warning',
            20000,
          )
        }
        break
      }
      case 'room:call_ended': {
        const ceData = msg.data as { room_id: string; reason?: string; max_minutes?: number; plan?: string }
        roomStore.updateRoomCallStatus(ceData.room_id, null, 0)
        // Auto-teardown conference if the ended call matches the active one
        const confStore = useConferenceStore()
        if (confStore.isInCall && confStore.roomId === ceData.room_id) {
          // FR-115 P5 — ended by the plan's cap, not by a person: say so.
          if (ceData.reason === 'plan_limit' && ceData.max_minutes) {
            useSnackbar().showSnackbar(callEndedByPlanMessage(ceData.max_minutes, ceData.plan), 'info', 10000)
          }
          confStore.leaveRoom()
        }
        break
      }
      case 'room:call_updated': {
        const cuData = msg.data as { room_id: string; participant_count: number; conference_status: string }
        roomStore.updateRoomCallStatus(cuData.room_id, cuData.conference_status, cuData.participant_count)
        break
      }
    }
  }

  function send(type: string, data: unknown) {
    if (socket?.readyState === WebSocket.OPEN) {
      const payload = JSON.stringify({ type, data })
      if (type.startsWith('media:')) {
        console.log('[WS] sending:', type)
      }
      socket.send(payload)
    } else {
      console.warn('[WS] cannot send, socket not open:', type, 'readyState:', socket?.readyState)
    }
  }

  function sendTyping(roomId: string) {
    send('typing:start', { room_id: roomId })
  }

  /** Wait for a specific message type (one-shot). Returns the data payload. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function waitForMessage(type: string, timeoutMs = 10000): Promise<any> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pendingWaiters.delete(type)
        reject(new Error(`Timeout waiting for ${type}`))
      }, timeoutMs)

      pendingWaiters.set(type, {
        resolve: (data) => {
          clearTimeout(timer)
          resolve(data)
        },
        reject: (err) => {
          clearTimeout(timer)
          reject(err)
        },
      })
    })
  }

  /** Register a persistent handler for a media message type. */
  function onMediaMessage(type: string, handler: MediaMessageHandler) {
    mediaHandlers.set(type, handler)
  }

  /** Remove a persistent handler for a media message type. */
  function offMediaMessage(type: string) {
    mediaHandlers.delete(type)
  }

  /** Send a raw object as-is (no `{type, data}` envelope). Used by the
   *  remote-control signalling protocol which has its own `{t, ...}` shape. */
  function sendRaw(msg: unknown) {
    if (socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify(msg))
    } else {
      console.warn('[WS] cannot sendRaw, socket not open')
    }
  }

  /** Register a handler for an rc:* message type (e.g. `rc:sdp.answer`).
   *  Multi-subscriber (P3): every registered handler for the type runs;
   *  the returned function unsubscribes ONLY this handler. `offRcMessage`
   *  (legacy surface, still exported) removes a specific handler when
   *  given one, else every handler for the type. */
  function onRcMessage(t: string, handler: RcHandler): () => void {
    let hs = rcHandlers.get(t)
    if (!hs) {
      hs = new Set()
      rcHandlers.set(t, hs)
    }
    hs.add(handler)
    return () => {
      const set = rcHandlers.get(t)
      if (set) {
        set.delete(handler)
        if (set.size === 0) rcHandlers.delete(t)
      }
    }
  }
  function offRcMessage(t: string, handler?: RcHandler) {
    if (!handler) {
      rcHandlers.delete(t)
      return
    }
    const set = rcHandlers.get(t)
    if (set) {
      set.delete(handler)
      if (set.size === 0) rcHandlers.delete(t)
    }
  }

  function cleanup() {
    if (pingInterval) {
      clearInterval(pingInterval)
      pingInterval = null
    }
    if (reconnectTimeout) {
      clearTimeout(reconnectTimeout)
      reconnectTimeout = null
    }
  }

  function disconnect() {
    cleanup()
    socket?.close()
    socket = null
    status.value = 'disconnected'
    connectionId.value = null
    pendingWaiters.clear()
    mediaHandlers.clear()
    rcHandlers.clear()
  }

  return {
    status,
    connectionId,
    connect,
    disconnect,
    setTenantAffinity,
    getDialedTid,
    forceRedial,
    send,
    sendRaw,
    sendTyping,
    waitForMessage,
    onMediaMessage,
    offMediaMessage,
    onRcMessage,
    offRcMessage,
  }
})
