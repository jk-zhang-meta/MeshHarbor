// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { APP_BASE_PATH, appRoutePath } from '@/utils/deployment'
import { deploymentWebSocketUrl } from '@/utils/deploymentPath'
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { useNotificationStore } from './notification'
import { useTaskStore } from './tasks'
import { useTenantStore } from './tenant'
import { useOrgBadgesStore } from './orgBadges'
import { useAgentStore } from './agents'
import { useDeviceStore } from './devices'
import { useGpuStore } from './gpu'
import type { NameSync } from '@/utils/nameSync'

type WsStatus = 'disconnected' | 'connecting' | 'connected'

export const useWsStore = defineStore('ws', () => {
  const status = ref<WsStatus>('disconnected')
  let socket: WebSocket | null = null
  let pingInterval: ReturnType<typeof setInterval> | null = null
  let reconnectTimeout: ReturnType<typeof setTimeout> | null = null

  // Remote-control message handlers — rc:* messages use a `t` discriminator
  // instead of the `{type, data}` envelope, so they get their own channel.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  type RcHandler = (msg: any) => void
  // Multi-user P3: MULTI-subscriber per rc:* type. Each subscriber gets its
  // own slot and an unsubscribe that removes only itself; per-session demux
  // stays in the subscribers (`sessionGateAllows` in useRemoteControl).
  const rcHandlers = new Map<string, Set<RcHandler>>()

  // S6 — tenant-affinity key. Carried as `tid=` on the WS URL so the
  // front load-balancer hashes this connection onto the pod that owns
  // the active tenant (rc-hub / tunnel-hub are pod-local).
  // The server validates membership; other-tenant notifications still
  // arrive via the Redis fan-out, so a multi-tenant user loses nothing.
  let affinityTid: string | null = null
  // The affinity the LIVE socket was actually dialed with. `affinityTid`
  // can move ahead of it (lazy affinity — org switches don't redial);
  // placement-critical flows (rc pre-flight) compare against THIS.
  let dialedTid: string | null = null
  // Whether a session has ever been dialed on this store.
  let dialedOnce = false
  // True once a socket has opened — a later open is a RE-connect and the
  // shell must resync state that WS pushes would have delivered meanwhile.
  let hadConnection = false

  /**
   * The affinity key an about-to-happen dial should carry. Resolution:
   * app-set affinity (active org of THIS tab; also how the rc
   * pre-flight pins a cross-org agent's tenant over the page URL) →
   * URL path (synchronously correct before the router/pinia boot) →
   * persisted last tenant.
   */
  function effectiveTid(): string | null {
    if (affinityTid) return affinityTid
    const fromPath = appRoutePath(location.pathname ?? '').match(/^\/tenant\/([0-9a-f]{24})\b/)?.[1]
    if (fromPath) return fromPath
    try {
      return globalThis.localStorage?.getItem('meshharbor-current-tenant') ?? null
    } catch {
      return null
    }
  }

  /**
   * The handshake carries NO credential in the URL.
   *
   * The browser attaches the `access_token` session cookie automatically —
   * it is `HttpOnly` and set by login / OAuth / refresh, and the server reads
   * it on the upgrade (see `ws::handler::session_cookie`).
   */
  function wsUrl(tid: string | null): string {
    return deploymentWebSocketUrl(`${location.protocol}//${location.host}`, tid, APP_BASE_PATH)
  }

  /**
   * Set (or clear) the tenant-affinity key — LAZILY. The next natural
   * dial (drop-reconnect, forceRedial) carries it; nothing on this
   * socket is placement-critical outside the rc pre-flight, which does
   * its own compare-and-redial against `dialedTid`.
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
   * didn't change. No-op when no socket is live.
   */
  function forceRedial() {
    if (socket && socket.readyState <= WebSocket.OPEN && dialedOnce) {
      const old = socket
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
      // shell (AppLayout) refetch badges and fleet state on re-open.
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
        if (msg.type === 'connected') {
          console.log('[WS] received:', msg.type)
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
      reconnectTimeout = setTimeout(() => connect(), 3000)
    }

    socket.onerror = () => {
      socket?.close()
    }
  }

  function handleMessage(msg: { type: string; data?: unknown }) {
    const notificationStore = useNotificationStore()
    const taskStore = useTaskStore()

    switch (msg.type) {
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
      case 'device:name': {
        const update = msg.data as { tenant_id: string; agent_id: string; name: string; name_sync: NameSync }
        if (update?.tenant_id !== useTenantStore().current?.id || !update.agent_id || typeof update.name !== 'string' || !update.name_sync) break
        useAgentStore().applyNameSync(update)
        useDeviceStore().patchRow({ id: update.agent_id, name: update.name, name_sync: update.name_sync })
        break
      }
      case 'device:presence': {
        // P4 — realtime device transitions. Active org → patch the agents
        // store in place; any other org → attention marker on its switcher row.
        const dp = msg.data as {
          tenant_id?: string
          agents?: Array<{ agent_id: string; name: string; presence: 'online' | 'stale' | 'offline' }>
        }
        if (!dp.tenant_id || !dp.agents?.length) break
        if (dp.tenant_id === useTenantStore().current?.id) {
          useAgentStore().applyPresence(dp.agents)
          useDeviceStore().applyPresence(dp.agents)
        } else {
          useOrgBadgesStore().noteDevicePresence(dp.tenant_id, dp.agents)
        }
        break
      }
      case 'gpu:subscribed':
        useGpuStore().noteWsSubscribed(msg.data as never)
        break
      case 'gpu:update':
        useGpuStore().applyWsHostUpdate(msg.data as never)
        break
    }
  }

  function send(type: string, data: unknown) {
    if (socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type, data }))
    } else {
      console.warn('[WS] cannot send, socket not open:', type, 'readyState:', socket?.readyState)
    }
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
   *  removes a specific handler when given one, else every handler for the type. */
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
    rcHandlers.clear()
  }

  return {
    status,
    connect,
    disconnect,
    setTenantAffinity,
    getDialedTid,
    forceRedial,
    send,
    sendRaw,
    onRcMessage,
    offRcMessage,
  }
})
