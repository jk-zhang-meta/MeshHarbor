// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { APP_BASE_PATH, appPath } from '@/utils/deployment'
import { api } from '@/api/client'

function urlBase64ToUint8Array(base64String: string): Uint8Array {
  const padding = '='.repeat((4 - (base64String.length % 4)) % 4)
  const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/')
  const rawData = atob(base64)
  const outputArray = new Uint8Array(rawData.length)
  for (let i = 0; i < rawData.length; i++) {
    outputArray[i] = rawData.charCodeAt(i)
  }
  return outputArray
}

export async function subscribePush(): Promise<void> {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return

  try {
    const config = await api.get<{ vapid_public_key: string }>('/push/config')
    if (!config.vapid_public_key) return

    const registration = await navigator.serviceWorker.register(appPath('/sw.js'), { scope: APP_BASE_PATH })
    await navigator.serviceWorker.ready

    const permission = await Notification.requestPermission()
    if (permission !== 'granted') return

    const keyArray = urlBase64ToUint8Array(config.vapid_public_key)
    const subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: keyArray.buffer as ArrayBuffer,
    })

    const json = subscription.toJSON()
    await api.post('/push/subscribe', {
      endpoint: json.endpoint,
      keys: {
        auth: json.keys?.auth,
        p256dh: json.keys?.p256dh,
      },
    })
  } catch (e) {
    console.warn('Push subscription failed:', e)
  }
}

export async function unsubscribePush(): Promise<void> {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) return

  try {
    const registration = await navigator.serviceWorker.getRegistration(APP_BASE_PATH)
    if (!registration) return

    const subscription = await registration.pushManager.getSubscription()
    if (!subscription) return

    await api.post('/push/unsubscribe', { endpoint: subscription.endpoint })
    await subscription.unsubscribe()
  } catch (e) {
    console.warn('Push unsubscribe failed:', e)
  }
}
