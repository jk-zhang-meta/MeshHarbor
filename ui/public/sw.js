// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
// registration.scope includes this product's outer deployment path.
function notificationUrl(value) {
  const scope = new URL(self.registration.scope)
  try {
    const target = new URL(value || './', scope)
    if (target.origin !== scope.origin) return scope.href
    if (!target.pathname.startsWith(scope.pathname)) {
      target.pathname = scope.pathname.replace(/\/$/, '') + target.pathname
    }
    return target.href
  } catch { return scope.href }
}

self.addEventListener('push', (event) => {
  if (!event.data) return

  let data
  try {
    data = event.data.json()
  } catch {
    data = { title: 'MeshHarbor · 织港', body: event.data.text() }
  }

  const options = {
    body: data.body || '',
    icon: new URL('meshharbor.svg', self.registration.scope).href,
    badge: new URL('meshharbor.svg', self.registration.scope).href,
    data: { url: notificationUrl(data.url) },
  }

  event.waitUntil(self.registration.showNotification(data.title || 'MeshHarbor · 织港', options))
})

self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  const url = notificationUrl(event.notification.data?.url)
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if (client.url.startsWith(self.registration.scope) && 'focus' in client) {
          client.navigate(url)
          return client.focus()
        }
      }
      return clients.openWindow(url)
    }),
  )
})
