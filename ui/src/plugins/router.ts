// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { createRouter, createWebHistory } from 'vue-router'
import type { RouteRecordRaw } from 'vue-router'
import { looksSignedIn } from '@/api/session'
import { useCapabilitiesStore } from '@/stores/capabilities'
import type { ModuleId } from '@/modules/registry'

declare module 'vue-router' {
  interface RouteMeta {
    /** Requires a signed-in session (the cookie hint). */
    auth?: boolean
    /** A page for the signed-out state (login, landing, …). */
    guest?: boolean
    /** FR-69 P9 — the server module this route belongs to. Absent on every
     *  core route; children inherit it through `to.matched`, so a `network`
     *  section needs no meta of its own. */
    module?: ModuleId
    /** #1631 — the param whose change must REMOUNT the routed view (see
     *  `plugins/routeViewKey.ts` + `components/layout/KeyedRouterView.vue`).
     *  Vue Router reuses the mounted component when only params change, so
     *  a view that resolves its subject once in `onMounted` (the remote
     *  viewer, the profile page) kept showing the previous subject under the
     *  new URL. Absent = today's reuse, which the views that rewrite
     *  `route.query` in place depend on — do not key by fullPath. */
    remountOn?: string
    /** T8b — route may render chrome-less (`100vw × 100dvh`) when opened with `?embed=1`. */
    allowEmbed?: boolean
  }
}

const routes: RouteRecordRaw[] = [
  {
    path: '/landing',
    name: 'landing',
    component: () => import('@/views/LandingView.vue'),
    meta: { guest: true },
  },
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/auth/LoginView.vue'),
    meta: { guest: true },
  },
  {
    path: '/register',
    name: 'register',
    component: () => import('@/views/auth/RegisterView.vue'),
    meta: { guest: true },
  },
  {
    path: '/verify-email-change',
    name: 'verify-email-change',
    component: () => import('@/views/auth/VerifyEmailChangeView.vue'),
  },
  {
    path: '/native-session-complete',
    name: 'native-session-complete',
    component: () => import('@/views/auth/NativeSessionCompleteView.vue'),
  },
  {
    path: '/privacy',
    name: 'privacy',
    component: () => import('@/views/legal/PrivacyPolicyView.vue'),
  },
  {
    path: '/terms',
    name: 'terms',
    component: () => import('@/views/legal/TermsView.vue'),
  },
  {
    path: '/imprint',
    name: 'imprint',
    component: () => import('@/views/legal/ImprintView.vue'),
  },
  {
    path: '/oauth/callback',
    name: 'oauth-callback',
    component: () => import('@/views/auth/OAuthCallbackView.vue'),
    meta: { guest: true },
  },
  {
    path: '/invite/:code',
    name: 'invite',
    component: () => import('@/views/invite/InviteLandingView.vue'),
  },
  {
    // Public owner-consent landing (Phase 4). No `meta.auth` — the token in the
    // path is the capability, so a logged-out owner can approve from the email
    // link / push tap.
    path: '/consent/:token',
    name: 'consent',
    component: () => import('@/views/remote/ConsentView.vue'),
    meta: { module: 'fleet' },
  },
  {
    // 0.5.0 — Chromeless admin silent watch & takeover viewer (100vw × 100dvh,
    // outside AppLayout so no sidebar/app-bar obscures the monitored screen).
    path: '/tenant/:tenantId/monitoring/watch/:agentId',
    name: 'monitoring-watch',
    component: () => import('@/views/monitoring/MonitorWatchView.vue'),
    meta: { auth: true, module: 'remote', remountOn: 'agentId' },
  },
  {
    path: '/',
    component: () => import('@/components/layout/AppLayout.vue'),
    meta: { auth: true },
    children: [
      {
        path: '',
        name: 'dashboard',
        component: () => import('@/views/dashboard/DashboardView.vue'),
      },
      {
        path: 'my-devices', name: 'my-devices',
        component: () => import('@/views/account/PersonalDevicesView.vue'),
      },
      {
        // `mh login` / the tray's sign-in lands here (`?code=XXXXX-XXXXX`).
        path: 'device-login', name: 'device-login',
        component: () => import('@/views/account/DeviceLoginView.vue'),
      },
      {
        path: 'device-shares', name: 'device-shares',
        component: () => import('@/views/account/DeviceSharesView.vue'),
      },
      {
        path: 'device-shares/:shareId/remote', name: 'shared-remote',
        component: () => import('@/views/remote/SharedRemoteView.vue'),
        meta: { module: 'remote', remountOn: 'shareId' },
      },
      {
        // Global, not tenant membership. The view asks the server for owner access.
        path: 'account-approval',
        name: 'account-approval',
        component: () => import('@/views/account/AccountApprovalView.vue'),
      },
      {
        path: 'profile/edit',
        name: 'profile-edit',
        component: () => import('@/views/profile/ProfileEditView.vue'),
      },
      {
        // Stats PR-4 — platform-operator observability (relay fleet, orgs).
        // Client-gated by user.is_platform_admin; the server 404s everyone else.
        path: 'observability',
        name: 'observability',
        component: () => import('@/views/observability/ObservabilityView.vue'),
      },
      {
        path: 'profile/:userId',
        name: 'profile',
        component: () => import('@/views/profile/ProfileView.vue'),
        // #1631 — loads its user once in onMounted; a profile→profile hop
        // must be a fresh view, not the previous user under the new URL.
        meta: { remountOn: 'userId' },
      },
      {
        // FR-52 P4e — control a device in ANOTHER organization, with its
        // connect code and the password its owner set on it. Outside the
        // tenant subtree on purpose: the person using it belongs to no org the
        // device is in, and may belong to none at all.
        path: 'connect',
        name: 'connect',
        component: () => import('@/views/remote/ConnectView.vue'),
        meta: { module: 'remote' },
      },
      {
        // The viewer for the session that login opened. Reached only through
        // `connect`, which hands it the login in memory; a reload lands back
        // on the password, by design.
        path: 'connect/session',
        name: 'connect-session',
        component: () => import('@/views/remote/RemoteControl.vue'),
        meta: { module: 'remote' },
      },
      {
        path: 'tenant/:tenantId',
        children: [
          {
            path: '',
            name: 'tenant-dashboard',
            component: () => import('@/views/dashboard/TenantDashboard.vue'),
          },
          {
            path: 'invites',
            name: 'invites',
            component: () => import('@/views/invite/InviteManageView.vue'),
          },
          {
            // FR-12 — the welcome tour. Every member can reach it forever
            // (app-bar `?` / user menu); a fresh org auto-opens it once.
            // The chapter lives in the URL hash, so `#devices` deep-links
            // from the devices empty state and back/forward work.
            path: 'tutorial',
            name: 'tutorial',
            component: () => import('@/views/tutorial/TutorialView.vue'),
          },
          {
            // S4 pivot — the fleet page, promoted out of Admin. The old
            // `admin-agents` path redirects here (below).
            path: 'devices',
            name: 'devices',
            component: () => import('@/views/devices/DevicesView.vue'),
            meta: { module: 'fleet' },
          },
          {
            // FR-139 — GPU servers at a glance (fleet, history, users, alerts, bots).
            path: 'gpu',
            name: 'gpu-servers',
            component: () => import('@/views/gpu/GpuServersView.vue'),
            meta: { module: 'fleet' },
          },
          {
            // T8b — full-page interactive 3D device globe; supports `?embed=1&lang=&theme=`
            // for the desktop companion (no app bar / no nav drawer) and normal full-page browsing.
            path: 'network/globe',
            name: 'network-globe',
            props: true,
            component: () => import('@/views/network/NetworkGlobeView.vue'),
            meta: { module: 'network', allowEmbed: true },
          },
          {
            // S4 pivot — the overlay/tunnel network group, promoted out
            // of Admin (Tailscale-style IA). Sections stay child routes
            // (bookmarkable, back/forward-friendly), same pattern as
            // Admin.
            path: 'network',
            // 2026-08-04 — machines + tunnel-clients folded into the unified
            // Devices page (overlay address/last-seen live on the device
            // rows now); the parent lands on ACL, the first remaining child.
            redirect: { name: 'network-acl' },
            component: () => import('@/views/network/NetworkPanel.vue'),
            meta: { module: 'network' },
            children: [
              { path: 'machines',       redirect: { name: 'devices' } },
              { path: 'tunnel-clients', redirect: { name: 'devices' } },
              // 2026-08-04 — ONE ACL page with Overlay + Tunnel tabs
              // (separate backends, single place); the standalone
              // overlay-acl path lands on its tab.
              { path: 'acl',            name: 'network-acl',            props: true, component: () => import('@/components/admin/AclSection.vue') },
              { path: 'subnet-routes',  name: 'network-subnet-routes',  props: true, component: () => import('@/components/admin/OverlaySubnetRoutesSection.vue') },
              { path: 'overlay-acl',    redirect: (to) => ({ name: 'network-acl', params: to.params, query: { tab: 'overlay' } }) },
              { path: 'dns',            name: 'network-dns',            props: true, component: () => import('@/components/admin/MagicDnsSection.vue') },
              // MeshHarbor #19 — what each node reported reading from its kernel.
              { path: 'inventory',      name: 'network-inventory',      props: true, component: () => import('@/components/admin/NetInventorySection.vue') },
              // MeshHarbor #20 — declared forwards, planned before any effect.
              { path: 'forwards',       name: 'network-forwards',       props: true, component: () => import('@/components/admin/ManagedForwardSection.vue') },
              // Server topology: zone backbone globe & gateway links.
              { path: 'servers',        name: 'network-servers',        props: true, component: () => import('@/components/admin/ServerTopologySection.vue') },
            ],
          },
          {
            path: 'admin',
            // Parent-level redirect: hitting `/tenant/{id}/admin` goes
            // straight to the Settings child without leaving an
            // intermediate history entry. Avoids the back-button loop
            // that an empty-path child redirect would create.
            redirect: { name: 'admin-settings' },
            component: () => import('@/views/admin/AdminPanel.vue'),
            // Each section is a child route — URL reflects the active
            // tab, browser back/forward works, deep links bookmarkable.
            // `props: true` auto-passes route params (tenantId) as
            // component props so each section receives `tenantId`
            // consistently with the existing AgentsSection contract.
            children: [
              { path: 'settings',  name: 'admin-settings',  props: true, component: () => import('@/components/admin/SettingsSection.vue') },
              { path: 'members',   name: 'admin-members',   props: true, component: () => import('@/components/admin/MembersSection.vue') },
              { path: 'roles',     name: 'admin-roles',     props: true, component: () => import('@/components/admin/RolesSection.vue') },
              // S4 — the fleet/network sections moved out of Admin; the
              // old paths 301 to their new homes (named redirects keep
              // the :tenantId param). Old bookmarks + docs keep working.
              { path: 'agents',          redirect: { name: 'devices' } },
              { path: 'tunnel-clients',  redirect: { name: 'devices' } },
              { path: 'tunnel-policies', redirect: { name: 'network-acl' } },
              { path: 'subnet-routes',   redirect: { name: 'network-subnet-routes' } },
              { path: 'magic-dns',       redirect: { name: 'network-dns' } },
            ],
          },
          {
            // 0.5.0 — Unified SSH & Remote Control Monitoring Console
            // (`监控中` live + `监控历史` history + `命令审计` exec).
            path: 'monitoring',
            redirect: { name: 'monitoring-live' },
            component: () => import('@/views/monitoring/MonitoringPanel.vue'),
            children: [
              { path: 'live',    name: 'monitoring-live',    props: true, meta: { module: 'fleet' }, component: () => import('@/views/monitoring/LiveMonitoringTab.vue') },
              { path: 'history', name: 'monitoring-history', props: true, meta: { module: 'fleet' }, component: () => import('@/views/monitoring/MonitoringHistoryTab.vue') },
              { path: 'exec',    name: 'monitoring-exec',    props: true, meta: { module: 'fleet' }, component: () => import('@/components/admin/ExecAuditSection.vue') },
            ],
          },
          {
            // Legacy `/audit/*` bookmarks redirect cleanly to `/monitoring/*`.
            path: 'audit',
            redirect: { name: 'monitoring-live' },
            children: [
              { path: 'exec',         name: 'audit-exec',         redirect: { name: 'monitoring-exec' } },
              { path: 'ssh',          name: 'audit-ssh',          redirect: { name: 'monitoring-history' } },
              { path: 'ssh-activity', name: 'audit-ssh-activity', redirect: { name: 'monitoring-history' } },
            ],
          },
          {
            path: 'agent/:agentId/remote',
            name: 'agent-remote',
            component: () => import('@/views/remote/RemoteControl.vue'),
            // #1631 — the viewer resolves its device in onMounted and owns a
            // live session; picking another device in the nav must tear that
            // view down and mount a fresh one for the new agentId, never
            // re-point the mounted one (its Connect kept dialling the old
            // device). Locked by KeyedRouterView.spec.ts on this record.
            meta: { module: 'remote', remountOn: 'agentId' },
          },
        ],
      },
    ],
  },
  // 404 catch-all
  {
    path: '/:pathMatch(.*)*',
    name: 'not-found',
    component: () => import('@/views/NotFoundView.vue'),
  },
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes,
})

router.beforeEach((to, _from, next) => {
  // A HINT, not a credential — the session is an HttpOnly cookie this code
  // cannot read. Guarding on it only decides which screen to render; every
  // request is still authorised by the server, and a stale hint just means the
  // first API call 401s and bounces back here.
  const signedIn = looksSignedIn()
  if (to.meta.auth && !signedIn) {
    if (to.fullPath === '/' || to.fullPath === '') {
      // Bare root: first-visit marketing page, nothing to return to.
      next({ name: 'landing' })
    } else {
      // S2: remember the protected deep-link (e.g. the desktop app's
      // "View screen" → /tenant/{tid}/agent/{aid}/remote) and go
      // straight to login — the landing page would strand the link.
      // Consumed by the guest guard below and the login/OAuth handlers.
      sessionStorage.setItem('pending_redirect', to.fullPath)
      next({ name: 'login' })
    }
  } else if (to.meta.guest && signedIn) {
    // After login/register, check for pending invite
    const pendingInvite = sessionStorage.getItem('pending_invite_code')
    const pendingRedirect = sessionStorage.getItem('pending_redirect')
    if (pendingInvite) {
      sessionStorage.removeItem('pending_invite_code')
      next({ name: 'invite', params: { code: pendingInvite } })
    } else if (
      // Same-origin paths ONLY: `startsWith('/')` alone also admits the
      // protocol-relative `//evil.com` / `/\evil.com` open-redirect forms.
      pendingRedirect &&
      pendingRedirect.startsWith('/') &&
      !pendingRedirect.startsWith('//') &&
      !pendingRedirect.startsWith('/\\')
    ) {
      sessionStorage.removeItem('pending_redirect')
      next(pendingRedirect)
    } else {
      next({ name: 'dashboard' })
    }
  } else {
    next()
  }
})

// FR-69 P9 — a pillar the server does not mount is absent everywhere at
// once: the navigation hides it (AppLayout, TenantDashboard) and this guard
// refuses its routes, so a bookmark or a stale link lands on the org
// dashboard instead of a page whose every request 404s. Runs AFTER the
// auth guard above, so an anonymous deep-link still meets login first.
// `to.matched` carries the parents' meta, so a `network` section child needs
// no meta of its own. Fail-OPEN: an unanswered `/api/capabilities` gates
// nothing (see `stores/capabilities.ts`).
router.beforeEach(async (to) => {
  const wanted = to.matched.map((r) => r.meta.module).find((m): m is ModuleId => Boolean(m))
  if (!wanted) return true
  const caps = useCapabilitiesStore()
  await caps.ready()
  if (caps.has(wanted)) {
    return true
  }
  console.warn(
    `[modules] route '${String(to.name)}' needs module '${wanted}', which this server does not mount`,
  )
  const tenantId = to.params.tenantId
  return typeof tenantId === 'string' && tenantId !== ''
    ? { name: 'tenant-dashboard', params: { tenantId } }
    : { name: 'not-found' }
})

export default router
