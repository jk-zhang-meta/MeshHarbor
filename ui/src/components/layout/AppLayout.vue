<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-app class="app-layout-root">
    <v-navigation-drawer
      v-if="!embedChromeHidden"
      v-model="drawer"
      :rail="!mobile && rail"
      :permanent="!mobile"
      :temporary="mobile"
      :width="mobile ? undefined : navWidth"
      class="app-nav"
    >
      <!-- Drag the right edge to resize (persisted). Hidden in rail mode —
           rail width is Vuetify's own. -->
      <div
        v-if="!mobile && !rail"
        class="nav-resize-handle"
        aria-hidden="true"
        @mousedown.prevent="startNavResize"
      />
      <!-- Brand = way home (org picker at '/'); the chevron owns the rail toggle. -->
      <v-list-item
        v-if="!mobile && rail"
        prepend-icon="mdi-menu"
        title=""
        @click="rail = false"
      />
      <v-list-item v-else style="cursor: pointer" @click="goHome">
        <img :src="brandLogo" alt="MeshHarbor · 织港" width="160" height="32" class="app-brand-logo" />
        <template v-if="!mobile" #append>
          <v-btn
            icon="mdi-chevron-double-left"
            size="x-small"
            variant="text"
            :aria-label="t('mh.layout.collapseSidebar')"
            @click.stop="rail = true"
          />
        </template>
      </v-list-item>

      <v-divider />

      <!-- Organization switcher: current org + dropdown (switch orgs,
           create a new one, back to the picker). -->
      <v-list v-if="!railActive" density="compact">
        <v-menu @update:model-value="(open: boolean) => open && orgBadges.fetchSummary()">
          <template #activator="{ props: menuProps }">
            <v-list-item
              v-bind="menuProps"
              :title="tenantStore.current?.name || t('mh.layout.selectOrg')"
              prepend-icon="mdi-domain"
            >
              <template #append>
                <!-- P4 — dot = some OTHER org has unread activity -->
                <v-badge
                  v-if="orgBadges.anyForeignActivity(tenantStore.current?.id ?? null)"
                  dot
                  color="error"
                  inline
                  class="mr-1"
                />
                <v-icon size="small">mdi-chevron-down</v-icon>
              </template>
            </v-list-item>
          </template>
          <v-list density="compact">
            <v-list-item
              v-for="t in tenantStore.tenants"
              :key="t.id"
              :title="t.name"
              :subtitle="t.slug"
              :active="tenantStore.current?.id === t.id"
              prepend-icon="mdi-domain"
              @click="selectTenant(t)"
            >
              <template #append>
                <!-- P4 — per-org badges: unread notifications, plus an
                     amber marker when devices went offline/stale while parked -->
                <v-badge
                  v-if="tenantStore.current?.id !== t.id && orgBadges.badgeCount(t.id) > 0"
                  :content="orgBadges.badgeCount(t.id)"
                  color="error"
                  inline
                />
                <v-icon
                  v-if="tenantStore.current?.id !== t.id && orgBadges.hasDeviceEvents(t.id)"
                  size="x-small"
                  color="warning"
                  class="ml-1"
                >
                  mdi-monitor-off
                </v-icon>
              </template>
            </v-list-item>
            <v-divider />
            <v-list-item
              :title="t('mh.layout.newOrg')"
              prepend-icon="mdi-plus"
              @click="showCreateOrg = true"
            />
            <v-list-item
              :title="t('mh.layout.allOrgs')"
              prepend-icon="mdi-view-grid-outline"
              @click="goHome"
            />
          </v-list>
        </v-menu>
      </v-list>

      <v-divider />

      <!-- Navigation — fleet first (Devices, GPU), then the overlay/tunnel Network group,
           Invites, Observability (platform operators), Admin, Audit. -->
      <v-list v-if="tenantId" v-model:opened="openGroups" density="compact" nav>
        <v-list-item
          :to="`/tenant/${tenantId}`"
          prepend-icon="mdi-view-dashboard"
          :title="$t('nav.dashboard')"
          exact
        />
        <!-- Devices-first: collapsible group listing the fleet's AGENTS. -->
        <v-list-group v-if="showFleetNav" value="devices" class="nav-entity-group">
          <template #activator="{ props: groupProps }">
            <v-list-item v-bind="groupProps" prepend-icon="mdi-monitor-multiple" :title="$t('nav.devices')">
              <template #append>
                <v-btn
                  icon="mdi-view-grid-outline"
                  size="x-small"
                  variant="text"
                  :to="`/tenant/${tenantId}/devices`"
                  :title="t('mh.layout.openDevices')"
                  :aria-label="t('mh.layout.openDevices')"
                  @click.stop
                />
              </template>
            </v-list-item>
          </template>
          <v-text-field
            v-if="!railActive"
            v-model="deviceNav.query.value"
            density="compact"
            variant="solo-filled"
            flat
            hide-details
            clearable
            prepend-inner-icon="mdi-magnify"
            :placeholder="$t('common.search')"
            class="mx-2 my-1 nav-search"
            :aria-label="t('mh.layout.searchDevices')"
          />
          <v-list-item
            v-for="d in deviceNav.items.value"
            :key="d.id"
            :to="caps.has('remote') ? `/tenant/${tenantId}/agent/${d.id}/remote` : undefined"
            :title="d.name"
            :disabled="d.presence === 'offline'"
            density="compact"
          >
            <template #prepend>
              <span
                class="mh-presence__dot mr-3"
                :class="`mh-presence--${d.presence === 'online' || d.presence === 'stale' ? d.presence : 'offline'}`"
                aria-hidden="true"
              />
            </template>
          </v-list-item>
          <v-list-item
            v-if="deviceNav.searching.value"
            density="compact"
            :title="$t('common.loading')"
            disabled
          />
          <v-list-item
            v-else-if="deviceNav.hasMore.value"
            density="compact"
            class="text-medium-emphasis"
            :title="$t('common.loadMore')"
            prepend-icon="mdi-chevron-down"
            @click="deviceNav.loadMore()"
          />
        </v-list-group>
        <v-list-item
          v-if="showFleetNav"
          :to="`/tenant/${tenantId}/gpu`"
          prepend-icon="mdi-expansion-card"
          :title="$t('nav.gpuServers')"
          data-testid="nav-gpu-servers"
        />
        <v-list-group v-if="showFleetNav && caps.has('network')" value="network">
          <template #activator="{ props: groupProps }">
            <v-list-item v-bind="groupProps" prepend-icon="mdi-lan" :title="$t('nav.network')" />
          </template>
          <v-list-item :to="`/tenant/${tenantId}/network/acl`" prepend-icon="mdi-shield-key" :title="$t('nav.tunnelAcl')" />
          <v-list-item :to="`/tenant/${tenantId}/network/subnet-routes`" prepend-icon="mdi-lan-connect" :title="$t('nav.subnetRoutes')" />
          <v-list-item :to="`/tenant/${tenantId}/network/dns`" prepend-icon="mdi-dns" :title="$t('nav.magicDns')" />
          <v-list-item :to="`/tenant/${tenantId}/network/inventory`" prepend-icon="mdi-format-list-bulleted-type" :title="$t('nav.netInventory')" />
          <v-list-item :to="`/tenant/${tenantId}/network/forwards`" prepend-icon="mdi-transit-connection-variant" :title="$t('nav.managedForwards')" />
          <v-list-item :to="`/tenant/${tenantId}/network/servers`" prepend-icon="mdi-earth" :title="$t('nav.serverTopology')" />
        </v-list-group>
        <v-list-item
          v-if="canInvite"
          :to="`/tenant/${tenantId}/invites`"
          prepend-icon="mdi-account-plus"
          :title="$t('nav.invites')"
        />

        <!-- ── Platform insights section ────────────────────────── -->
        <v-divider v-if="isPlatformAdmin" class="my-1" />
        <v-list-item
          v-if="isPlatformAdmin"
          to="/observability"
          prepend-icon="mdi-chart-timeline-variant-shimmer"
          :title="$t('nav.observability')"
        />

        <!-- ── Administration section ───────────────────────────── -->
        <v-divider class="my-1" />
        <v-list-group value="admin">
          <template #activator="{ props: groupProps }">
            <v-list-item v-bind="groupProps" prepend-icon="mdi-cog" :title="$t('nav.admin')" />
          </template>
          <v-list-item :to="`/tenant/${tenantId}/admin/members`" prepend-icon="mdi-account-group" :title="$t('nav.members')" />
          <v-list-item :to="`/tenant/${tenantId}/admin/roles`" prepend-icon="mdi-shield-account" :title="$t('nav.roles')" />
        </v-list-group>
        <v-list-group v-if="canSeeExecAudit || canSeeSshAudit" value="audit">
          <template #activator="{ props: groupProps }">
            <v-list-item v-bind="groupProps" prepend-icon="mdi-clipboard-text-clock" :title="$t('nav.audit')" />
          </template>
          <v-list-item
            v-if="canSeeExecAudit"
            :to="`/tenant/${tenantId}/audit/exec`"
            prepend-icon="mdi-console-line"
            :title="$t('nav.execAudit')"
          />
          <v-list-item
            v-if="canSeeSshAudit"
            :to="`/tenant/${tenantId}/audit/ssh`"
            prepend-icon="mdi-key-chain"
            :title="$t('nav.sshAudit')"
          />
          <v-list-item
            v-if="canSeeSshAudit"
            :to="`/tenant/${tenantId}/audit/ssh-activity`"
            prepend-icon="mdi-pulse"
            :title="$t('nav.sshActivity')"
          />
        </v-list-group>
      </v-list>

      <v-list density="compact">
        <v-list-item :to="{ path: '/my-devices', query: route.query.desktop === '1' ? { desktop: '1' } : {} }" prepend-icon="mdi-account-multiple" :title="$t('mh.nav.myDevices')" data-testid="personal-devices-nav" />
        <v-list-item :to="{ path: '/device-shares', query: route.query.desktop === '1' ? { desktop: '1' } : {} }" prepend-icon="mdi-share-variant" :title="$t('mh.nav.deviceShares')" data-testid="device-shares-nav" />
      </v-list>

      <!-- Central approval is global; never hide it behind tenant membership. -->
      <v-list v-if="accountApproval.isOwner" density="compact">
        <v-list-item to="/account-approval" prepend-icon="mdi-account-check" :title="$t('mh.nav.accountApprovals')" data-testid="account-approval-nav" />
      </v-list>

      <template #append>
        <v-list density="compact">
          <v-list-item
            prepend-icon="mdi-cog"
            :title="t('nav.settings')"
            :to="settingsRoute"
          />
        </v-list>
      </template>
    </v-navigation-drawer>

    <!-- FR-125 — the remote viewer on a phone held sideways takes the whole
         page; its own pull-tab brings its toolbar back, and leaving the mode
         (or the page) brings this bar back. -->
    <v-app-bar v-if="!embedChromeHidden" density="compact" flat :model-value="!immersiveViewer">
      <template #prepend>
        <v-badge
          v-if="mobile"
          dot
          color="error"
          :model-value="orgBadges.anyForeignActivity(tenantStore.current?.id ?? null)"
          offset-x="10"
          offset-y="10"
        >
          <v-app-bar-nav-icon :aria-label="t('mh.layout.menu')" @click="drawer = !drawer" />
        </v-badge>
      </template>
      <v-app-bar-title class="app-bar-title-truncate">
        {{ pageTitle }}
      </v-app-bar-title>

      <template #append>
        <v-btn icon="mdi-magnify" size="small" :aria-label="t('common.search')" @click="showSearch = true" />
        <v-btn
          v-if="tenantId"
          icon="mdi-help-circle-outline"
          size="small"
          class="d-none d-sm-inline-flex"
          :title="$t('nav.tutorial')"
          :aria-label="$t('nav.tutorial')"
          :to="{ name: 'tutorial', params: { tenantId } }"
        />
        <v-btn
          :icon="isDark ? 'mdi-weather-sunny' : 'mdi-weather-night'"
          size="small"
          class="d-none d-sm-inline-flex"
          :aria-label="isDark ? t('mh.layout.lightMode') : t('mh.layout.darkMode')"
          @click="toggleTheme"
        />
        <v-menu>
          <template #activator="{ props: langProps }">
            <v-btn
              icon="mdi-translate"
              size="small"
              v-bind="langProps"
              :title="$t('mh.lang.label')"
              :aria-label="$t('mh.lang.label')"
              data-testid="language-menu"
            />
          </template>
          <v-list density="compact">
            <v-list-item
              v-for="l in LOCALES"
              :key="l.code"
              :title="l.label"
              :active="currentLocale === l.code"
              :data-testid="`language-${l.code}`"
              @click="setLocale(l.code)"
            />
          </v-list>
        </v-menu>
        <v-menu v-model="showNotifications" :close-on-content-click="false">
          <template #activator="{ props: menuProps }">
            <v-btn icon size="small" v-bind="menuProps">
              <v-badge
                :content="notificationStore.unreadCount"
                :model-value="notificationStore.unreadCount > 0"
                color="error"
                overlap
              >
                <v-icon>mdi-bell-outline</v-icon>
              </v-badge>
            </v-btn>
          </template>
          <notification-panel @close="showNotifications = false" />
        </v-menu>
        <v-menu v-if="auth.isAuthenticated">
          <template #activator="{ props }">
            <v-btn icon v-bind="props" size="small">
              <v-avatar size="28" color="primary">
                <span class="text-caption">{{ initials }}</span>
              </v-avatar>
            </v-btn>
          </template>
          <v-list density="compact">
            <v-list-item prepend-icon="mdi-account" :title="t('mh.layout.profile')" @click="goToProfile" />
            <v-list-item
              v-if="tenantId"
              prepend-icon="mdi-school-outline"
              :title="$t('nav.tutorial')"
              :to="{ name: 'tutorial', params: { tenantId } }"
            />
            <v-list-item
              prepend-icon="mdi-book-open-variant"
              :title="t('mh.layout.docs')"
              :href="appPath('/docs/')"
              target="_blank"
              rel="noopener"
            />
            <v-list-item
              v-if="xs"
              :prepend-icon="isDark ? 'mdi-weather-sunny' : 'mdi-weather-night'"
              :title="isDark ? t('mh.layout.lightMode') : t('mh.layout.darkMode')"
              @click="toggleTheme"
            />
            <v-list-item prepend-icon="mdi-logout" :title="t('auth.logout')" @click="handleLogout" />
          </v-list>
        </v-menu>
      </template>
    </v-app-bar>

    <v-main
      ref="mainRef"
      class="app-main-no-scroll"
      :class="{ 'app-main--embed': embedChromeHidden }"
    >
      <v-alert
        v-if="!embedChromeHidden && wsStore.status === 'connecting'"
        type="warning"
        density="compact"
        variant="tonal"
        closable
        class="ws-status-banner"
      >
        {{ t('mh.layout.connecting') }}
      </v-alert>
      <v-alert
        v-else-if="!embedChromeHidden && wsStore.status === 'disconnected'"
        type="error"
        density="compact"
        variant="tonal"
        closable
        class="ws-status-banner"
      >
        {{ t('mh.layout.reconnecting') }}
      </v-alert>
      <!-- #1631 — keyed by `meta.remountOn` so the remote viewer follows the
           device in the URL; every other route keeps the plain reuse. -->
      <keyed-router-view />
    </v-main>

    <spotlight-tour v-if="!embedChromeHidden" />

    <!-- Global search dialog -->
    <search-dialog v-model="showSearch" />

    <!-- New organization dialog (reachable from the org switcher) -->
    <v-dialog v-model="showCreateOrg" max-width="420">
      <v-card>
        <v-card-title>{{ t('mh.layout.newOrg') }}</v-card-title>
        <v-card-text>
          <v-form ref="createOrgForm" @submit.prevent="handleCreateOrg">
            <v-text-field
              v-model="orgName"
              :label="t('mh.layout.orgName')"
              :rules="[rules.required]"
              @update:model-value="autoSlugFromName"
            />
            <v-text-field
              v-model="orgSlug"
              :label="t('mh.layout.orgSlug')"
              :hint="t('mh.layout.orgSlugHint')"
              :rules="[rules.required, rules.slug]"
              @update:model-value="orgSlugTouched = true"
            />
          </v-form>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="showCreateOrg = false">{{ t('common.cancel') }}</v-btn>
          <v-btn color="primary" :loading="creatingOrg" @click="handleCreateOrg">{{ t('mh.layout.create') }}</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-app>
</template>

<script setup lang="ts">
import { appPath } from '@/utils/deployment'
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useTheme, useDisplay } from 'vuetify'
import { useI18n } from 'vue-i18n'
import { LOCALES, setLocale } from '@/plugins/i18n'
import { useAuth } from '@/composables/useAuth'
import { useAccountApprovalStore } from '@/stores/accountApproval'
import { useBrand } from '@/composables/useBrand'
import { PRODUCT_TITLE } from '@/utils/product'
import SpotlightTour from '@/components/tutorial/SpotlightTour.vue'
import { useSpotlightTour } from '@/composables/useSpotlightTour'
import { usePageViews } from '@/composables/usePageViews'
import { useRouteTenantSync } from '@/composables/useRouteTenantSync'
import { useTenantStore } from '@/stores/tenant'
import {
  canManageInvites,
  canSeeFleetNav,
  canViewExecAudit,
  canViewSshAudit,
} from '@/utils/permissions'
import { useAgentStore } from '@/stores/agents'
import { useCappedSearchList } from '@/composables/useCappedSearchList'
import { api } from '@/api/client'
import { useNotificationStore } from '@/stores/notification'
import { useOrgBadgesStore } from '@/stores/orgBadges'
import { useWsStore } from '@/stores/ws'
import { useCapabilitiesStore } from '@/stores/capabilities'
import NotificationPanel from '@/components/layout/NotificationPanel.vue'
import KeyedRouterView from '@/components/layout/KeyedRouterView.vue'
import SearchDialog from '@/components/layout/SearchDialog.vue'
import { useSnackbar } from '@/composables/useSnackbar'
import { useValidation } from '@/composables/useValidation'
import { immersiveViewer } from '@/composables/useImmersiveViewer'
import { isEmbedChromeHidden } from '@/views/network/globeEmbedParams'
import {
  hasSeenTour,
  markTourSeen,
  pushTutorialState,
  shouldAutoOpenTour,
} from '@/composables/useTutorialProgress'

const { mobile, xs } = useDisplay()
const { showError: showCreateOrgError } = useSnackbar()
const { rules } = useValidation()
const { auth, logout: handleLogout } = useAuth()
const accountApproval = useAccountApprovalStore()
watch(() => auth.user?.id ?? null, (id) => {
  accountApproval.reset()
  if (id) void accountApproval.loadAccess(id)
}, { immediate: true })
usePageViews()
const tenantStore = useTenantStore()
const notificationStore = useNotificationStore()
const orgBadges = useOrgBadgesStore()
const wsStore = useWsStore()
const caps = useCapabilitiesStore()
const route = useRoute()
const spotlight = useSpotlightTour()
watch(
  () => route.query.tour,
  (id) => {
    if (typeof id !== 'string' || !id) return
    if (spotlight.start(id)) {
      const q = { ...route.query }
      delete q.tour
      router.replace({ path: route.path, query: q, hash: route.hash })
    }
  },
  { immediate: true },
)
const router = useRouter()
const theme = useTheme()
const { logo: brandLogo } = useBrand()

const embedChromeHidden = computed(() => isEmbedChromeHidden(route))

function goToProfile() {
  if (auth.user?.id) {
    router.push({ name: 'profile', params: { userId: auth.user.id } })
  }
}

const drawer = ref(!mobile.value)
const rail = ref(false)
const railActive = computed(() => !mobile.value && rail.value)

const mainRef = ref<{ $el: HTMLElement } | null>(null)
watch(
  () => route.path,
  () => mainRef.value?.$el?.scrollTo?.({ top: 0 }),
)
const openGroups = ref<string[]>(['devices'])

// ── Resizable drawer ─────────────────────────────────────────────
const NAV_WIDTH_KEY = 'meshharbor-nav-width'
const NAV_WIDTH_DEFAULT = 308
function loadNavWidth(): number {
  try {
    const v = Number(localStorage.getItem(NAV_WIDTH_KEY))
    if (Number.isFinite(v) && v >= 220 && v <= 520) return v
  } catch {
    /* private browsing */
  }
  return NAV_WIDTH_DEFAULT
}
const navWidth = ref(loadNavWidth())
function onNavResizeMove(e: MouseEvent) {
  navWidth.value = Math.min(520, Math.max(220, e.clientX))
}
function stopNavResize() {
  document.removeEventListener('mousemove', onNavResizeMove)
  document.removeEventListener('mouseup', stopNavResize)
  document.body.style.cursor = ''
  document.body.style.userSelect = ''
  try {
    localStorage.setItem(NAV_WIDTH_KEY, String(navWidth.value))
  } catch {
    /* private browsing */
  }
}
function startNavResize() {
  document.addEventListener('mousemove', onNavResizeMove)
  document.addEventListener('mouseup', stopNavResize)
  document.body.style.cursor = 'col-resize'
  document.body.style.userSelect = 'none'
}

// ── Sidebar capped lists (first 10 + load-more, server search) ──
const agentStore = useAgentStore()

interface SidebarDevice {
  id: string
  name: string
  presence: 'online' | 'stale' | 'offline'
}

const SIDEBAR_PAGE = 10
const PRESENCE_RANK = { online: 0, stale: 1, offline: 2 } as const

const deviceNav = useCappedSearchList<SidebarDevice>({
  all: computed<SidebarDevice[]>(() =>
    agentStore.agents
      .map((a) => ({
        id: a.id,
        name: a.display_name || a.name,
        presence: a.presence ?? ((a.is_online ? 'online' : 'offline') as SidebarDevice['presence']),
      }))
      .sort(
        (x, y) =>
          PRESENCE_RANK[x.presence] - PRESENCE_RANK[y.presence] ||
          x.name.toLowerCase().localeCompare(y.name.toLowerCase()),
      ),
  ),
  search: async (q, page) => {
    const params = new URLSearchParams({
      q,
      page: String(page),
      per_page: String(SIDEBAR_PAGE),
      kind: 'agent',
      sort: 'status',
    })
    const resp = await api.get<{
      items: Array<{
        id: string
        name: string
        display_name?: string
        presence: 'online' | 'stale' | 'offline'
      }>
    }>(`/tenant/${tenantId.value}/device?${params.toString()}`)
    return resp.items.map((r) => ({
      id: r.id,
      name: r.display_name || r.name,
      presence: r.presence,
    }))
  },
  pageSize: SIDEBAR_PAGE,
})
const showNotifications = ref(false)
const showSearch = ref(false)

const isDark = computed(() => theme.global.current.value.dark)

function toggleTheme() {
  const next = isDark.value ? 'light' : 'dark'
  theme.global.name.value = next
  localStorage.setItem('meshharbor-theme', next)
}

const tenantId = computed(
  () => (route.params.tenantId as string | undefined) || tenantStore.current?.id || '',
)

useRouteTenantSync(route)

watch(
  () => tenantStore.current?.id ?? null,
  (tid) => {
    wsStore.setTenantAffinity(tid)
    if (tid) void tenantStore.fetchMyMembership(tid)
  },
  { immediate: true },
)

const showFleetNav = computed(
  () => caps.has('fleet') && canSeeFleetNav(tenantStore.myPermissions, tenantStore.isOwner),
)
const canInvite = computed(() =>
  canManageInvites(tenantStore.myPermissions, tenantStore.isOwner),
)
const canSeeExecAudit = computed(() =>
  canViewExecAudit(tenantStore.myPermissions, tenantStore.isOwner),
)
const canSeeSshAudit = computed(() =>
  canViewSshAudit(tenantStore.myPermissions, tenantStore.isOwner),
)
const isPlatformAdmin = computed(() => auth.user?.is_platform_admin === true)

watch(
  [tenantId, showFleetNav] as const,
  ([tid, fleet], prev) => {
    const prevTid = prev?.[0]
    if (tid && prevTid !== undefined && prevTid !== tid) {
      deviceNav.reset()
    }
    if (tid && fleet) void agentStore.fetchAgents(tid).catch(() => {})
  },
  { immediate: true },
)

let tourChecked = false
async function maybeAutoOpenTour() {
  if (tourChecked) return
  if (embedChromeHidden.value) return
  const tid = tenantId.value
  const uid = auth.user?.id
  if (!tid || !uid) return
  if (route.name === 'tutorial') return
  if (hasSeenTour(uid)) {
    tourChecked = true
    return
  }
  if (!showFleetNav.value) return
  tourChecked = true
  try {
    await agentStore.fetchAgents(tid)
  } catch {
    return
  }
  if (
    !shouldAutoOpenTour({
      userId: uid,
      devices: agentStore.total,
    })
  ) {
    return
  }
  markTourSeen(uid)
  pushTutorialState({ seen: true })
  router.replace({ name: 'tutorial', params: { tenantId: tid } })
}
watch([tenantId, showFleetNav] as const, () => void maybeAutoOpenTour(), { immediate: true })

const settingsRoute = computed(() =>
  tenantId.value ? `/tenant/${tenantId.value}/admin` : '/',
)

const { t, locale: currentLocale } = useI18n()
const pageTitle = computed(() => {
  const name = route.name as string
  if (name === 'my-devices') return t('mh.nav.myDevices')
  if (name === 'device-shares' || name === 'shared-remote') return t('mh.nav.deviceShares')
  if (name === 'account-approval') return t('mh.nav.accountApprovals')
  if (name === 'network-globe') return t('mh.globeV2.deviceNetworkTitle')
  return (route.meta.title as string) || PRODUCT_TITLE
})

const initials = computed(() => {
  const name = auth.user?.display_name || auth.user?.username || '?'
  return name.charAt(0).toUpperCase()
})

interface Tenant {
  id: string
  name: string
  slug: string
}

function goHome() {
  router.push('/')
}

function selectTenant(t: Tenant) {
  tenantStore.setCurrent(t as never)
  orgBadges.clearForTenant(t.id)
  router.push(`/tenant/${t.id}`)
}

// ── New-organization dialog ─────────────────────────────────────
const showCreateOrg = ref(false)
const createOrgForm = ref()
const orgName = ref('')
const orgSlug = ref('')
const orgSlugTouched = ref(false)
const creatingOrg = ref(false)

function slugify(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
}

function autoSlugFromName() {
  if (!orgSlugTouched.value) orgSlug.value = slugify(orgName.value)
}

async function handleCreateOrg() {
  const { valid } = await createOrgForm.value.validate()
  if (!valid) return
  creatingOrg.value = true
  try {
    const tenant = await tenantStore.createTenant(orgName.value, orgSlug.value)
    showCreateOrg.value = false
    orgName.value = ''
    orgSlug.value = ''
    orgSlugTouched.value = false
    router.push(`/tenant/${tenant.id}`)
  } catch (e) {
    const msg = e instanceof Error ? e.message : t('mh.layout.createOrgFailed')
    showCreateOrgError(
      msg.includes('duplicate') || msg.includes('E11000')
        ? t('mh.layout.slugTaken')
        : msg,
    )
  } finally {
    creatingOrg.value = false
  }
}

function onSearchShortcut(e: KeyboardEvent) {
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault()
    showSearch.value = true
  }
}

async function onWsReconnected() {
  orgBadges.fetchSummary()
  if (!tenantId.value) return
  deviceNav.reset()
  if (showFleetNav.value) void agentStore.fetchAgents(tenantId.value).catch(() => {})
}

onMounted(async () => {
  await tenantStore.fetchTenants()
  if (!embedChromeHidden.value) {
    notificationStore.fetchUnreadCount()
    orgBadges.fetchSummary()
  }
  window.addEventListener('keydown', onSearchShortcut)
  window.addEventListener('ws:reconnected', onWsReconnected)
})

onUnmounted(() => {
  window.removeEventListener('keydown', onSearchShortcut)
  window.removeEventListener('ws:reconnected', onWsReconnected)
})
</script>

<style scoped>
.app-brand-logo {
  display: block;
  height: 32px;
  width: auto;
}

.app-nav :deep(.v-navigation-drawer__content) {
  scrollbar-width: thin; /* Firefox */
  scrollbar-color: transparent transparent;
}
.app-nav:hover :deep(.v-navigation-drawer__content) {
  scrollbar-color: rgba(var(--v-theme-on-surface), 0.25) transparent;
}
.app-nav :deep(.v-navigation-drawer__content)::-webkit-scrollbar {
  width: 6px;
}
.app-nav :deep(.v-navigation-drawer__content)::-webkit-scrollbar-track {
  background: transparent;
}
.app-nav :deep(.v-navigation-drawer__content)::-webkit-scrollbar-thumb {
  background: transparent;
  border-radius: 3px;
}
.app-nav:hover :deep(.v-navigation-drawer__content)::-webkit-scrollbar-thumb {
  background: rgba(var(--v-theme-on-surface), 0.25);
}

.nav-resize-handle {
  position: absolute;
  top: 0;
  bottom: 0;
  right: 0;
  width: 5px;
  cursor: col-resize;
  z-index: 10;
}
.nav-resize-handle:hover {
  background: rgba(var(--v-theme-primary), 0.25);
}

.nav-entity-group :deep(.v-list-group__items .v-list-item) {
  padding-inline-start: 20px !important;
}

.app-layout-root :deep(.v-application__wrap) {
  min-height: 0 !important;
  flex: 1 1 0 !important;
  overflow: hidden;
  height: 100%;
}

.app-main-no-scroll {
  overflow-y: auto !important;
  overflow-x: hidden !important;
  flex: 1 1 0 !important;
  min-height: 0 !important;
  display: flex !important;
  flex-direction: column !important;
}
.app-main--embed {
  padding: 0 !important;
  overflow: hidden !important;
  width: 100vw;
  height: 100vh;
  height: 100dvh;
}

.ws-status-banner {
  flex: 0 0 auto;
  border-radius: 0;
}
.app-bar-title-truncate {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
