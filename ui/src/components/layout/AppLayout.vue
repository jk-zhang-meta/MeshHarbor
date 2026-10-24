<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-app class="app-layout-root">
    <v-navigation-drawer
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
      <!-- Brand = way home (org picker at '/'); the chevron owns the rail
           toggle — the brand used to be ONLY a rail toggle, leaving the
           app with no route back to the root at all. -->
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
            aria-label="Collapse sidebar"
            @click.stop="rail = true"
          />
        </template>
      </v-list-item>

      <v-divider />

      <!-- Organization switcher: current org + dropdown (switch orgs,
           create a new one, back to the picker). Switching NAVIGATES —
           the old list only mutated the store, leaving the URL and the
           room list on the previous org. -->
      <v-list v-if="!railActive" density="compact">
        <v-menu @update:model-value="(open: boolean) => open && orgBadges.fetchSummary()">
          <template #activator="{ props: menuProps }">
            <v-list-item
              v-bind="menuProps"
              :title="tenantStore.current?.name || 'Select organization'"
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
                <!-- P4 — per-org badges: unread messages+notifications, plus an
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
              title="New organization"
              prepend-icon="mdi-plus"
              @click="showCreateOrg = true"
            />
            <v-list-item
              title="All organizations"
              prepend-icon="mdi-view-grid-outline"
              @click="goHome"
            />
          </v-list>
        </v-menu>
      </v-list>

      <v-divider />

      <!-- Navigation — S4 pivot IA: fleet first (Devices), then the
           overlay/tunnel Network group, then collaboration (Rooms), with
           the Admin residue last. Two-level via v-list-group; leaf items
           are real routes. -->
      <v-list v-if="tenantId" v-model:opened="openGroups" density="compact" nav>
        <v-list-item
          :to="`/tenant/${tenantId}`"
          prepend-icon="mdi-view-dashboard"
          :title="$t('nav.dashboard')"
          exact
        />
        <!-- FR-90 — agent sessions; only where the server runs `hive`, which
             is switched off unless an operator turns it on (the capability
             gate fails CLOSED for it). -->
        <v-list-item
          v-if="caps.has('hive') && hiveServed"
          :to="`/tenant/${tenantId}/sessions`"
          prepend-icon="mdi-robot-outline"
          :title="$t('nav.agentSessions')"
          data-testid="nav-agent-sessions"
        />
        <v-list-item
          v-if="caps.has('hive') && hiveServed"
          :to="`/tenant/${tenantId}/memory`"
          prepend-icon="mdi-brain"
          :title="$t('nav.agentMemory')"
          data-testid="nav-agent-memory"
        />
        <!-- FR-90 P2h-2 — where sessions are copied: only where the server
             copies them at all (`hive.replicaset`, off by default). -->
        <v-list-item
          v-if="caps.has('hive') && hiveServed && hiveCopied"
          :to="`/tenant/${tenantId}/copies`"
          prepend-icon="mdi-content-copy"
          :title="$t('nav.agentCopies')"
          data-testid="nav-agent-copies"
        />
        <!-- Devices-first (2026-08-26): the flat Devices item became a
             collapsible group listing the fleet's AGENTS (a tap lands in the
             remote view; tunnel clients have none, so they live only on the
             /devices page the header icon opens). Server-searchable with a
             20-row cap + load-more; rows are a live view over
             agentStore.agents so device:presence keeps the dots honest. -->
        <v-list-group v-if="showFleetNav" value="devices" class="nav-entity-group">
          <template #activator="{ props: groupProps }">
            <v-list-item v-bind="groupProps" prepend-icon="mdi-monitor-multiple" :title="$t('nav.devices')">
              <template #append>
                <v-btn
                  icon="mdi-view-grid-outline"
                  size="x-small"
                  variant="text"
                  :to="`/tenant/${tenantId}/devices`"
                  title="Open the devices page"
                  aria-label="Open the devices page"
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
            aria-label="Search devices"
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
              <v-icon
                size="x-small"
                :color="d.presence === 'online' ? 'success' : d.presence === 'stale' ? 'warning' : 'grey'"
              >
                mdi-circle
              </v-icon>
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
        <v-list-group v-if="showFleetNav && caps.has('network')" value="network">
          <template #activator="{ props: groupProps }">
            <v-list-item v-bind="groupProps" prepend-icon="mdi-lan" :title="$t('nav.network')" />
          </template>
          <!-- 2026-08-04 — Machines + Tunnel clients folded into Devices;
               ACL is ONE entry (a tabbed page hosting Overlay + Tunnel —
               the standalone Overlay ACL page was reachable from NO nav). -->
          <v-list-item :to="`/tenant/${tenantId}/network/acl`" prepend-icon="mdi-shield-key" :title="$t('nav.tunnelAcl')" />
          <v-list-item :to="`/tenant/${tenantId}/network/subnet-routes`" prepend-icon="mdi-lan-connect" :title="$t('nav.subnetRoutes')" />
          <v-list-item :to="`/tenant/${tenantId}/network/dns`" prepend-icon="mdi-dns" :title="$t('nav.magicDns')" />
        </v-list-group>
        <!-- The old flat "Your rooms" list, as a collapsible group: server-
             searchable, first 20 + load-more. Rows keep the unread badges;
             the header carries the total so a collapsed group still shows
             there's something unread. The list under an EMPTY query is a
             SLICE of roomStore.rooms — that store list stays complete
             (dashboard tiles, the app-bar call menu and updateRoomCallStatus
             iterate it), the cap is presentational only. -->
        <v-list-group v-if="caps.has('chat')" value="rooms" class="nav-entity-group">
          <template #activator="{ props: groupProps }">
            <v-list-item v-bind="groupProps" prepend-icon="mdi-pound" :title="$t('nav.rooms')">
              <template #append>
                <v-badge
                  v-if="roomStore.totalUnread > 0"
                  :content="roomStore.totalUnread"
                  color="error"
                  inline
                />
                <v-btn
                  icon="mdi-view-grid-outline"
                  size="x-small"
                  variant="text"
                  :to="`/tenant/${tenantId}/rooms`"
                  title="Open the rooms page"
                  aria-label="Open the rooms page"
                  @click.stop
                />
              </template>
            </v-list-item>
          </template>
          <!-- Explore lives INSIDE Rooms now (the Collaboration group is
               gone) — it's "find rooms you're not in", the natural sibling
               of the room list below the divider. -->
          <v-list-item
            :to="`/tenant/${tenantId}/explore`"
            prepend-icon="mdi-compass"
            :title="$t('nav.explore')"
            density="compact"
          />
          <v-divider class="my-1" />
          <v-text-field
            v-if="!railActive"
            v-model="roomNav.query.value"
            density="compact"
            variant="solo-filled"
            flat
            hide-details
            clearable
            prepend-inner-icon="mdi-magnify"
            :placeholder="$t('common.search')"
            class="mx-2 my-1 nav-search"
            aria-label="Search rooms"
          />
          <v-list-item
            v-for="room in roomNav.items.value"
            :key="room.id"
            :to="`/tenant/${tenantId}/room/${room.id}`"
            :title="room.name"
            :prepend-icon="room.has_media && caps.has('conference') ? 'mdi-video' : 'mdi-pound'"
            density="compact"
          >
            <template #append>
              <v-badge
                v-if="(roomStore.unreadCounts[room.id] || 0) > 0"
                :content="roomStore.unreadCounts[room.id]"
                color="error"
                inline
              />
            </template>
          </v-list-item>
          <v-list-item
            v-if="roomNav.searching.value"
            density="compact"
            :title="$t('common.loading')"
            disabled
          />
          <v-list-item
            v-else-if="roomNav.hasMore.value"
            density="compact"
            class="text-medium-emphasis"
            :title="$t('common.loadMore')"
            prepend-icon="mdi-chevron-down"
            @click="roomNav.loadMore()"
          />
        </v-list-group>
        <v-list-item
          v-if="caps.has('chat')"
          :to="`/tenant/${tenantId}/files`"
          prepend-icon="mdi-folder"
          :title="$t('nav.files')"
        />
        <!-- Top-level again (2026-08-26): the S4 IA pivot demoted Invites
             into a collapsible group and users read that as "the invite
             page disappeared". FAIL-CLOSED gate (canManageInvites) — the
             list endpoint needs INVITE_MEMBERS, so this item must never
             show for a caller who can't make the request it leads to.
             (It used to say "the api client logs out on GET 403". It no
             longer does — FR-82 — so this is UX, not session safety.) -->
        <v-list-item
          v-if="canInvite"
          :to="`/tenant/${tenantId}/invites`"
          prepend-icon="mdi-account-plus"
          :title="$t('nav.invites')"
        />

        <!-- ── Insights section ─────────────────────────────────── -->
        <v-divider v-if="showAnalyticsNav || isPlatformAdmin" class="my-1" />
        <!-- Analytics (stats PR-4): FAIL-CLOSED gating (canQueryAnalytics)
             — the stats query endpoints 404 without MANAGE_AGENTS, so this
             nav never leads a plain member to a page whose every panel
             comes back empty. (FR-82: no longer a logout risk.) -->
        <v-list-item
          v-if="showAnalyticsNav"
          :to="`/tenant/${tenantId}/analytics`"
          prepend-icon="mdi-chart-areaspline"
          :title="$t('nav.analytics')"
        />
        <!-- Platform observability (stats PR-4): visible only to the
             platform-operator allowlist; the server 404s everyone else. -->
        <v-list-item
          v-if="isPlatformAdmin"
          to="/observability"
          prepend-icon="mdi-chart-timeline-variant-shimmer"
          :title="$t('nav.observability')"
        />
        <!-- FR-102 — the growth digest, same allowlist, same 404. -->
        <v-list-item
          v-if="isPlatformAdmin"
          to="/observability/growth"
          prepend-icon="mdi-sprout"
          :title="$t('nav.growth')"
        />

        <!-- ── Administration section ───────────────────────────── -->
        <v-divider class="my-1" />
        <!-- Settings left the group (2026-08-26) — it stays reachable via
             the drawer-footer Settings entry; the group holds the people/
             money residue. -->
        <v-list-group value="admin">
          <template #activator="{ props: groupProps }">
            <v-list-item v-bind="groupProps" prepend-icon="mdi-cog" :title="$t('nav.admin')" />
          </template>
          <v-list-item :to="`/tenant/${tenantId}/admin/members`" prepend-icon="mdi-account-group" :title="$t('nav.members')" />
          <v-list-item :to="`/tenant/${tenantId}/admin/roles`" prepend-icon="mdi-shield-account" :title="$t('nav.roles')" />
          <v-list-item v-if="caps.has('saas')" :to="`/tenant/${tenantId}/billing`" prepend-icon="mdi-credit-card" :title="$t('nav.billing')" />
        </v-list-group>
        <!-- Audit trails, out of Admin/Settings (2026-08-26). FAIL-CLOSED
             per item on the SERVER's own bit split (VIEW_EXEC_AUDIT vs
             VIEW_SSH_AUDIT — reviewing commands and reviewing SSH sessions
             are different jobs); the group shows when either applies. -->
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
        <v-list-item :to="{ path: '/my-devices', query: route.query.desktop === '1' ? { desktop: '1' } : {} }" prepend-icon="mdi-account-multiple" title="My devices &amp; sharing" data-testid="personal-devices-nav" />
        <v-list-item :to="{ path: '/device-shares', query: route.query.desktop === '1' ? { desktop: '1' } : {} }" prepend-icon="mdi-share-variant" title="Device shares" data-testid="device-shares-nav" />
      </v-list>

      <!-- Central approval is global; never hide it behind tenant membership. -->
      <v-list v-if="accountApproval.isOwner" density="compact">
        <v-list-item to="/account-approval" prepend-icon="mdi-account-check" title="Account approvals" data-testid="account-approval-nav" />
      </v-list>

      <template #append>
        <!-- Mini conference widget (visible when in call but navigated away) -->
        <mini-conference
          v-if="conferenceStore.isInCall && !isOnCallPage"
        />
        <!-- Pulsing phone icon in rail mode when in call -->
        <v-list v-if="railActive && conferenceStore.isInCall" density="compact">
          <v-list-item
            prepend-icon="mdi-phone"
            class="call-indicator"
            @click="returnToCall"
          >
            <v-badge dot color="success" />
          </v-list-item>
        </v-list>
        <v-list density="compact">
          <v-list-item
            prepend-icon="mdi-cog"
            title="Settings"
            :to="settingsRoute"
          />
        </v-list>
      </template>
    </v-navigation-drawer>

    <v-app-bar density="compact" flat>
      <template #prepend>
        <!-- The drawer is closed on a phone, so what it signals has to reach
             the bar: the dot says another org has unread activity (the
             switcher row's own dot sits inside the drawer). -->
        <v-badge
          v-if="mobile"
          dot
          color="error"
          :model-value="orgBadges.anyForeignActivity(tenantStore.current?.id ?? null)"
          offset-x="10"
          offset-y="10"
        >
          <v-app-bar-nav-icon aria-label="Menu" @click="drawer = !drawer" />
        </v-badge>
      </template>
      <v-app-bar-title class="app-bar-title-truncate">
        {{ pageTitle }}
      </v-app-bar-title>

      <template #append>
        <!-- A phone's bar holds ☰ · title · search · bell · avatar, plus
             these two indicators as icons with a badge (their text versions
             alone cost ~125 px). Past that budget the avatar menu — and
             Logout with it — was pushed off-screen. -->
        <!-- YOUR call, on a phone, off the call page. The desktop drawer's
             MiniConference carries mute / camera / hang up; on a phone the
             drawer is closed, so a call kept running with a live mic and
             nothing on screen saying so (the indicator next to this one
             deliberately lists only OTHER rooms' calls). -->
        <v-menu v-if="mobile && conferenceStore.isInCall && route.name !== 'room-call'">
          <template #activator="{ props: inCallProps }">
            <v-btn
              v-bind="inCallProps"
              icon
              size="small"
              variant="flat"
              color="success"
              class="call-pulse mr-1"
              data-testid="in-call-menu"
              :aria-label="conferenceStore.isMuted ? 'In a call, muted — call controls' : 'In a call — call controls'"
            >
              <v-icon>{{ conferenceStore.isMuted ? 'mdi-microphone-off' : 'mdi-phone-in-talk' }}</v-icon>
            </v-btn>
          </template>
          <v-list density="compact" min-width="220">
            <v-list-subheader>{{ conferenceStore.roomName || 'Call' }}</v-list-subheader>
            <v-list-item prepend-icon="mdi-arrow-expand" title="Return to call" @click="returnToCall" />
            <v-list-item
              :prepend-icon="conferenceStore.isMuted ? 'mdi-microphone-off' : 'mdi-microphone'"
              :title="conferenceStore.isMuted ? 'Unmute' : 'Mute'"
              @click="conferenceStore.toggleMute()"
            />
            <v-list-item
              :prepend-icon="conferenceStore.isVideoOn ? 'mdi-video' : 'mdi-video-off'"
              :title="conferenceStore.isVideoOn ? 'Turn camera off' : 'Turn camera on'"
              @click="conferenceStore.toggleVideo()"
            />
            <v-divider />
            <v-list-item prepend-icon="mdi-phone-hangup" title="Hang up" base-color="error" @click="hangUp" />
          </v-list>
        </v-menu>
        <!-- Active call indicator -->
        <v-menu v-if="activeCallRooms.length > 0">
          <template #activator="{ props: callMenuProps }">
            <v-btn
              v-if="xs"
              v-bind="callMenuProps"
              icon
              size="small"
              variant="tonal"
              color="success"
              class="call-pulse mr-1"
              :aria-label="`${activeCallRooms.length} active call${activeCallRooms.length !== 1 ? 's' : ''}`"
            >
              <v-badge :content="activeCallRooms.length" color="success" floating>
                <v-icon>mdi-phone-ring</v-icon>
              </v-badge>
            </v-btn>
            <v-btn
              v-else
              v-bind="callMenuProps"
              size="small"
              variant="tonal"
              color="success"
              class="call-pulse mr-2"
            >
              <v-icon start>mdi-phone-ring</v-icon>
              {{ activeCallRooms.length }}
            </v-btn>
          </template>
          <v-list density="compact">
            <v-list-subheader>Active Calls</v-list-subheader>
            <v-list-item
              v-for="room in activeCallRooms"
              :key="room.id"
              :title="room.name"
              :subtitle="`${room.participant_count} participant${room.participant_count !== 1 ? 's' : ''}`"
              prepend-icon="mdi-video"
              @click="router.push({ name: 'room-call', params: { tenantId: tenantId, roomId: room.id } })"
            />
          </v-list>
        </v-menu>
        <!-- Unread messages indicator -->
        <template v-if="roomStore.totalUnread > 0">
          <v-btn
            v-if="xs"
            icon
            size="small"
            variant="tonal"
            color="error"
            class="mr-1"
            :aria-label="`${roomStore.totalUnread} unread message${roomStore.totalUnread !== 1 ? 's' : ''}`"
            @click="goToFirstUnread"
          >
            <v-badge :content="roomStore.totalUnread" color="error" floating>
              <v-icon>mdi-message-badge</v-icon>
            </v-badge>
          </v-btn>
          <v-btn
            v-else
            size="small"
            variant="tonal"
            color="error"
            class="mr-2"
            @click="goToFirstUnread"
          >
            <v-icon start>mdi-message-badge</v-icon>
            {{ roomStore.totalUnread }}
          </v-btn>
        </template>
        <v-btn icon="mdi-magnify" size="small" aria-label="Search" @click="showSearch = true" />
        <!-- FR-12 — the tour, reachable forever (not only at first login).
             Below 600 px it lives in the avatar menu only (it is already
             there), to keep the bar inside a phone's width. -->
        <v-btn
          v-if="tenantId"
          icon="mdi-help-circle-outline"
          size="small"
          class="d-none d-sm-inline-flex"
          :title="$t('nav.tutorial')"
          :aria-label="$t('nav.tutorial')"
          :to="{ name: 'tutorial', params: { tenantId } }"
        />
        <!-- The theme toggle's phone fallback is in the avatar menu. -->
        <v-btn
          :icon="isDark ? 'mdi-weather-sunny' : 'mdi-weather-night'"
          size="small"
          class="d-none d-sm-inline-flex"
          :aria-label="isDark ? 'Light mode' : 'Dark mode'"
          @click="toggleTheme"
        />
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
            <v-list-item prepend-icon="mdi-account" title="Profile" @click="goToProfile" />
            <v-list-item
              v-if="tenantId"
              prepend-icon="mdi-school-outline"
              :title="$t('nav.tutorial')"
              :to="{ name: 'tutorial', params: { tenantId } }"
            />
            <!-- FR-60 — the public docs. `href`, not `:to`: /docs is static
                 HTML served by nginx, not a route in this router, so a
                 router-link would land on the 404 view. New tab, because
                 leaving the app mid-task to read a reference page is not
                 what someone opening docs wants. -->
            <v-list-item
              prepend-icon="mdi-book-open-variant"
              title="Documentation"
              :href="appPath('/docs/')"
              target="_blank"
              rel="noopener"
            />
            <!-- The bar's theme toggle, below 600 px where the bar has no
                 room for it. -->
            <v-list-item
              v-if="xs"
              :prepend-icon="isDark ? 'mdi-weather-sunny' : 'mdi-weather-night'"
              :title="isDark ? 'Light mode' : 'Dark mode'"
              @click="toggleTheme"
            />
            <v-list-item prepend-icon="mdi-logout" title="Logout" @click="handleLogout" />
          </v-list>
        </v-menu>
      </template>
    </v-app-bar>

    <v-alert
      v-if="wsStore.status === 'connecting'"
      type="warning"
      density="compact"
      variant="tonal"
      closable
      class="ws-status-banner"
    >
      Connecting...
    </v-alert>
    <v-alert
      v-else-if="wsStore.status === 'disconnected'"
      type="error"
      density="compact"
      variant="tonal"
      closable
      class="ws-status-banner"
    >
      Disconnected. Reconnecting...
    </v-alert>

    <v-main ref="mainRef" class="app-main-no-scroll">
      <!-- #1631 — keyed by `meta.remountOn` so the remote viewer follows the
           device in the URL; every other route keeps the plain reuse. -->
      <keyed-router-view />
    </v-main>

    <!-- FR-12 P2 — one mount point for spotlight tours. It lives here rather
         than in each page because a tour is STARTED from somewhere else (the
         Tutorial, via `?tour=`), and a component cannot mount itself into a
         page it is navigating to. -->
    <spotlight-tour />

    <!-- Global search dialog -->
    <search-dialog v-model="showSearch" />

    <!-- New organization dialog (reachable from the org switcher) -->
    <v-dialog v-model="showCreateOrg" max-width="420">
      <v-card>
        <v-card-title>New organization</v-card-title>
        <v-card-text>
          <v-form ref="createOrgForm" @submit.prevent="handleCreateOrg">
            <v-text-field
              v-model="orgName"
              label="Name"
              :rules="[rules.required]"
              @update:model-value="autoSlugFromName"
            />
            <v-text-field
              v-model="orgSlug"
              label="Slug"
              hint="URL-friendly identifier, globally unique"
              :rules="[rules.required, rules.slug]"
              @update:model-value="orgSlugTouched = true"
            />
          </v-form>
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="showCreateOrg = false">Cancel</v-btn>
          <v-btn color="primary" :loading="creatingOrg" @click="handleCreateOrg">Create</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>

    <!-- Call started notification -->
    <v-snackbar v-model="callSnackbar" :timeout="8000" color="success" location="top right">
      {{ callSnackbarText }}
      <template #actions>
        <v-btn variant="text" @click="joinCallFromSnackbar">Join</v-btn>
        <v-btn variant="text" icon="mdi-close" @click="callSnackbar = false" />
      </template>
    </v-snackbar>
  </v-app>
</template>

<script setup lang="ts">
import { appPath } from '@/utils/deployment'
import { ref, computed, watch, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useTheme, useDisplay } from 'vuetify'
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
  canQueryAnalytics,
  canSeeFleetNav,
  canViewExecAudit,
  canViewSshAudit,
} from '@/utils/permissions'
import { useRoomStore, type Room } from '@/stores/rooms'
import { useAgentStore } from '@/stores/agents'
import { useCappedSearchList } from '@/composables/useCappedSearchList'
import { api } from '@/api/client'
import { useNotificationStore } from '@/stores/notification'
import { useOrgBadgesStore } from '@/stores/orgBadges'
import { useConferenceStore } from '@/stores/conference'
import { useCallControls } from '@/composables/useCallControls'
import { useWsStore } from '@/stores/ws'
import { useCapabilitiesStore } from '@/stores/capabilities'
import { useHiveStore } from '@/stores/hive'
import { useMessageStore } from '@/stores/messages'
import NotificationPanel from '@/components/layout/NotificationPanel.vue'
import KeyedRouterView from '@/components/layout/KeyedRouterView.vue'
import MiniConference from '@/components/conference/MiniConference.vue'
import SearchDialog from '@/components/layout/SearchDialog.vue'
import { useSnackbar } from '@/composables/useSnackbar'
import { useValidation } from '@/composables/useValidation'
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
// Wave 2 — route-change beacon for the platform analytics. Installed
// once here, in the authenticated shell, so it never runs for logged-out
// visitors (landing / auth pages live outside this layout).
usePageViews()
const tenantStore = useTenantStore()
const roomStore = useRoomStore()
const notificationStore = useNotificationStore()
const orgBadges = useOrgBadgesStore()
const conferenceStore = useConferenceStore()
const { returnToCall, hangUp } = useCallControls()
const wsStore = useWsStore()
// FR-69 P9 — which pillars THIS server mounts. Every nav item below that
// belongs to a module reads `caps.has(...)`: one predicate for navigation
// and routes (the router guard reads the same store), fail-open until the
// server has answered.
const caps = useCapabilitiesStore()
const route = useRoute()
// FR-12 P2 — `?tour=<id>` starts a spotlight tour on arrival. The param is
// stripped immediately: a tour is a one-time nudge, and leaving it in the URL
// would replay on every refresh and follow a shared link to someone who never
// asked for it.
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

const isOnCallPage = computed(() => route.name === 'room-call')

// Active calls across all rooms (excluding the one the user is currently in)
const activeCallRooms = computed(() =>
  roomStore.rooms.filter(
    (r) => r.conference_status === 'in_progress' && (r.participant_count || 0) > 0 && r.id !== conferenceStore.roomId,
  ),
)

function goToFirstUnread() {
  // Navigate to the first room with unread messages
  const roomId = Object.entries(roomStore.unreadCounts).find(([, count]) => count > 0)?.[0]
  if (roomId && tenantId.value) {
    router.push(`/tenant/${tenantId.value}/room/${roomId}`)
  }
}

function goToProfile() {
  if (auth.user?.id) {
    router.push({ name: 'profile', params: { userId: auth.user.id } })
  }
}

// Drawer starts CLOSED on mobile (so the hamburger button is the
// affordance to open it) and OPEN on desktop (the standard sidebar
// experience). Without this, mobile users would land with the nav
// drawer covering the page until they explicitly close it.
const drawer = ref(!mobile.value)
const rail = ref(false)
// Rail is a desktop state: a window narrowed below 1280 px after the rail
// was chosen keeps `rail` true, and every check that read it raw then hid
// the org switcher and the drawer's searches from the phone drawer.
const railActive = computed(() => !mobile.value && rail.value)

// <v-main> is the page's scroller, not the window, and it stays mounted
// across child routes — so nothing reset it, and a page opened at the
// previous page's offset (on a phone, often its bottom, its header and
// primary action out of view). The PATH only: several views rewrite their
// query or hash in place and must keep their place.
const mainRef = ref<{ $el: HTMLElement } | null>(null)
watch(
  () => route.path,
  () => mainRef.value?.$el?.scrollTo?.({ top: 0 }),
)
// S4 nav groups — Collaboration starts open (the day-to-day pages);
// Only Devices starts EXPANDED (the primary nav destination); Rooms /
// Network / Admin / Audit start collapsed. The user's toggles win afterwards.
const openGroups = ref<string[]>(['devices'])

// ── Resizable drawer ─────────────────────────────────────────────
// Default 308 ≈ Vuetify's 256 + 20%; drag the right edge, persisted.
const NAV_WIDTH_KEY = 'roomler-nav-width'
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
  // The drawer is anchored at the viewport's left edge, so the pointer's
  // clientX IS the wanted width.
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

// ── Sidebar capped lists (first 20 + load-more, server search) ──
const agentStore = useAgentStore()

interface SidebarDevice {
  id: string
  name: string
  presence: 'online' | 'stale' | 'offline'
}

// Both sidebar groups show the first 10 (+10 per "Load more"). The
// pageSize MUST match each search fn's per_page — hasMore is inferred
// from a full page.
const SIDEBAR_PAGE = 10

const roomNav = useCappedSearchList<Room>({
  all: computed(() => roomStore.rooms),
  search: (q, page) => roomStore.searchRooms(tenantId.value, q, page, SIDEBAR_PAGE),
  pageSize: SIDEBAR_PAGE,
})

const PRESENCE_RANK = { online: 0, stale: 1, offline: 2 } as const

const deviceNav = useCappedSearchList<SidebarDevice>({
  // Live view over agentStore.agents, ONLINE FIRST (then stale, then
  // offline; name-tiebroken). Because this is a computed over the store
  // that device:presence patches in place, a device coming online
  // re-sorts into the visible top-10 slice on its own — no extra wiring.
  all: computed<SidebarDevice[]>(() =>
    agentStore.agents
      .map((a) => ({
        id: a.id,
        // Display name when set, machine name otherwise — matching the
        // grid and the search-mode rows.
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
    // The unified device feed, agents only (tunnel clients have no
    // /remote). sort=status = the server's presence rank — search results
    // lead with online devices too.
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
  localStorage.setItem('roomler-theme', next)
}

// Call notification snackbar
const callSnackbar = ref(false)
const callSnackbarText = ref('')
const callSnackbarRoomId = ref('')

function onCallStarted(e: Event) {
  const detail = (e as CustomEvent).detail as { room_id: string; room_name: string }
  callSnackbarText.value = `Call started in ${detail.room_name}`
  callSnackbarRoomId.value = detail.room_id
  callSnackbar.value = true
}

function joinCallFromSnackbar() {
  callSnackbar.value = false
  if (tenantId.value && callSnackbarRoomId.value) {
    router.push({ name: 'room-call', params: { tenantId: tenantId.value, roomId: callSnackbarRoomId.value } })
  }
}

// Route param wins over the store: a deep link to /tenant/B while the
// store still says A used to point every sidebar target at A.
const tenantId = computed(
  () => (route.params.tenantId as string | undefined) || tenantStore.current?.id || '',
)

// FR-90 P1g — agent sessions may serve some organizations and not others:
// their pages show only where the server says they do.
const hive = useHiveStore()
const hiveServed = computed(() => hive.served[tenantId.value] === true)
const hiveCopied = computed(() => hive.copied[tenantId.value] === true)
watch(
  [tenantId, () => caps.has('hive')],
  ([tid, on]) => {
    if (tid && on) void hive.checkServed(tid)
  },
  { immediate: true },
)

// Route → store sync: keep tenantStore.current on the org the URL names —
// on a deep link and a reload too, where the param never changes and the org
// list lands after mount (useRouteTenantSync says why that mattered).
useRouteTenantSync(route)

// S6 — keep the WS's tenant-affinity key in sync with the active
// tenant. PR-1 made this LAZY: the store only records the key (the
// next natural dial carries it) — eagerly redialing here killed live
// rc sessions and conference calls on every org switch. The rc
// pre-flight does its own compare-and-redial for the one flow that is
// genuinely placement-critical.
watch(
  () => tenantStore.current?.id ?? null,
  (tid, prevTid) => {
    wsStore.setTenantAffinity(tid)
    // Deferred-S4 — the caller's own permission mask drives fleet-nav
    // visibility. Fail-open: nav shows until the fetch lands (see
    // canSeeFleetNav); the server still enforces every action.
    if (tid) void tenantStore.fetchMyMembership(tid)
    // Org SWITCH (not the immediate first fire — onMounted owns the
    // initial fetch): reload the sidebar's rooms + unread badges for the
    // new org; the old switcher left them showing the previous org.
    if (tid && prevTid !== undefined && prevTid !== tid && caps.has('chat')) {
      void roomStore.fetchRooms(tid).then(() => roomStore.fetchAllUnreadCounts(tid))
    }
  },
  { immediate: true },
)

// Gate the Devices page + Network group on fleet permissions
// (MANAGE_AGENTS / REMOTE_CONTROL / ADMINISTRATOR / owner). Collab +
// Admin groups stay visible for every member.
const showFleetNav = computed(
  () => caps.has('fleet') && canSeeFleetNav(tenantStore.myPermissions, tenantStore.isOwner),
)
const showAnalyticsNav = computed(() =>
  canQueryAnalytics(tenantStore.myPermissions, tenantStore.isOwner),
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

// Sidebar Devices group data + capped-list resets. A SEPARATE watcher from
// the rooms one above: this body reads `showFleetNav`, which is declared
// between the two — folding it into the earlier immediate watcher would hit
// the TDZ on first run. AppLayout never fetched agents before the group
// existed; refetching on every tenant/permission flip is idempotent.
watch(
  [tenantId, showFleetNav] as const,
  ([tid, fleet], prev) => {
    const prevTid = prev?.[0]
    if (tid && prevTid !== undefined && prevTid !== tid) {
      roomNav.reset()
      deviceNav.reset()
    }
    if (tid && fleet) void agentStore.fetchAgents(tid).catch(() => {})
  },
  { immediate: true },
)

// FR-12 — the welcome tour opens ONCE, for a user who has never seen it, in
// an org that is still empty (no devices, at most one room). Everyone else is
// never interrupted: the `?` in the app bar is the way back in.
//
// The seen-flag read comes FIRST and costs a localStorage hit, so the common
// case (already seen) bails before issuing a single request; the counts are
// only fetched for a user this can still fire for, once per app load.
let tourChecked = false
async function maybeAutoOpenTour() {
  if (tourChecked) return
  const tid = tenantId.value
  const uid = auth.user?.id
  if (!tid || !uid) return
  if (route.name === 'tutorial') return
  if (hasSeenTour(uid)) {
    tourChecked = true
    return
  }
  // The device count needs the fleet surfaces; without it there is no
  // evidence the org is fresh, and we never navigate on a guess.
  if (!showFleetNav.value) return
  tourChecked = true
  try {
    await Promise.all([
      agentStore.fetchAgents(tid),
      roomStore.rooms.length || !caps.has('chat') ? Promise.resolve() : roomStore.fetchRooms(tid),
    ])
  } catch {
    return
  }
  if (
    !shouldAutoOpenTour({
      userId: uid,
      devices: agentStore.total,
      rooms: roomStore.rooms.length,
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

const pageTitle = computed(() => {
  const name = route.name as string
  if (name === 'my-devices') return 'My devices & sharing'
  if (name === 'device-shares' || name === 'shared-remote') return 'Device shares'
  if (name === 'account-approval') return 'Account approvals'
  if (name === 'room-chat') return 'Chat'
  if (name === 'room-call') return 'Call'
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
  // P4 — visiting an org acknowledges its badges (device-attention dot
  // clears; counts re-sync from the summary endpoint).
  orgBadges.clearForTenant(t.id)
  // Navigate — the pre-2026-08 switcher only mutated the store, leaving
  // the URL, sidebar targets and room list on the previous org.
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
    const msg = e instanceof Error ? e.message : 'Failed to create organization'
    // tenants.slug is globally unique — surface the dup-key case in words.
    showCreateOrgError(
      msg.includes('duplicate') || msg.includes('E11000')
        ? 'That slug is already taken — pick another'
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

// WS came back after a drop: pushes that would have arrived meanwhile are
// gone — refetch rooms (call badges), unread counts, and the open room's
// messages so the UI converges without a manual reload.
async function onWsReconnected() {
  // P4 — cross-org badges converge by refetch (no event replay).
  orgBadges.fetchSummary()
  if (!tenantId.value) return
  // Sidebar search state is stale relative to the wholesale refetches below.
  roomNav.reset()
  deviceNav.reset()
  if (showFleetNav.value) void agentStore.fetchAgents(tenantId.value).catch(() => {})
  // FR-69 P9 — rooms, unread counts and messages are the chat module's; a
  // server without it has nothing to refetch (and would answer 404).
  if (!caps.has('chat')) return
  await roomStore.fetchRooms(tenantId.value)
  roomStore.fetchAllUnreadCounts(tenantId.value)
  const messageStore = useMessageStore()
  if (messageStore.currentRoomId) {
    messageStore.fetchMessages(tenantId.value, messageStore.currentRoomId)
  }
}

onMounted(async () => {
  await tenantStore.fetchTenants()
  notificationStore.fetchUnreadCount()
  orgBadges.fetchSummary()
  window.addEventListener('room:call_started', onCallStarted)
  window.addEventListener('keydown', onSearchShortcut)
  window.addEventListener('ws:reconnected', onWsReconnected)
  // Fetch rooms and unread counts for current tenant — the chat module's;
  // skipped where the server does not mount it (FR-69 P9).
  if (tenantId.value && caps.has('chat')) {
    await roomStore.fetchRooms(tenantId.value)
    roomStore.fetchAllUnreadCounts(tenantId.value)
  }
})

onUnmounted(() => {
  window.removeEventListener('room:call_started', onCallStarted)
  window.removeEventListener('keydown', onSearchShortcut)
  window.removeEventListener('ws:reconnected', onWsReconnected)
})
</script>

<style scoped>
/* The brand row: the lockup (symbol + wordmark) at the row's icon height. */
.app-brand-logo {
  display: block;
  height: 32px;
  width: auto;
}

/* The nav's scrollbar was the OS default — thick and permanently visible
   once Devices is expanded. Thin overlay style instead, thumb shown only
   while the pointer is over the drawer. The 6px webkit width stays
   reserved even when the thumb is transparent, so nothing shifts on
   hover. */
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

/* Drag strip on the drawer's right edge (resizable nav). */
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

/* Devices/Rooms group children: replace Vuetify's group indent so the row's
   PREPEND icon (presence dot / room hash) sits in a vertical line with the
   MAGNIFY icon inside the search field above: field box starts at 16px
   (8px nav-list pad + mx-2 8px) and the solo field pads its prepend-inner
   icon a further 12px (--v-field-padding-start) → icon column at ~28px.
   Items carry the 8px list pad, so 20px inline padding lands there. */
.nav-entity-group :deep(.v-list-group__items .v-list-item) {
  padding-inline-start: 20px !important;
}

/* Neutralize the inner v-application__wrap's min-height: 100vh
   so the layout is constrained to the viewport height provided by the OUTER v-app in App.vue */
.app-layout-root :deep(.v-application__wrap) {
  min-height: 0 !important;
  flex: 1 1 0 !important;
  overflow: hidden;
  height: 100%;
}

/* Make v-main a flex column container so router-view children can fill it,
   and prevent it from growing beyond available space. Use overflow-y: auto
   (rather than hidden) so list-style views — admin / rooms / files / invites
   / billing — get a natural page scrollbar when their content exceeds the
   viewport. Chat / conference views set their own `overflow: hidden` on the
   inner root so their internal scroll containers (`flex-grow-1
   overflow-y-auto` on the message list) keep working unchanged.
   Note: Vuetify 3 does NOT render .v-main__wrap — slot content goes directly in <main>. */
/* overflow-x: the page never scrolls sideways — a wide table scrolls in its
   own box. The house padding (pa-2, 8 px) is narrower than a v-row's
   gutters (12 px), so every page with a row overflowed by 4 px and swayed
   sideways under a finger (FR-116). */
.app-main-no-scroll {
  overflow-y: auto !important;
  overflow-x: hidden !important;
  flex: 1 1 0 !important;
  min-height: 0 !important;
  display: flex !important;
  flex-direction: column !important;
}

.ws-status-banner {
  flex: 0 0 auto;
  border-radius: 0;
}
.call-pulse {
  animation: pulse-green 2s ease-in-out infinite;
}
@keyframes pulse-green {
  0%, 100% { box-shadow: 0 0 0 0 rgba(76, 175, 80, 0.4); }
  50% { box-shadow: 0 0 0 8px rgba(76, 175, 80, 0); }
}
.app-bar-title-truncate {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
</style>
