<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-card>
    <!-- No title text: the hosting view's h1 already says "Devices"
         (consistent with /rooms and /analytics) — the bar holds actions only. -->
    <v-card-title class="d-flex align-center">
      <v-spacer />
      <v-btn
        prepend-icon="mdi-update"
        variant="tonal"
        size="small"
        class="mr-2 d-none d-sm-inline-flex"
        :disabled="agentStore.agents.length === 0"
        @click="updateAllDialogOpen = true"
      >
        {{ $t('mh.dev.updateAll') }}
      </v-btn>
      <!-- The phone fallback (docs/ui.md: a toolbar item hidden below sm
           keeps a way in): the same action, icon-only. -->
      <v-btn
        icon="mdi-update"
        variant="tonal"
        size="small"
        density="comfortable"
        class="mr-2 d-sm-none"
        :disabled="agentStore.agents.length === 0"
        :aria-label="$t('mh.dev.updateAll')"
        :title="$t('mh.dev.updateAll')"
        @click="updateAllDialogOpen = true"
      />
      <!-- ONE enroll entry point for both kinds, at every width. -->
      <v-menu>
        <template #activator="{ props: menuProps }">
          <v-btn
            v-bind="menuProps"
            data-tour="enroll-button"
            prepend-icon="mdi-key-plus"
            append-icon="mdi-menu-down"
            color="primary"
            variant="flat"
            size="small"
          >
            {{ $t('mh.dev.enroll') }}
          </v-btn>
        </template>
        <v-list density="compact">
          <v-list-item prepend-icon="mdi-monitor" :title="$t('mh.dev.enrollDevice')" @click="openEnrollDialog" />
          <v-list-item prepend-icon="mdi-lan-pending" :title="$t('mh.dev.enrollTunnel')" @click="openTunnelEnrollDialog" />
        </v-list>
      </v-menu>
    </v-card-title>

    <v-card-text>
      <v-alert
        v-if="agentStore.error"
        type="error"
        variant="tonal"
        closable
        @click:close="agentStore.error = null"
        class="mb-4"
      >
        {{ agentStore.error }}
      </v-alert>

      <!-- S1a — forced-update feedback (delivered / offline counts). -->
      <v-alert
        v-if="updateNotice"
        type="info"
        variant="tonal"
        closable
        @click:close="updateNotice = null"
        class="mb-4"
      >
        {{ updateNotice }}
      </v-alert>

      <!-- ONE toolbar for the grid and the cards: the same search, the same
           kind filter and the same count at every width. Phones used to get
           none of it (an unsearchable list of every device, then a separate
           tunnel-clients table). -->
      <div class="d-flex align-center mb-2 flex-wrap" :class="{ 'ga-2': mobile }">
        <v-text-field
          v-model="gridSearch"
          data-tour="device-search"
          density="compact"
          variant="outlined"
          hide-details
          clearable
          prepend-inner-icon="mdi-magnify"
          :placeholder="$t('mh.dev.searchPlaceholder')"
          :class="mobile ? 'device-search--full' : undefined"
          :style="mobile ? undefined : 'max-width: 340px'"
          :aria-label="$t('mh.dev.searchAria')"
        />
        <!-- Kind filter. Default = devices WITHOUT tunnel clients — the
             remote-desktop fleet is what this page is about day-to-day;
             tunnels are one radio away. Server-side (`kind` param). -->
        <v-radio-group
          v-model="gridKind"
          inline
          hide-details
          density="compact"
          :class="mobile ? 'flex-grow-0' : 'ml-4 flex-grow-0'"
          :aria-label="$t('mh.dev.kindAria')"
        >
          <v-radio :label="$t('mh.dev.kindDevices')" value="agent" density="compact" />
          <v-radio :label="$t('mh.dev.kindTunnels')" value="tunnel_client" density="compact" />
          <v-radio :label="$t('mh.dev.kindBoth')" value="both" density="compact" />
        </v-radio-group>
        <v-spacer />
        <span class="text-caption text-medium-emphasis mr-2">
          {{ gridKind === 'tunnel_client' ? $t('mh.dev.countTunnels', { n: deviceStore.total }, deviceStore.total) : $t('mh.dev.countDevices', { n: deviceStore.total }, deviceStore.total) }}
        </span>
        <!-- Columns are a grid concept; the cards have none. -->
        <v-btn
          v-if="!mobile"
          icon="mdi-cog-outline"
          size="small"
          variant="text"
          :color="colsCustomized ? 'primary' : undefined"
          :title="$t('mh.dev.configureColumns')"
          :aria-label="$t('mh.dev.configureColumns')"
          @click="colDialogOpen = true"
        />
      </div>

      <!-- Desktop / landscape tablet (≥ md): the UNIFIED server-driven grid —
           agents + tunnel clients in ONE v-data-table-server. Search / sort /
           pagination run on the SERVER (GET /tenant/{tid}/device — q matches
           across the overlay join incl. IP + MagicDNS), and column
           visibility/order are per-user (useGridColumns → localStorage).
           The grid rows are the lean DeviceRow feed; rich agent-only cells
           (consent, codecs, the action menu) look the full Agent up from
           agentStore by id. Action column stays LEFTMOST so it never falls
           off the right edge (field bug 2026-05-01). Below md the SAME rows
           render as cards further down. -->
      <template v-if="!mobile">
        <v-data-table-server
          data-tour="device-grid"
          v-model:page="gridPage"
          v-model:items-per-page="gridPerPage"
          :headers="effectiveHeaders"
          :items="deviceStore.items"
          :items-length="deviceStore.total"
          :loading="deviceStore.loading"
          :items-per-page-options="[10, 25, 50, 100]"
          density="compact"
          class="agents-table"
          item-value="id"
          @update:options="onGridOptions"
        >
          <template #item.actions="{ item }">
            <div class="agents-actions-col d-flex align-center">
              <v-btn
                v-if="item.kind === 'agent'"
                icon="mdi-remote-desktop"
                size="small"
                variant="text"
                color="primary"
                :disabled="!item.is_online"
                :to="{ name: 'agent-remote', params: { tenantId, agentId: item.id } }"
                :aria-label="$t('mh.dev.connectTo', { name: deviceLabel(item) })"
              />
              <DeviceActionsMenu
                :tenant-id="tenantId"
                :row="item"
                :agent="agentFor(item)"
                :client="clientFor(item)"
                :node="nodeFor(item)"
                :network-mounted="caps.has('network')"
                :update-busy="updateBusy === item.id"
                :rotate-key-busy="rotateKeyBusy === item.id"
                :update-blocked="updateBlockedText(agentFor(item))"
                @action="(a: DeviceAction) => onDeviceAction(item, a)"
              />
            </div>
          </template>
          <template #item.name="{ item }">
            <div class="d-flex align-center">
              <v-icon
                :color="rowPresenceColor(item)"
                size="small"
                class="mr-2"
                :title="rowPresenceTitle(item)"
              >
                {{ rowPresenceIcon(item) }}
              </v-icon>
              <span class="font-weight-medium">{{ deviceLabel(item) }}</span>
              <!-- FR-51 — the vanishing must never be a surprise: this device
                   removes itself (reaped after silence; immediately on a clean
                   stop), and a later enrollment is a NEW device. -->
              <v-chip
                v-if="item.ephemeral"
                size="x-small"
                color="warning"
                variant="tonal"
                class="ml-2"
                prepend-icon="mdi-clock-fast"
                :title="$t('mh.dev.ephemeralTitle')"
              >
                {{ $t('mh.dev.ephemeral') }}
              </v-chip>
              <v-btn
                :icon="copiedAgentId === item.id ? 'mdi-check' : 'mdi-content-copy'"
                size="x-small"
                variant="text"
                :color="copiedAgentId === item.id ? 'success' : undefined"
                class="ml-1"
                @click="copyAgentId(item.id)"
                :aria-label="$t('mh.dev.copyIdFor', { name: deviceLabel(item) })"
                :title="copiedAgentId === item.id ? $t('mh.dev.copied') : $t('mh.dev.copyId')"
              />
            </div>
            <div class="text-caption text-medium-emphasis d-flex align-center flex-nowrap">
              <!-- The machine-reported title collapses away by default once a
                   display name is set (column-picker checkbox; the remote
                   page reads the same preference). -->
              <span v-if="secondaryDeviceName(item, hideNameWhenDisplay)" class="mr-1">{{ item.name }} ·</span>
              <span class="agent-id-preview" :title="$t('mh.dev.deviceIdTitle', { id: item.id })">
                id: {{ shortId(item.id) }}
              </span>
              <span class="mx-1">·</span>
              <span :title="`machine_id: ${item.machine_id}`">{{ shortId(item.machine_id) }}</span>
              <span v-if="item.version"> · v{{ item.version }}</span>
              <!-- FR-27 — the companion's own version, and only when it
                   DISAGREES with the daemon's. Shown at all because the two
                   update by different mechanisms on every platform, so
                   "Update all" moving the daemon says nothing about the
                   desktop; hidden when they match because a second identical
                   number on every row is noise, and the whole point of the
                   field is the disagreement. -->
              <span
                v-if="companionSkew(item)"
                class="companion-skew ml-1"
                :title="$t('mh.dev.skewTitleLong', { desktop: companionSkew(item), daemon: item.version })"
              >
                · {{ $t('mh.dev.desktopVersion', { v: companionSkew(item) }) }}
              </span>
              <!-- FR-100 P1a — the device's own key, as a person reads it, so
                   what a browser pins can be checked against this list. Absent
                   until the device sends one. -->
              <span
                v-if="item.kind === 'agent' && agentFor(item)?.peer_auth_fingerprint"
                class="ml-1 text-mono"
                :title="$t('mh.dev.keyFingerprintTitle', { fp: agentFor(item)!.peer_auth_fingerprint })"
              >
                · {{ $t('mh.dev.keyShort') }} {{ agentFor(item)!.peer_auth_fingerprint!.slice(0, 9) }}…
              </span>
            </div>
          </template>
          <template #item.kind="{ item }">
            <v-chip size="x-small" variant="tonal" :color="item.kind === 'agent' ? 'primary' : 'secondary'">
              {{ item.kind === 'agent' ? $t('mh.dev.kindDevice') : $t('mh.dev.kindTunnel') }}
            </v-chip>
          </template>
          <template #item.status="{ item }">
            <v-chip
              size="small"
              :color="rowStatusColor(item)"
              variant="flat"
              :title="rowPresenceTitle(item)"
            >
              {{ rowStatusLabel(item) }}
            </v-chip>
            <!-- FR-103 — only when the device's credential needs someone. -->
            <v-chip
              v-if="item.kind === 'agent' && agentFor(item) && credentialChip(agentFor(item)!.token_expires_at)"
              size="x-small"
              variant="tonal"
              class="mt-1"
              prepend-icon="mdi-key-alert"
              :color="credentialChip(agentFor(item)!.token_expires_at)!.color"
              :title="credentialChip(agentFor(item)!.token_expires_at)!.tooltip"
            >
              {{ credentialChip(agentFor(item)!.token_expires_at)!.text }}
            </v-chip>
            <!-- FR-106 — only when an online device has not installed a
                 release that has been out for a day. -->
            <v-chip
              v-if="item.kind === 'agent' && agentFor(item) && stallChip(agentFor(item)!)"
              size="x-small"
              variant="tonal"
              class="mt-1"
              prepend-icon="mdi-update"
              :color="stallChip(agentFor(item)!)!.color"
              :title="stallChip(agentFor(item)!)!.tooltip"
              data-testid="agent-update-stall-chip"
            >
              {{ stallChip(agentFor(item)!)!.text }}
            </v-chip>
            <v-chip
              v-if="item.kind === 'agent' && agentFor(item) && remoteConfigChip(agentFor(item)!)"
              size="x-small"
              variant="tonal"
              class="mt-1"
              :color="remoteConfigChip(agentFor(item)!)!.color"
              :prepend-icon="remoteConfigChip(agentFor(item)!)!.icon"
              :title="remoteConfigChip(agentFor(item)!)!.tooltip"
              @click="openRemoteConfig(agentFor(item)!)"
            >
              {{ remoteConfigChip(agentFor(item)!)!.text }}
            </v-chip>
            <v-chip
              v-if="item.kind === 'agent' && agentFor(item) && keyRotationChip(agentFor(item)!)"
              size="x-small"
              variant="tonal"
              class="mt-1"
              :color="keyRotationChip(agentFor(item)!)!.color"
              :prepend-icon="keyRotationChip(agentFor(item)!)!.icon"
              :title="keyRotationChip(agentFor(item)!)!.tooltip"
            >
              {{ keyRotationChip(agentFor(item)!)!.text }}
            </v-chip>
          </template>
          <template #item.os="{ item }">
            <v-chip size="x-small" :prepend-icon="osIcon(item.os as any)" variant="tonal">
              {{ item.os }}
            </v-chip>
          </template>
          <template #item.overlay_ip="{ item }">
            <template v-if="item.overlay_ip">
              <div class="text-caption text-mono">{{ item.overlay_ip }}</div>
              <div
                class="text-caption text-medium-emphasis text-mono"
                :title="deriveOverlayV6(item.overlay_ip) ?? undefined"
              >
                {{ deriveOverlayV6(item.overlay_ip) }}
              </div>
              <!-- FR-40 — the node's public key, so a rotation is visible as a
                   changed key rather than trusted from a chip. -->
              <div
                v-if="item.overlay_public_key"
                class="text-caption text-medium-emphasis text-mono"
                :title="$t('mh.dev.overlayKeyTitle', { epoch: item.overlay_key_epoch ?? 0, key: item.overlay_public_key })"
              >
                {{ $t('mh.dev.keyShort') }} {{ item.overlay_public_key.slice(0, 10) }}… · e{{ item.overlay_key_epoch ?? 0 }}
              </div>
            </template>
            <span v-else class="text-caption text-medium-emphasis">—</span>
          </template>
          <template #item.magic_dns="{ item }">
            <div v-if="item.magic_dns_fqdn" class="d-flex align-center">
              <span class="text-caption text-mono">{{ item.magic_dns_fqdn }}</span>
              <v-btn
                :icon="copiedAgentId === item.magic_dns_fqdn ? 'mdi-check' : 'mdi-content-copy'"
                size="x-small"
                variant="text"
                class="ml-1"
                @click="copyAgentId(item.magic_dns_fqdn!)"
                :aria-label="$t('mh.dev.copyDnsFor', { name: deviceLabel(item) })"
              />
            </div>
            <span v-else-if="item.magic_dns_name" class="text-caption text-mono" :title="$t('mh.dev.noDnsDomain')">
              {{ item.magic_dns_name }}
            </span>
            <span v-else class="text-caption text-medium-emphasis">—</span>
          </template>
          <template #item.tags="{ item }">
            <div v-if="item.tags?.length" class="d-flex flex-nowrap ga-1">
              <v-chip v-for="t in item.tags.slice(0, 3)" :key="t" size="x-small" variant="tonal">
                {{ t }}
              </v-chip>
              <v-chip
                v-if="item.tags.length > 3"
                size="x-small"
                variant="tonal"
                :title="item.tags.slice(3).join(', ')"
              >
                +{{ item.tags.length - 3 }}
              </v-chip>
            </div>
            <span v-else class="text-caption text-medium-emphasis">—</span>
          </template>
          <template #item.consent="{ item }">
            <!-- FR-116 D1 — the six access controls on demand, as on a phone:
                 the row shows the policy's summary (the card's Access line)
                 and the chevron opens the controls in place. Every control
                 open kept each row ~210 px tall. -->
            <template v-if="item.kind === 'agent' && agentFor(item)">
              <button
                type="button"
                class="consent-toggle"
                :aria-expanded="consentOpen.has(item.id)"
                :data-testid="`consent-toggle-${item.id}`"
                @click="toggleConsent(item.id)"
              >
                <span class="text-body-2">{{ consentSummary(agentFor(item)!) }}</span>
                <v-icon size="small">{{ consentOpen.has(item.id) ? 'mdi-chevron-up' : 'mdi-chevron-down' }}</v-icon>
              </button>
              <DeviceAccessPolicyFields
                v-if="consentOpen.has(item.id)"
                class="mt-1"
                :agent="agentFor(item)!"
                :busy="consentBusy === item.id"
                :owned-by-me="isOwnedByMe(agentFor(item)!)"
                variant="plain"
                @consent="(m: ConsentMode) => onConsentModeChange(agentFor(item)!, m)"
                @prompt-owner="(v: boolean) => onPromptOwnerChange(agentFor(item)!, v)"
                @input-mode="(m: 'free' | 'exclusive') => onInputModeChange(agentFor(item)!, m)"
                @idle-minutes="(m: number) => onIdleMinutesChange(agentFor(item)!, m)"
                @lock-on-end="(l: LockOnEnd) => onLockOnEndChange(agentFor(item)!, l)"
                @rc-overlay="(v: boolean) => onRcOverlayChange(agentFor(item)!, v)"
              />
            </template>
            <span v-else class="text-caption text-medium-emphasis">—</span>
          </template>
          <template #item.codecs="{ item }">
            <template v-if="item.kind === 'agent' && agentFor(item)">
              <div v-if="codecChips(agentFor(item)!).length === 0" class="text-caption text-medium-emphasis">—</div>
              <div v-else-if="lgAndDown" class="d-flex flex-nowrap ga-1 align-center">
                <v-chip
                  size="x-small"
                  :color="codecChips(agentFor(item)!)[0].color"
                  variant="tonal"
                  :title="codecChips(agentFor(item)!).map(c => c.tooltip).join(', ')"
                >
                  {{ codecChips(agentFor(item)!)[0].label }}
                </v-chip>
                <v-chip
                  v-if="codecChips(agentFor(item)!).length > 1"
                  size="x-small"
                  variant="tonal"
                  :title="codecChips(agentFor(item)!).slice(1).map(c => c.tooltip).join(', ')"
                >
                  +{{ codecChips(agentFor(item)!).length - 1 }}
                </v-chip>
              </div>
              <div v-else class="d-flex flex-nowrap ga-1">
                <v-chip
                  v-for="codec in codecChips(agentFor(item)!)"
                  :key="codec.label"
                  size="x-small"
                  :color="codec.color"
                  variant="tonal"
                  :title="codec.tooltip"
                >
                  {{ codec.label }}
                </v-chip>
              </div>
              <!-- A device the OS has muzzled looks identical to a healthy one
                   until you connect and get a black screen, because macOS
                   reports success either way. Say it here instead. -->
              <div v-if="permissionWarnings(agentFor(item)!).length" class="d-flex flex-nowrap ga-1 mt-1">
                <v-chip
                  v-for="w in permissionWarnings(agentFor(item)!)"
                  :key="w.label"
                  size="x-small"
                  color="warning"
                  variant="tonal"
                  :title="w.tooltip"
                >
                  {{ w.label }}
                </v-chip>
              </div>
            </template>
            <span v-else class="text-caption text-medium-emphasis">—</span>
          </template>
          <template #item.last_seen_at="{ item }">
            <span class="text-caption" :title="fmtDate(item.last_seen_at)">{{ fmtRelative(item.last_seen_at) }}</span>
          </template>
          <template #no-data>
            <div class="text-center pa-8 text-medium-emphasis">
              <template v-if="gridSearch">
                {{ $t('mh.dev.noMatch', { q: gridSearch }) }}
              </template>
              <template v-else>
                <v-icon size="48" color="grey-lighten-1" class="mb-2">mdi-desktop-classic</v-icon>
                <p class="mb-1">{{ $t('mh.dev.noneYet') }}</p>
                <p class="text-body-2">
                  {{ $t('mh.dev.noneHint') }}
                </p>
                <!-- FR-12 — the empty state is exactly where the tour helps. -->
                <v-btn
                  size="small"
                  variant="text"
                  color="primary"
                  prepend-icon="mdi-school-outline"
                  :to="{ name: 'tutorial', params: { tenantId }, hash: '#devices' }"
                  class="mt-2"
                >
                  {{ $t('mh.dev.walkThrough') }}
                </v-btn>
              </template>
            </div>
          </template>
        </v-data-table-server>
      </template>

      <!-- Phone and portrait tablet (< md): the SAME server rows as the grid,
           as cards — the same search, kind filter, pagination and action menu,
           so a device is never named or offered differently by width. A card
           shows what identifies the device and what needs a person; its access
           policy and its technical details open on demand. (It used to list
           every device, unpaged, each card ~500 px tall with all six policy
           controls open, the machine's name where the grid shows the display
           name, and a separate 7-column tunnel-clients table below.) -->
      <div v-else data-tour="device-grid" class="device-cards">
        <div
          v-if="deviceStore.loading && deviceStore.items.length === 0"
          class="d-flex justify-center pa-8"
        >
          <v-progress-circular indeterminate />
        </div>
        <div
          v-else-if="deviceStore.items.length === 0"
          class="text-center pa-4 pa-md-6 pa-lg-8 text-medium-emphasis"
        >
          <template v-if="gridSearch">
            {{ $t('mh.dev.noMatch', { q: gridSearch }) }}
          </template>
          <template v-else>
            <v-icon size="64" color="grey-lighten-1" class="mb-2">mdi-desktop-classic</v-icon>
            <p class="mb-2">{{ $t('mh.dev.noneYet') }}</p>
            <p class="text-body-2">
              {{ $t('mh.dev.noneHint') }}
            </p>
            <v-btn
              size="small"
              variant="text"
              color="primary"
              prepend-icon="mdi-school-outline"
              :to="{ name: 'tutorial', params: { tenantId }, hash: '#devices' }"
              class="mt-2"
            >
              {{ $t('mh.dev.walkThrough') }}
            </v-btn>
          </template>
        </div>
        <v-row v-else dense>
          <v-col
            v-for="item in deviceStore.items"
            :key="`${item.kind}:${item.id}`"
            cols="12"
            sm="6"
          >
            <v-card
              variant="outlined"
              class="device-card h-100 d-flex flex-column"
              :data-testid="`device-card-${item.id}`"
            >
              <!-- Who it is: the name a person knows it by, then what the
                   machine calls itself (unless hidden), OS, version, last seen. -->
              <div class="d-flex align-start ga-2 pa-3 pb-2">
                <v-icon
                  :color="rowPresenceColor(item)"
                  size="small"
                  class="mt-1 flex-shrink-0"
                  :title="rowPresenceTitle(item)"
                >
                  {{ rowPresenceIcon(item) }}
                </v-icon>
                <div class="flex-grow-1 device-card__head">
                  <div class="font-weight-medium text-break">{{ deviceLabel(item) }}</div>
                  <div class="text-caption text-medium-emphasis text-break">
                    <span v-if="secondaryDeviceName(item, hideNameWhenDisplay)">{{ item.name }} · </span>
                    <v-icon size="x-small" :icon="osIcon(item.os)" class="mr-1" />{{ item.os }}
                    <span v-if="item.version"> · v{{ item.version }}</span>
                    <span :title="fmtDate(item.last_seen_at)"> · {{ fmtRelative(item.last_seen_at) }}</span>
                  </div>
                </div>
                <v-chip
                  size="small"
                  :color="rowStatusColor(item)"
                  variant="flat"
                  class="flex-shrink-0"
                  :title="rowPresenceTitle(item)"
                >
                  {{ rowStatusLabel(item) }}
                </v-chip>
              </div>
              <!-- What needs a person, and the device's own labels: the chips
                   the grid shows (docs/ui.md "needs a person"), never a chip
                   that is only a fact. -->
              <div v-if="cardHasChips(item)" class="d-flex flex-wrap ga-1 px-3 pb-2">
                <v-chip
                  v-if="item.kind === 'tunnel_client'"
                  size="x-small"
                  variant="tonal"
                  color="secondary"
                >
                  {{ $t('mh.dev.kindTunnel') }}
                </v-chip>
                <!-- FR-51 — the vanishing must never be a surprise. -->
                <v-chip
                  v-if="item.ephemeral"
                  size="x-small"
                  color="warning"
                  variant="tonal"
                  prepend-icon="mdi-clock-fast"
                  :title="$t('mh.dev.ephemeralTitle')"
                >
                  {{ $t('mh.dev.ephemeral') }}
                </v-chip>
                <template v-if="agentFor(item)">
                  <!-- FR-103 — only when the device's credential needs someone. -->
                  <v-chip
                    v-if="credentialChip(agentFor(item)!.token_expires_at)"
                    size="x-small"
                    variant="tonal"
                    prepend-icon="mdi-key-alert"
                    :color="credentialChip(agentFor(item)!.token_expires_at)!.color"
                    :title="credentialChip(agentFor(item)!.token_expires_at)!.tooltip"
                  >
                    {{ credentialChip(agentFor(item)!.token_expires_at)!.text }}
                  </v-chip>
                  <!-- FR-106 — the same chip as the table view's. -->
                  <v-chip
                    v-if="stallChip(agentFor(item)!)"
                    size="x-small"
                    variant="tonal"
                    prepend-icon="mdi-update"
                    :color="stallChip(agentFor(item)!)!.color"
                    :title="stallChip(agentFor(item)!)!.tooltip"
                    data-testid="agent-update-stall-chip"
                  >
                    {{ stallChip(agentFor(item)!)!.text }}
                  </v-chip>
                  <v-chip
                    v-if="remoteConfigChip(agentFor(item)!)"
                    size="x-small"
                    variant="tonal"
                    :color="remoteConfigChip(agentFor(item)!)!.color"
                    :prepend-icon="remoteConfigChip(agentFor(item)!)!.icon"
                    :title="remoteConfigChip(agentFor(item)!)!.tooltip"
                    @click="openRemoteConfig(agentFor(item)!)"
                  >
                    {{ remoteConfigChip(agentFor(item)!)!.text }}
                  </v-chip>
                  <v-chip
                    v-if="keyRotationChip(agentFor(item)!)"
                    size="x-small"
                    variant="tonal"
                    :color="keyRotationChip(agentFor(item)!)!.color"
                    :prepend-icon="keyRotationChip(agentFor(item)!)!.icon"
                    :title="keyRotationChip(agentFor(item)!)!.tooltip"
                  >
                    {{ keyRotationChip(agentFor(item)!)!.text }}
                  </v-chip>
                  <!-- FR-27 — only when the companion disagrees with the
                       daemon: the desktop is running code the daemon has
                       moved past. -->
                  <v-chip
                    v-if="companionSkew(item)"
                    size="x-small"
                    color="warning"
                    variant="tonal"
                    :title="$t('mh.dev.skewTitle', { desktop: companionSkew(item), daemon: item.version })"
                  >
                    {{ $t('mh.dev.desktopVersion', { v: companionSkew(item) }) }}
                  </v-chip>
                  <!-- FR-92 P5b — keep busy, only while it is ON: the device's
                       claim, shown as such; off or unknown shows nothing. -->
                  <v-chip
                    v-if="agentFor(item)!.keep_busy?.on"
                    size="x-small"
                    color="info"
                    variant="tonal"
                    prepend-icon="mdi-cursor-default-gesture-outline"
                    :title="keepBusyBriefTitle(agentFor(item)!.keep_busy)"
                    data-testid="agent-keep-busy-chip"
                  >
                    {{ $t('mh.dev.keepBusy') }} · {{ agentFor(item)!.keep_busy!.phase }}
                  </v-chip>
                  <!-- A device the OS has muzzled looks identical to a healthy
                       one until you connect and get a black screen. -->
                  <v-chip
                    v-for="w in permissionWarnings(agentFor(item)!)"
                    :key="w.label"
                    size="x-small"
                    color="warning"
                    variant="tonal"
                    :title="w.tooltip"
                  >
                    {{ w.label }}
                  </v-chip>
                </template>
                <v-chip
                  v-for="t in (item.tags ?? []).slice(0, 3)"
                  :key="`tag-${t}`"
                  size="x-small"
                  variant="outlined"
                  prepend-icon="mdi-tag-outline"
                >
                  {{ t }}
                </v-chip>
                <v-chip
                  v-if="(item.tags?.length ?? 0) > 3"
                  size="x-small"
                  variant="outlined"
                  :title="(item.tags ?? []).slice(3).join(', ')"
                >
                  +{{ (item.tags?.length ?? 0) - 3 }}
                </v-chip>
              </div>
              <!-- On demand: the policy (six controls that used to be open on
                   every card) and the technical facts. Each title says what is
                   inside, so a collapsed card still answers "how is this set?". -->
              <v-expansion-panels
                variant="accordion"
                multiple
                flat
                tile
                class="device-card__panels mt-auto"
              >
                <v-expansion-panel v-if="agentFor(item)" value="access">
                  <v-expansion-panel-title>
                    <div class="device-card__panel-title">
                      <span class="text-body-2 font-weight-medium flex-shrink-0">
                        <v-icon size="small" class="mr-1">mdi-shield-account-outline</v-icon>{{ $t('mh.dev.access') }}
                      </span>
                      <span class="text-caption text-medium-emphasis device-card__panel-summary">
                        {{ policySummary(agentFor(item)!.access_policy, isOwnedByMe(agentFor(item)!)).join(' · ') }}
                      </span>
                    </div>
                  </v-expansion-panel-title>
                  <v-expansion-panel-text>
                    <DeviceAccessPolicyFields
                      :agent="agentFor(item)!"
                      :busy="consentBusy === item.id"
                      :owned-by-me="isOwnedByMe(agentFor(item)!)"
                      variant="outlined"
                      @consent="(m: ConsentMode) => onConsentModeChange(agentFor(item)!, m)"
                      @prompt-owner="(v: boolean) => onPromptOwnerChange(agentFor(item)!, v)"
                      @input-mode="(m: 'free' | 'exclusive') => onInputModeChange(agentFor(item)!, m)"
                      @idle-minutes="(m: number) => onIdleMinutesChange(agentFor(item)!, m)"
                      @lock-on-end="(l: LockOnEnd) => onLockOnEndChange(agentFor(item)!, l)"
                      @rc-overlay="(v: boolean) => onRcOverlayChange(agentFor(item)!, v)"
                    />
                  </v-expansion-panel-text>
                </v-expansion-panel>
                <v-expansion-panel value="details">
                  <v-expansion-panel-title>
                    <div class="device-card__panel-title">
                      <span class="text-body-2 font-weight-medium flex-shrink-0">
                        <v-icon size="small" class="mr-1">mdi-information-outline</v-icon>{{ $t('mh.dev.details') }}
                      </span>
                      <span class="text-caption text-medium-emphasis device-card__panel-summary">
                        {{ item.overlay_ip || $t('mh.dev.noOverlay') }}
                      </span>
                    </div>
                  </v-expansion-panel-title>
                  <v-expansion-panel-text>
                    <dl class="device-card__facts text-caption">
                      <template v-if="item.overlay_ip">
                        <dt>{{ $t('mh.dev.col.overlay') }}</dt>
                        <dd class="text-mono">
                          {{ item.overlay_ip }}<br />{{ deriveOverlayV6(item.overlay_ip) }}
                        </dd>
                      </template>
                      <template v-if="item.magic_dns_fqdn || item.magic_dns_name">
                        <dt>MagicDNS</dt>
                        <dd class="text-mono">
                          {{ item.magic_dns_fqdn || item.magic_dns_name }}
                          <v-btn
                            v-if="item.magic_dns_fqdn"
                            :icon="copiedAgentId === item.magic_dns_fqdn ? 'mdi-check' : 'mdi-content-copy'"
                            size="x-small"
                            variant="text"
                            density="comfortable"
                            :aria-label="$t('mh.dev.copyDnsFor', { name: deviceLabel(item) })"
                            @click="copyAgentId(item.magic_dns_fqdn!)"
                          />
                        </dd>
                      </template>
                      <!-- FR-40 — the node's public key, so a rotation is
                           visible as a changed key rather than trusted from a
                           chip. -->
                      <template v-if="item.overlay_public_key">
                        <dt>{{ $t('mh.dev.overlayKey') }}</dt>
                        <dd class="text-mono">
                          {{ item.overlay_public_key.slice(0, 10) }}… · {{ $t('mh.dev.epoch', { n: item.overlay_key_epoch ?? 0 }) }}
                        </dd>
                      </template>
                      <dt>{{ $t('mh.dev.deviceId') }}</dt>
                      <dd class="text-mono">
                        {{ shortId(item.id) }}
                        <v-btn
                          :icon="copiedAgentId === item.id ? 'mdi-check' : 'mdi-content-copy'"
                          size="x-small"
                          variant="text"
                          density="comfortable"
                          :color="copiedAgentId === item.id ? 'success' : undefined"
                          :aria-label="$t('mh.dev.copyIdFor', { name: deviceLabel(item) })"
                          @click="copyAgentId(item.id)"
                        />
                      </dd>
                      <dt>{{ $t('mh.dev.machineId') }}</dt>
                      <dd class="text-mono">{{ shortId(item.machine_id) }}</dd>
                      <!-- FR-100 P1a — the device's own key, as a person reads
                           it, so what a browser pins can be checked here. -->
                      <template v-if="agentFor(item)?.peer_auth_fingerprint">
                        <dt>{{ $t('mh.dev.deviceKey') }}</dt>
                        <dd class="text-mono">{{ agentFor(item)!.peer_auth_fingerprint }}</dd>
                      </template>
                      <template v-if="agentFor(item) && codecChips(agentFor(item)!).length > 0">
                        <dt>{{ $t('mh.dev.col.codecs') }}</dt>
                        <dd class="d-flex flex-wrap ga-1">
                          <v-chip
                            v-for="codec in codecChips(agentFor(item)!)"
                            :key="codec.label"
                            size="x-small"
                            :color="codec.color"
                            variant="tonal"
                            :title="codec.tooltip"
                          >
                            {{ codec.label }}
                          </v-chip>
                        </dd>
                      </template>
                      <dt>{{ $t('mh.dev.col.lastSeen') }}</dt>
                      <dd>{{ fmtDate(item.last_seen_at) }}</dd>
                    </dl>
                  </v-expansion-panel-text>
                </v-expansion-panel>
              </v-expansion-panels>
              <v-card-actions class="px-3 pt-1 pb-2">
                <v-btn
                  v-if="item.kind === 'agent'"
                  size="small"
                  variant="tonal"
                  color="primary"
                  prepend-icon="mdi-remote-desktop"
                  :disabled="!item.is_online"
                  :to="{ name: 'agent-remote', params: { tenantId, agentId: item.id } }"
                  :aria-label="$t('mh.dev.connectTo', { name: deviceLabel(item) })"
                  class="flex-grow-1"
                >
                  {{ $t('mh.dev.connect') }}
                </v-btn>
                <v-spacer v-else />
                <DeviceActionsMenu
                  :tenant-id="tenantId"
                  :row="item"
                  :agent="agentFor(item)"
                  :client="clientFor(item)"
                  :node="nodeFor(item)"
                  :network-mounted="caps.has('network')"
                  :update-busy="updateBusy === item.id"
                  :rotate-key-busy="rotateKeyBusy === item.id"
                  :update-blocked="updateBlockedText(agentFor(item))"
                  @action="(a: DeviceAction) => onDeviceAction(item, a)"
                />
              </v-card-actions>
            </v-card>
          </v-col>
        </v-row>
        <div
          v-if="deviceStore.totalPages > 1"
          class="d-flex flex-column align-center mt-3"
        >
          <v-pagination
            v-model="gridPage"
            :length="deviceStore.totalPages"
            :total-visible="xs ? 3 : 5"
            density="comfortable"
            size="small"
          />
          <span class="text-caption text-medium-emphasis">{{ pageRangeText }}</span>
        </div>
      </div>
    </v-card-text>
  </v-card>

  <!-- S4 — unified enrollment dialog (token + per-OS install commands
       derived from this origin; template map vitest-locked). -->
  <EnrollmentDialog
    :model-value="enrollDialogOpen"
    kind="agent"
    :token="enrollToken?.enrollment_token ?? null"
    :expires-in="enrollToken?.expires_in ?? null"
    :loading="enrollLoading"
    :error="enrollError"
    :anchor="enrollToken?.anchor === true"
    @update:model-value="(v: boolean) => { if (!v) closeEnrollDialog() }"
    @update:anchor="reissueEnrollToken"
  />

  <!-- Tunnel-client enrollment (folded from /network/tunnel-clients) -->
  <EnrollmentDialog
    :model-value="tunnelEnrollDialogOpen"
    kind="tunnel"
    :token="tunnelEnrollToken?.enrollment_token ?? null"
    :expires-in="tunnelEnrollToken?.expires_in ?? null"
    :loading="tunnelEnrollLoading"
    :error="tunnelEnrollError"
    @update:model-value="(v: boolean) => { if (!v) closeTunnelEnrollDialog() }"
  />

  <!-- Per-user column visibility + order for the unified grid. -->
  <GridColumnPickerDialog
    v-model="colDialogOpen"
    :entries="colEntries"
    @toggle="colToggle"
    @reorder="colReorder"
    @reset="colReset"
  >
    <template #append>
      <v-divider class="my-1" />
      <v-checkbox-btn
        v-model="hideNameWhenDisplay"
        density="compact"
        class="px-2"
        :label="$t('mh.dev.hideName')"
      />
    </template>
  </GridColumnPickerDialog>

  <!-- Name / display-name / tags (both kinds; rename propagates to MagicDNS). -->
  <DeviceEditDialog
    v-model="editDialogOpen"
    :tenant-id="tenantId"
    :device="editTarget"
    @saved="onDeviceSaved"
  />

  <!-- Overlay eviction (lifted from MachinesSection; shared by devices and
       tunnel clients — the confirm copy branches on will_rejoin). -->
  <v-dialog v-model="evictDialogOpen" max-width="540">
    <v-card>
      <v-card-title>
        {{ evictTarget?.will_rejoin
          ? $t('mh.dev.evict.titleRejoin', { name: nodeLabel(evictTarget) })
          : $t('mh.dev.evict.titleRemove', { name: nodeLabel(evictTarget) }) }}
      </v-card-title>
      <v-card-text>
        <ul class="text-body-2 mb-3 ps-4">
          <li>
            <i18n-t keypath="mh.dev.evict.leaves" tag="span">
              <template #ip><span class="text-mono">{{ evictTarget?.overlay_ip }}</span></template>
            </i18n-t>
          </li>
          <li>
            <i18n-t keypath="mh.dev.evict.released" tag="span">
              <template #different><strong>{{ $t('mh.dev.different') }}</strong></template>
            </i18n-t>
          </li>
          <li v-if="evictTarget?.will_rejoin">
            <i18n-t keypath="mh.dev.evict.rejoins" tag="span">
              <template #name><strong>{{ nodeLabel(evictTarget) }}</strong></template>
              <template #different><strong>{{ $t('mh.dev.different') }}</strong></template>
            </i18n-t>
          </li>
          <li v-else>
            {{ $t('mh.dev.evict.gone') }}
          </li>
        </ul>
        <v-alert type="warning" variant="tonal" density="compact" class="mb-0">
          <i18n-t keypath="mh.dev.evict.pinned" tag="span">
            <template #cfg><code>overlay_exit_node = "{{ evictTarget?.name }}"</code></template>
          </i18n-t>
        </v-alert>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="evictDialogOpen = false">{{ $t('common.cancel') }}</v-btn>
        <v-btn color="error" variant="flat" :loading="evicting" @click="performEvict">
          {{ evictTarget?.will_rejoin ? $t('mh.dev.evict.doRejoin') : $t('mh.dev.evict.doRemove') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <!-- Tunnel-client delete confirmation (folded from TunnelClientsSection) -->
  <v-dialog v-model="tunnelDeleteDialogOpen" max-width="480">
    <v-card>
      <v-card-title>{{ $t('mh.dev.tunnelDelete.title') }}</v-card-title>
      <v-card-text>
        <p class="font-weight-medium mb-2">{{ deviceLabel(tunnelDeleteTarget) }}</p>
        <p class="text-body-2">
          {{ $t('mh.dev.tunnelDelete.body') }}
        </p>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="tunnelDeleteDialogOpen = false">{{ $t('common.cancel') }}</v-btn>
        <v-btn
          color="error"
          variant="flat"
          :loading="tunnelDeleting"
          @click="performTunnelDelete"
        >
          {{ $t('mh.dev.tunnelDelete.do') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <!-- Crash reports modal -->
  <AgentCrashesDialog
    v-model="crashesDialogOpen"
    :tenant-id="tenantId"
    :agent-id="crashesTarget?.id ?? ''"
    :agent-name="deviceLabel(crashesTarget)"
  />

  <!-- Logs viewer modal (centralized agent-log upload, rc.58/rc.59) -->
  <AgentLogsDialog
    v-model="logsDialogOpen"
    :tenant-id="tenantId"
    :agent-id="logsTarget?.id ?? ''"
    :agent-name="deviceLabel(logsTarget)"
  />

  <!-- Fleet RPC — run a command on the device, and edit the policy that
       decides whether anyone may. Both are guarded by `v-if` on the target
       so a null agent can never reach a dialog that assumes one. -->
  <DeviceConsoleDialog
    v-if="consoleTarget"
    v-model="consoleDialogOpen"
    :tenant-id="tenantId"
    :agent="consoleTarget"
  />
  <ExecPolicyDialog
    v-if="execPolicyTarget"
    v-model="execPolicyDialogOpen"
    :tenant-id="tenantId"
    :agent="execPolicyTarget"
  />
  <SshPolicyDialog
    v-if="sshPolicyTarget"
    v-model="sshPolicyDialogOpen"
    :tenant-id="tenantId"
    :agent="sshPolicyTarget"
  />
  <ExternalAccessDialog
    v-if="externalAccessTarget"
    v-model="externalAccessDialogOpen"
    :tenant-id="tenantId"
    :agent="externalAccessTarget"
    @saved="agentStore.fetchAgents(tenantId); fetchGrid()"
  />
  <RemoteConfigDialog
    v-if="remoteConfigTarget"
    v-model="remoteConfigDialogOpen"
    :tenant-id="tenantId"
    :agent="remoteConfigTarget"
    @saved="agentStore.fetchAgents(tenantId); fetchGrid()"
  />

  <!-- FR-40 — rotate-overlay-key confirmation -->
  <v-dialog v-model="rotateKeyDialogOpen" max-width="520">
    <v-card>
      <v-card-title>{{ $t('mh.dev.rotate.title', { name: deviceLabel(rotateKeyTarget) }) }}</v-card-title>
      <v-card-text>
        <i18n-t keypath="mh.dev.rotate.body" tag="span">
          <template #onDevice><strong>{{ $t('mh.dev.rotate.onDevice') }}</strong></template>
        </i18n-t>
        <br /><br />
        {{ $t('mh.dev.rotate.disruptive') }}
        <template v-if="rotateKeyTarget && !rotateKeyTarget.is_online">
          <br /><br />
          {{ $t('mh.dev.rotate.offline') }}
        </template>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="rotateKeyDialogOpen = false">{{ $t('common.cancel') }}</v-btn>
        <v-btn
          color="warning"
          variant="flat"
          :loading="rotateKeyBusy !== null"
          @click="doRotateKey"
        >
          {{ $t('mh.dev.rotate.do') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <!-- S1a — Update-all confirmation -->
  <v-dialog v-model="updateAllDialogOpen" max-width="480">
    <v-card>
      <v-card-title>{{ $t('mh.dev.upd.title') }}</v-card-title>
      <v-card-text>
        {{ $t('mh.dev.upd.body', { total: agentStore.agents.length, online: agentStore.agents.filter((a) => a.is_online).length }) }}
        <div v-if="wontUpdateHere.length > 0" class="mt-3">
          {{ $t('mh.dev.upd.wont', { n: wontUpdateHere.length }) }}
          <ul class="ml-4">
            <li v-for="x in wontUpdateHere" :key="x.a.id">
              <strong>{{ deviceLabel(x.a) }}</strong> — {{ refusalShort(x.code) }}
            </li>
          </ul>
        </div>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="updateAllDialogOpen = false">{{ $t('common.cancel') }}</v-btn>
        <v-btn color="primary" variant="flat" @click="doUpdateAll" :loading="updatingAll">
          {{ $t('mh.dev.updateAll') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <!-- Delete confirmation -->
  <v-dialog v-model="deleteDialogOpen" max-width="540">
    <v-card>
      <v-card-title>{{ $t('mh.dev.del.title') }}</v-card-title>
      <v-card-text>
        <p class="font-weight-medium mb-3">{{ deviceLabel(deleteTarget) }}</p>
        <ul class="text-body-2 mb-3 ps-4">
          <li>
            {{ $t('mh.dev.del.evicted') }}
          </li>
          <li>
            <i18n-t keypath="mh.dev.evict.released" tag="span">
              <template #different><strong>{{ $t('mh.dev.different') }}</strong></template>
            </i18n-t>
          </li>
          <li>
            <i18n-t keypath="mh.dev.del.stays" tag="span">
              <template #fresh><strong>{{ $t('mh.dev.del.fresh') }}</strong></template>
            </i18n-t>
          </li>
        </ul>
        <v-alert type="warning" variant="tonal" density="compact" class="mb-0">
          <i18n-t keypath="mh.dev.del.pinned" tag="span">
            <template #cfg><code>overlay_exit_node = "{{ deleteTarget?.name }}"</code></template>
          </i18n-t>
        </v-alert>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="deleteDialogOpen = false">{{ $t('common.cancel') }}</v-btn>
        <v-btn color="error" variant="flat" @click="performDelete" :loading="deleting">
          {{ $t('mh.dev.del.do') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <!-- Reassign device owner (MANAGE_AGENTS) -->
  <!-- Multi-org — add an already-enrolled device to a second organization
       without touching the machine. Needs MANAGE_AGENTS in both; the picker
       only lists orgs where the caller actually has it. -->
  <v-dialog v-model="joinOrgDialogOpen" max-width="520">
    <v-card>
      <v-card-title>{{ $t('mh.dev.join.title') }}</v-card-title>
      <v-card-text>
        <p class="text-body-2 mb-3">
          <i18n-t keypath="mh.dev.join.body" tag="span">
            <template #name><strong>{{ deviceLabel(joinOrgTarget) }}</strong></template>
          </i18n-t>
        </p>
        <v-alert
          v-if="joinOrgLoaded && !joinOrgSupported"
          type="warning"
          variant="tonal"
          density="compact"
          class="mb-3"
          :text="$t('mh.dev.join.old')"
        />
        <v-alert
          v-else-if="joinOrgLoaded && !joinOrgOnline"
          type="warning"
          variant="tonal"
          density="compact"
          class="mb-3"
          :text="$t('mh.dev.join.offline')"
        />
        <v-alert
          v-else-if="joinOrgLoaded && joinOrgItems.length === 0"
          type="info"
          variant="tonal"
          density="compact"
          class="mb-3"
          :text="$t('mh.dev.join.none')"
        />
        <v-select
          v-model="joinOrgTargetTenant"
          :items="joinOrgSelectItems"
          :loading="joinOrgLoading"
          :disabled="!joinOrgSupported || !joinOrgOnline || joinOrgItems.length === 0"
          :label="$t('mh.dev.join.org')"
          density="compact"
          variant="outlined"
          class="mb-3"
          hide-details
        />
        <v-select
          v-model="joinOrgOverlayMode"
          :items="[
            { title: $t('mh.dev.join.meshOff'), value: 'off' },
            { title: $t('mh.dev.join.meshTun'), value: 'tun' },
          ]"
          :disabled="!joinOrgSupported || !joinOrgOnline"
          :label="$t('mh.dev.join.mesh')"
          density="compact"
          variant="outlined"
          hide-details
        />
        <v-alert
          v-if="joinOrgOverlayMode === 'tun' && joinOrgLoaded && !joinOrgMeshReady"
          type="info"
          variant="tonal"
          density="compact"
          class="mt-3"
          :text="$t('mh.dev.join.restart')"
        />
        <v-alert
          v-if="joinOrgError"
          type="error"
          variant="tonal"
          density="compact"
          class="mt-3"
          :text="joinOrgError"
        />
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="joinOrgDialogOpen = false">{{ $t('common.cancel') }}</v-btn>
        <v-btn
          color="primary"
          variant="flat"
          :loading="joinOrgBusy"
          :disabled="!joinOrgTargetTenant || !joinOrgSupported || !joinOrgOnline"
          @click="confirmJoinOrg"
        >
          {{ $t('mh.dev.join.do') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <v-dialog v-model="reassignDialogOpen" max-width="440">
    <v-card>
      <v-card-title>{{ $t('mh.dev.owner.title') }}</v-card-title>
      <v-card-text>
        <p class="text-body-2 mb-3">
          <i18n-t keypath="mh.dev.owner.body" tag="span">
            <template #name><strong>{{ deviceLabel(reassignTarget) }}</strong></template>
          </i18n-t>
        </p>
        <v-select
          v-model="reassignOwnerId"
          :items="memberSelectItems"
          :label="$t('mh.dev.owner.new')"
          density="compact"
          variant="outlined"
          hide-details
        />
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="reassignDialogOpen = false">{{ $t('common.cancel') }}</v-btn>
        <v-btn
          color="primary"
          variant="flat"
          :loading="reassignBusy"
          :disabled="!reassignOwnerId || reassignOwnerId === reassignTarget?.owner_user_id"
          @click="confirmReassign"
        >
          {{ $t('mh.dev.owner.do') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <!-- Subnet routes (mesh subnet-router, Phase 2 — MANAGE_AGENTS) -->
  <v-dialog v-model="routesDialogOpen" max-width="560">
    <v-card>
      <v-card-title>{{ $t('mh.dev.routes.title') }}</v-card-title>
      <v-card-text>
        <p class="text-body-2 mb-3">
          <i18n-t keypath="mh.dev.routes.body" tag="span">
            <template #name><strong>{{ deviceLabel(routesTarget) }}</strong></template>
            <template #cmd><code>roomler socks5</code></template>
            <template #acl><strong>{{ $t('mh.tp.title') }}</strong></template>
          </i18n-t>
        </p>

        <div v-if="routesDraft.length" class="d-flex flex-wrap ga-2 mb-3">
          <v-chip
            v-for="cidr in routesDraft"
            :key="cidr"
            closable
            size="small"
            variant="tonal"
            color="primary"
            prepend-icon="mdi-ip-network-outline"
            @click:close="removeRoute(cidr)"
          >
            {{ cidr }}
          </v-chip>
        </div>
        <p v-else class="text-body-2 text-medium-emphasis mb-3">
          {{ $t('mh.dev.routes.none') }}
        </p>

        <div v-if="advertisedSuggestions.length" class="mb-3">
          <p class="text-caption text-medium-emphasis mb-1">
            {{ $t('mh.dev.routes.advertised') }}
          </p>
          <div class="d-flex flex-wrap ga-2">
            <v-chip
              v-for="cidr in advertisedSuggestions"
              :key="cidr"
              size="small"
              variant="outlined"
              color="primary"
              prepend-icon="mdi-lan-pending"
              append-icon="mdi-plus"
              @click="approveAdvertised(cidr)"
              :aria-label="$t('mh.dev.routes.approve', { cidr })"
            >
              {{ cidr }}
            </v-chip>
          </div>
        </div>

        <v-text-field
          v-model="routeInput"
          :label="$t('mh.dev.routes.add')"
          placeholder="10.66.24.0/24"
          density="compact"
          variant="outlined"
          :error-messages="routeInputError ? [routeInputError] : []"
          append-inner-icon="mdi-plus"
          :hint="$t('mh.dev.routes.hint')"
          persistent-hint
          @click:append-inner="addRoute"
          @keyup.enter="addRoute"
        />
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="routesDialogOpen = false">{{ $t('common.cancel') }}</v-btn>
        <v-btn color="primary" variant="flat" :loading="routesBusy" @click="saveRoutes">
          {{ $t('common.save') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useRoute, useRouter } from 'vue-router'
import { useDisplay } from 'vuetify'
import {
  useAgentStore,
  type Agent,
  type ConsentMode,
  type EnrollmentToken,
  type LockOnEnd,
} from '@/stores/agents'
import { codecChips, permissionWarnings } from './agentCodecChips'
import { keepBusyBriefTitle } from '@/composables/keepBusy'
import { credentialChip } from '@/utils/credentialExpiry'
import { updateStallChip } from '@/utils/updateStall'
import { refusalShort, updateRefusal } from '@/utils/updateRefusal'
import AgentCrashesDialog from './AgentCrashesDialog.vue'
import AgentLogsDialog from './AgentLogsDialog.vue'
import DeviceConsoleDialog from './DeviceConsoleDialog.vue'
import ExecPolicyDialog from './ExecPolicyDialog.vue'
import SshPolicyDialog from './SshPolicyDialog.vue'
import ExternalAccessDialog from './ExternalAccessDialog.vue'
import { useCapabilitiesStore } from '@/stores/capabilities'
import RemoteConfigDialog from './RemoteConfigDialog.vue'
import EnrollmentDialog from '@/components/enroll/EnrollmentDialog.vue'
import {
  useOverlayRoutesStore,
  deriveOverlayV6,
  type OverlayNode,
} from '@/stores/overlayRoutes'
import {
  useTunnelClientStore,
  type TunnelClient,
  type TunnelEnrollmentToken,
} from '@/stores/tunnelClients'
import { useDeviceStore, type DeviceRow } from '@/stores/devices'
import { useAuthStore } from '@/stores/auth'
import { useGridColumns } from '@/composables/useGridColumns'
import {
  deviceLabel,
  secondaryDeviceName,
  useHideDeviceName,
} from '@/composables/useHideDeviceName'
import GridColumnPickerDialog from '@/components/common/GridColumnPickerDialog.vue'
import DeviceEditDialog, { type EditableDevice } from '@/components/admin/DeviceEditDialog.vue'
import DeviceActionsMenu, { type DeviceAction } from './DeviceActionsMenu.vue'
import DeviceAccessPolicyFields from './DeviceAccessPolicyFields.vue'
import { policySummary } from './devicePolicy'

const props = defineProps<{ tenantId: string }>()

const agentStore = useAgentStore()
const overlayStore = useOverlayRoutesStore()
const tunnelClientStore = useTunnelClientStore()
const deviceStore = useDeviceStore()
// FR-69 P9 — the overlay-key rotation, the SSH policy and the peer-relay
// policy are the network module's routes; a `remote` profile has no network
// module, and a menu item that leads to a 404 is worse than none.
const caps = useCapabilitiesStore()
const auth = useAuthStore()
// Declared before the grid state below — gridKind's initializer reads
// route.query.
const route = useRoute()
const router = useRouter()

// ── Unified server-driven grid state ─────────────────────────────
const gridSearch = ref('')
const gridPage = ref(1)
// Default 10 (operator, 2026-08-27): the devices page leads the product —
// a screenful beats a scroll; the footer still offers 25/50/100.
const gridPerPage = ref(10)
const gridSort = ref<string | undefined>(undefined)
const gridDir = ref<'asc' | 'desc' | undefined>(undefined)
/** Kind radio: devices-only by default — 'both' widens to tunnel clients.
 *  Mirrored to/from the `?type=` querystring (device | tunnel | both) so the
 *  dashboard's Tunnels tile can land here pre-filtered and the URL stays
 *  shareable. */
const gridKind = ref<'agent' | 'tunnel_client' | 'both'>(kindFromQuery(route.query.type))
const colDialogOpen = ref(false)

function kindFromQuery(v: unknown): 'agent' | 'tunnel_client' | 'both' {
  return v === 'tunnel' ? 'tunnel_client' : v === 'both' ? 'both' : 'agent'
}
// Query → radio (e.g. in-app navigation to ?type=tunnel while mounted).
watch(
  () => route.query.type,
  (t) => {
    const k = kindFromQuery(t)
    if (k !== gridKind.value) gridKind.value = k
  },
)
// Radio → query (replace, not push — a filter flip is not a history entry).
watch(gridKind, (k) => {
  const wanted = k === 'tunnel_client' ? 'tunnel' : k === 'both' ? 'both' : undefined
  if ((route.query.type ?? undefined) !== wanted) {
    router.replace({ query: { ...route.query, type: wanted } })
  }
})

/** Column-picker extra: collapse the Name cell to the display name alone
 *  when one is set (default ON — the machine-reported title is noise once
 *  someone has named the device). Per user+org, like the column prefs, and
 *  shared with the remote-control page's header. */
// `tr`, not `t`: the template already uses `t` for a tag.
const { t: tr } = useI18n()
const hideNameWhenDisplay = useHideDeviceName(() => `${auth.user?.id ?? 'anon'}:${props.tenantId}`)

const deviceHeaders = computed(() => [
  // Leftmost on purpose — see the template comment (field bug 2026-05-01).
  { title: tr('mh.dev.col.actions'), key: 'actions', sortable: false, width: 96 },
  { title: tr('mh.dev.col.name'), key: 'name', sortable: true },
  { title: tr('mh.dev.col.kind'), key: 'kind', sortable: true },
  { title: tr('mh.dev.col.status'), key: 'status', sortable: true },
  { title: 'OS', key: 'os', sortable: true },
  { title: tr('mh.dev.col.overlay'), key: 'overlay_ip', sortable: true },
  { title: 'MagicDNS', key: 'magic_dns', sortable: true },
  { title: tr('mh.dev.col.tags'), key: 'tags', sortable: false },
  { title: tr('mh.dev.col.consent'), key: 'consent', sortable: false },
  { title: tr('mh.dev.col.codecs'), key: 'codecs', sortable: false },
  { title: tr('mh.dev.col.lastSeen'), key: 'last_seen_at', sortable: true },
])
const {
  effectiveHeaders,
  entries: colEntries,
  toggle: colToggle,
  reorder: colReorder,
  reset: colReset,
  customized: colsCustomized,
} = useGridColumns({
  headers: deviceHeaders,
  gridId: 'devices',
  scope: () => `${auth.user?.id ?? 'anon'}:${props.tenantId}`,
})

function fetchGrid() {
  deviceStore
    .fetchDevices(props.tenantId, {
      page: gridPage.value,
      perPage: gridPerPage.value,
      q: gridSearch.value || undefined,
      sort: gridSort.value,
      dir: gridDir.value,
      kind: gridKind.value === 'both' ? undefined : gridKind.value,
    })
    .catch(() => {})
}

watch(gridKind, () => {
  if (gridPage.value !== 1) gridPage.value = 1 // options handler fetches
  else fetchGrid()
})

/** v-data-table-server fires this once on mount too — it is the grid's ONLY
 *  fetch trigger for page/sort changes (a separate onMounted fetch would
 *  double-load). */
function onGridOptions(opts: {
  page: number
  itemsPerPage: number
  sortBy: Array<{ key: string; order: 'asc' | 'desc' }>
}) {
  gridPage.value = opts.page
  gridPerPage.value = opts.itemsPerPage
  gridSort.value = opts.sortBy[0]?.key
  gridDir.value = opts.sortBy[0]?.order
  fetchGrid()
}

let gridSearchTimer: ReturnType<typeof setTimeout> | undefined
watch(gridSearch, () => {
  if (gridSearchTimer) clearTimeout(gridSearchTimer)
  gridSearchTimer = setTimeout(() => {
    // Back to page 1: if the page actually changes, the options handler
    // fetches; when already there, fetch directly.
    if (gridPage.value !== 1) gridPage.value = 1
    else fetchGrid()
  }, 300)
})

// Rich agent-only cells (consent selects, codec chips, the action menu)
// need the FULL Agent — the grid rows are the lean DeviceRow feed.
const agentById = computed(() => {
  const m = new Map<string, Agent>()
  for (const a of agentStore.agents) m.set(a.id, a)
  return m
})
function agentFor(row: DeviceRow): Agent | undefined {
  return row.kind === 'agent' ? agentById.value.get(row.id) : undefined
}

/** FR-106 — the "not updating" chip for a device, or `null`. Online is the
 *  reachability truth the presence column renders (`is_online`, patched live
 *  by `applyPresence`). */
function stallChip(a: Agent) {
  return updateStallChip(a.agent_version, a.is_online, a.os, agentStore.releases)
}

/** FR-27 — the companion version to display, or `''` when there is nothing
 *  worth saying.
 *
 *  Returns a value ONLY when the companion disagrees with the daemon, because
 *  agreement is the expected state and rendering it on every row would bury
 *  the one case an operator needs to see. Absent (`undefined`) is deliberately
 *  silent rather than rendered as "unknown": it covers a pre-FR-27 agent, a
 *  host with no companion, and a failed probe alike, and guessing between them
 *  in a table cell would be worse than saying nothing. */
function companionSkew(row: DeviceRow): string {
  const cv = agentFor(row)?.companion_version
  return cv && cv !== row.version ? cv : ''
}
const clientById = computed(() => {
  const m = new Map<string, TunnelClient>()
  for (const c of tunnelClientStore.clients) m.set(c.id, c)
  return m
})
function clientFor(row: DeviceRow): TunnelClient | undefined {
  return row.kind === 'tunnel_client' ? clientById.value.get(row.id) : undefined
}
/** The row's overlay node, joined on the wire's FK (never on the name). */
function nodeFor(row: DeviceRow): OverlayNode | undefined {
  return row.kind === 'agent' ? nodeForAgent(row.id) : nodeForTunnelClient(row.id)
}

/** The one place a menu pick becomes a dialog or a request — the grid and the
 *  cards render the same `DeviceActionsMenu`, so they cannot offer different
 *  things for the same device. */
function onDeviceAction(row: DeviceRow, action: DeviceAction) {
  const a = agentFor(row)
  const node = nodeFor(row)
  switch (action) {
    case 'edit': return openEdit(row)
    case 'evict': return node ? confirmEvict(node) : undefined
    case 'delete-tunnel': {
      const c = clientFor(row)
      return c ? confirmTunnelDelete(c) : undefined
    }
  }
  if (!a) return
  switch (action) {
    case 'update': return void triggerUpdate(a)
    case 'rotate-key': return openRotateKey(a)
    case 'crashes': return openCrashes(a)
    case 'logs': return openLogs(a)
    case 'console': return openConsole(a)
    case 'join-org': return void openJoinOrg(a)
    case 'reassign': return openReassign(a)
    case 'exec-policy': return openExecPolicy(a)
    case 'ssh-policy': return openSshPolicy(a)
    case 'external-access': return openExternalAccess(a)
    case 'remote-config': return openRemoteConfig(a)
    case 'routes': return openRoutes(a)
    case 'delete': return confirmDelete(a)
  }
}

/** Whether a card has any chip to show — an empty chip row would only add
 *  padding. Mirrors the chip row's own conditions. */
function cardHasChips(row: DeviceRow): boolean {
  if (row.kind === 'tunnel_client' || row.ephemeral || (row.tags?.length ?? 0) > 0) return true
  const a = agentFor(row)
  if (!a) return false
  return !!(
    credentialChip(a.token_expires_at) ||
    stallChip(a) ||
    remoteConfigChip(a) ||
    keyRotationChip(a) ||
    companionSkew(row) ||
    a.keep_busy?.on ||
    permissionWarnings(a).length > 0
  )
}

/** "11–20 of 22" under the cards' pager. */
const pageRangeText = computed(() => {
  const total = deviceStore.total
  if (total === 0) return ''
  const first = (gridPage.value - 1) * gridPerPage.value + 1
  const last = Math.min(gridPage.value * gridPerPage.value, total)
  return tr('mh.dev.pageRange', { first, last, total })
})

// Row-level presence rendering (DeviceRow carries presence directly).
function rowPresenceColor(r: DeviceRow): string {
  return r.presence === 'online' ? 'success' : r.presence === 'stale' ? 'warning' : 'grey'
}
function rowPresenceIcon(r: DeviceRow): string {
  return r.presence === 'online'
    ? 'mdi-circle'
    : r.presence === 'stale'
      ? 'mdi-circle-half-full'
      : 'mdi-circle-outline'
}
function rowPresenceTitle(r: DeviceRow): string {
  if (r.kind === 'tunnel_client')
    return r.is_online ? tr('mh.dev.presence.onlineStored') : tr('mh.dev.presence.offlineStored')
  return r.presence === 'online'
    ? tr('mh.dev.presence.onlineTitle')
    : r.presence === 'stale'
      ? tr('mh.dev.presence.staleTitle')
      : tr('mh.dev.presence.offline')
}
function rowStatusColor(r: DeviceRow): string {
  return rowPresenceColor(r)
}
function rowStatusLabel(r: DeviceRow): string {
  return tr(`mh.dev.presence.${r.presence}`)
}

// ── Edit name & tags ─────────────────────────────────────────────
const editDialogOpen = ref(false)
const editTarget = ref<EditableDevice | null>(null)
function openEdit(row: DeviceRow) {
  editTarget.value = {
    kind: row.kind,
    id: row.id,
    name: row.name,
    display_name: row.display_name,
    tags: row.tags,
  }
  editDialogOpen.value = true
}
function onDeviceSaved(result: {
  id: string
  name: string
  display_name?: string
  tags: string[]
  dnsRenamed?: boolean
  dnsName?: string
}) {
  deviceStore.patchRow({
    id: result.id,
    name: result.name,
    display_name: result.display_name,
    tags: result.tags,
    ...(result.dnsName ? { magic_dns_name: result.dnsName } : {}),
  })
  // Refetch so sort/search reflect the new values server-side.
  fetchGrid()
}

// ── Unified-devices join (2026-08-04): overlay node per device row. The
// wire's agent_id / tunnel_client_id FKs are the join key — the node NAME
// is a lossy, de-duplicated DNS label and must not be used for this.
const nodesByAgentId = computed(() => {
  const m = new Map<string, OverlayNode>()
  for (const n of overlayStore.nodes) if (n.agent_id) m.set(n.agent_id, n)
  return m
})
const nodesByTunnelClientId = computed(() => {
  const m = new Map<string, OverlayNode>()
  for (const n of overlayStore.nodes) if (n.tunnel_client_id) m.set(n.tunnel_client_id, n)
  return m
})
function nodeForAgent(agentId: string): OverlayNode | undefined {
  return nodesByAgentId.value.get(agentId)
}
function nodeForTunnelClient(tcId: string): OverlayNode | undefined {
  return nodesByTunnelClientId.value.get(tcId)
}
/** A node by the name a person knows its device by. `node.name` is a lossy
 *  DNS label, so the device is found on the wire's FK; the label is only the
 *  fallback (a node whose device is gone). */
function nodeLabel(n: OverlayNode | null | undefined): string {
  if (!n) return ''
  const agent = n.agent_id ? agentById.value.get(n.agent_id) : undefined
  const client = n.tunnel_client_id ? clientById.value.get(n.tunnel_client_id) : undefined
  return deviceLabel(agent ?? client ?? n)
}

// ── Overlay eviction (lifted from MachinesSection) ───────────────
const evictDialogOpen = ref(false)
const evictTarget = ref<OverlayNode | null>(null)
const evicting = ref(false)
function confirmEvict(node: OverlayNode) {
  evictTarget.value = node
  evictDialogOpen.value = true
}
async function performEvict() {
  if (!evictTarget.value) return
  evicting.value = true
  try {
    await overlayStore.evictNode(props.tenantId, evictTarget.value.id)
    evictDialogOpen.value = false
    evictTarget.value = null
    await overlayStore.fetchNodes(props.tenantId)
    fetchGrid()
  } finally {
    evicting.value = false
  }
}

// ── Tunnel clients (folded from TunnelClientsSection) ────────────
const tunnelEnrollDialogOpen = ref(false)
const tunnelEnrollToken = ref<TunnelEnrollmentToken | null>(null)
const tunnelEnrollLoading = ref(false)
const tunnelEnrollError = ref<string | null>(null)
async function openTunnelEnrollDialog() {
  tunnelEnrollDialogOpen.value = true
  tunnelEnrollLoading.value = true
  tunnelEnrollToken.value = null
  tunnelEnrollError.value = null
  try {
    tunnelEnrollToken.value = await tunnelClientStore.issueEnrollmentToken(props.tenantId)
  } catch (e) {
    tunnelEnrollError.value = (e as Error).message
  } finally {
    tunnelEnrollLoading.value = false
  }
}
function closeTunnelEnrollDialog() {
  tunnelEnrollDialogOpen.value = false
  tunnelEnrollToken.value = null
  tunnelEnrollError.value = null
  // A freshly-enrolled client shows up on the next fetch.
  tunnelClientStore.fetchTunnelClients(props.tenantId)
}

const tunnelDeleteDialogOpen = ref(false)
const tunnelDeleteTarget = ref<TunnelClient | null>(null)
const tunnelDeleting = ref(false)
function confirmTunnelDelete(c: TunnelClient) {
  tunnelDeleteTarget.value = c
  tunnelDeleteDialogOpen.value = true
}
async function performTunnelDelete() {
  if (!tunnelDeleteTarget.value) return
  tunnelDeleting.value = true
  try {
    await tunnelClientStore.deleteTunnelClient(props.tenantId, tunnelDeleteTarget.value.id)
    tunnelDeleteDialogOpen.value = false
    tunnelDeleteTarget.value = null
    await Promise.all([
      tunnelClientStore.fetchTunnelClients(props.tenantId),
      overlayStore.fetchNodes(props.tenantId),
    ])
    fetchGrid()
  } finally {
    tunnelDeleting.value = false
  }
}

// The access-policy writes. The controls and their choices live in
// `DeviceAccessPolicyFields` / `devicePolicy.ts` (one copy for the grid and
// the cards); each change lands here as one full-policy PUT.
// Agent id whose consent mode is mid-update (disables + spins that row's select).
const consentBusy = ref<string | null>(null)
// FR-116 D1 — the grid rows whose access controls are open (all closed by
// default: the row shows the summary). A new Set on each toggle, so the
// template re-reads it.
const consentOpen = ref(new Set<string>())
function toggleConsent(id: string) {
  const next = new Set(consentOpen.value)
  if (next.has(id)) next.delete(id)
  else next.add(id)
  consentOpen.value = next
}
/** The card's Access line, wrapping only BETWEEN its parts ("Prompt on
 *  host · skipped for you"), so a long policy grows the row, not the column. */
function consentSummary(a: Agent): string {
  return policySummary(a.access_policy, isOwnedByMe(a))
    .map((p) => p.replace(/ /g, ' '))
    .join(' · ')
}
async function onConsentModeChange(a: Agent, mode: ConsentMode) {
  if ((a.access_policy.consent_mode ?? 'prompt') === mode) return
  consentBusy.value = a.id
  try {
    await agentStore.updateAccessPolicy(props.tenantId, a.id, {
      ...a.access_policy,
      consent_mode: mode,
    })
  } catch (e) {
    agentStore.error = (e as Error).message
  } finally {
    consentBusy.value = null
  }
}

/** FR-27 — do I own this device? Controlling your own device skips consent
 *  server-side, so the mode select above is inert for these rows unless
 *  `prompt_owner` is on. Only the owner sees the toggle: for anyone else the
 *  mode already applies, and an always-visible row explaining someone else's
 *  exemption would be noise. */
function isOwnedByMe(a: Agent): boolean {
  return !!auth.user?.id && a.owner_user_id === auth.user.id
}

async function onPromptOwnerChange(a: Agent, prompt_owner: boolean) {
  if ((a.access_policy.prompt_owner ?? false) === prompt_owner) return
  consentBusy.value = a.id
  try {
    await agentStore.updateAccessPolicy(props.tenantId, a.id, {
      ...a.access_policy,
      prompt_owner,
    })
  } catch (e) {
    agentStore.error = (e as Error).message
  } finally {
    consentBusy.value = null
  }
}

async function onInputModeChange(a: Agent, mode: 'free' | 'exclusive') {
  if ((a.access_policy.input_mode ?? 'free') === mode) return
  consentBusy.value = a.id
  try {
    await agentStore.updateAccessPolicy(props.tenantId, a.id, {
      ...a.access_policy,
      input_mode: mode,
    })
  } catch (e) {
    agentStore.error = (e as Error).message
  } finally {
    consentBusy.value = null
  }
}

// FR-101 P4b-2b — `0` from the select is "none of its own" (stored as null),
// so the organization's limit alone applies.
async function onIdleMinutesChange(a: Agent, minutes: number) {
  const next = minutes > 0 ? minutes : null
  if ((a.access_policy.auto_terminate_idle_minutes ?? null) === next) return
  consentBusy.value = a.id
  try {
    await agentStore.updateAccessPolicy(props.tenantId, a.id, {
      ...a.access_policy,
      auto_terminate_idle_minutes: next,
    })
  } catch (e) {
    agentStore.error = (e as Error).message
  } finally {
    consentBusy.value = null
  }
}

// FR-99 P3b — `never` from the select asks nothing (stored as null), so the
// device owner's own setting alone applies.
async function onLockOnEndChange(a: Agent, lock: LockOnEnd) {
  const next = lock === 'never' ? null : lock
  if ((a.access_policy.lock_on_end ?? null) === next) return
  consentBusy.value = a.id
  try {
    await agentStore.updateAccessPolicy(props.tenantId, a.id, {
      ...a.access_policy,
      lock_on_end: next,
    })
  } catch (e) {
    agentStore.error = (e as Error).message
  } finally {
    consentBusy.value = null
  }
}

async function onRcOverlayChange(a: Agent, rc_overlay: boolean) {
  if ((a.access_policy.rc_overlay ?? false) === rc_overlay) return
  consentBusy.value = a.id
  try {
    await agentStore.updateAccessPolicy(props.tenantId, a.id, {
      ...a.access_policy,
      rc_overlay,
    })
  } catch (e) {
    agentStore.error = (e as Error).message
  } finally {
    consentBusy.value = null
  }
}

// `mobile` is below md (< 960 px): phones and portrait tablets get the cards
// (one column on a phone, two from sm), wider screens the grid. `lgAndDown`
// (≤1280) drives the codec-chip rollup so mid-width viewports don't blow past
// the Actions column.
const { smAndDown: mobile, xs, lgAndDown } = useDisplay()

// The cards have no v-data-table-server to fire @update:options, so below md a
// page change fetches here. Guarded by `mobile`: on the grid the table's
// options event is the one fetch per change, and a second one would
// double-load.
watch(gridPage, () => {
  if (mobile.value) fetchGrid()
})

const enrollDialogOpen = ref(false)
const enrollLoading = ref(false)
const enrollToken = ref<EnrollmentToken | null>(null)
const enrollError = ref<string | null>(null)

// Per-row copy-feedback for the agent-id copy button. Holds the id
// of the last-copied agent for 2 s so the row's mdi-content-copy
// icon swaps to mdi-check (and back) without us having to thread
// state through each row.
const copiedAgentId = ref<string | null>(null)
let copiedAgentIdTimer: ReturnType<typeof setTimeout> | null = null

const deleteDialogOpen = ref(false)
const deleteTarget = ref<Agent | null>(null)
const deleting = ref(false)

// S1a — operator-forced self-update. Per-row busy id + a transient
// notice rendered in the info alert at the top of the card.
const updateBusy = ref<string | null>(null)
const updateNotice = ref<string | null>(null)
const updateAllDialogOpen = ref(false)
const updatingAll = ref(false)

// FR-40 — overlay-key rotation (docs/fr/FR-40-overlay-key-rotation.md)
const rotateKeyDialogOpen = ref(false)
const rotateKeyTarget = ref<Agent | null>(null)
const rotateKeyBusy = ref<string | null>(null)

function openRotateKey(a: Agent) {
  rotateKeyTarget.value = a
  rotateKeyDialogOpen.value = true
}

async function doRotateKey() {
  const a = rotateKeyTarget.value
  if (!a) return
  rotateKeyBusy.value = a.id
  try {
    const res = await agentStore.rotateOverlayKey(props.tenantId, a.id)
    updateNotice.value = res.delivered
      ? tr('mh.dev.rotate.ordered', { name: deviceLabel(a) })
      : tr('mh.dev.rotate.queuedOffline', { name: deviceLabel(a) })
    rotateKeyDialogOpen.value = false
    await agentStore.fetchAgents(props.tenantId)
    fetchGrid()
  } catch (e) {
    agentStore.error = (e as Error).message
  } finally {
    rotateKeyBusy.value = null
  }
}

/** One chip per resolved state. The states are the SERVER's resolution
 *  (`key_rotation_view`) — the client only names them. */
function keyRotationChip(
  a: Agent,
): { color: string; icon: string; text: string; tooltip: string } | null {
  const kr = a.key_rotation
  if (!kr) return null
  switch (kr.state) {
    case 'queued':
      return {
        color: 'info',
        icon: 'mdi-key-chain',
        text: tr('mh.dev.kr.queued'),
        tooltip: tr('mh.dev.kr.queuedTip'),
      }
    case 'delivered':
      return {
        color: 'info',
        icon: 'mdi-key-chain',
        text: tr('mh.dev.kr.rotating'),
        tooltip: tr('mh.dev.kr.deliveredTip'),
      }
    case 'rotating':
      return {
        color: 'info',
        icon: 'mdi-key-chain',
        text: tr('mh.dev.kr.rotating'),
        tooltip: tr('mh.dev.kr.rotatingTip'),
      }
    case 'rotated':
      return {
        color: 'success',
        icon: 'mdi-key-change',
        text: tr('mh.dev.kr.rotated', { epoch: kr.report?.key_epoch ?? '?' }),
        tooltip: tr('mh.dev.kr.rotatedTip', { at: kr.report?.reported_at ?? '' }),
      }
    case 'reported_not_joined':
      return {
        color: 'error',
        icon: 'mdi-key-alert',
        text: tr('mh.dev.kr.notJoined'),
        tooltip:
          tr('mh.dev.kr.notJoinedTip'),
      }
    case 'refused':
      return {
        color: 'warning',
        icon: 'mdi-hand-back-left-outline',
        text: tr('mh.dev.kr.refused', { outcome: kr.report?.outcome ?? 'refused' }),
        tooltip: kr.report?.detail ?? tr('mh.dev.kr.refusedTip'),
      }
    case 'failed':
      return {
        color: 'error',
        icon: 'mdi-alert-circle-outline',
        text: tr('mh.dev.kr.failed'),
        tooltip:
          kr.report?.detail ??
          tr('mh.dev.kr.failedTip'),
      }
    case 'unsupported':
      return {
        color: 'grey',
        icon: 'mdi-update',
        text: tr('mh.dev.kr.old'),
        tooltip:
          tr('mh.dev.kr.oldTip'),
      }
    default:
      return null
  }
}

async function triggerUpdate(a: Agent) {
  updateBusy.value = a.id
  try {
    const delivered = await agentStore.triggerUpdate(props.tenantId, a.id)
    updateNotice.value = delivered
      ? tr('mh.dev.upd.pushed', { name: deviceLabel(a) })
      : tr('mh.dev.upd.offline', { name: deviceLabel(a) })
  } catch (e) {
    agentStore.error = (e as Error).message
  } finally {
    updateBusy.value = null
  }
}

// FR-67 P7 — devices that will not act on an update ordered from here, from
// their hellos: named in the dialog BEFORE the click, and greyed out on their
// own "Update now". The server refuses those pushes anyway (the source of
// truth); this only stops the dashboard promising what will not happen.
const wontUpdateHere = computed(() =>
  agentStore.agents
    .map((a) => ({ a, code: updateRefusal(a.capabilities) }))
    .filter((x) => x.code !== null),
)

function updateBlockedText(a: Agent | undefined | null): string | undefined {
  const code = updateRefusal(a?.capabilities)
  return code ? refusalShort(code) : undefined
}

async function doUpdateAll() {
  updatingAll.value = true
  try {
    const res = await agentStore.triggerUpdateAll(props.tenantId)
    const names = new Map(agentStore.agents.map((a) => [a.id, deviceLabel(a)]))
    const skipped = res.results.filter((r) => r.refused_code)
    let notice = tr('mh.dev.upd.pushedAll', { delivered: res.delivered, requested: res.requested })
    if (skipped.length > 0) {
      notice +=
        ' ' +
        tr('mh.dev.upd.skipped', {
          n: skipped.length,
          list: skipped
            .map((r) => `${names.get(r.agent_id) ?? r.agent_id} (${refusalShort(r.refused_code)})`)
            .join(', '),
        })
    }
    updateNotice.value = notice
    updateAllDialogOpen.value = false
  } catch (e) {
    agentStore.error = (e as Error).message
  } finally {
    updatingAll.value = false
  }
}

// Crash-reports modal state (Task 9 Phase 3). Re-fetches on open via
// the dialog's own watcher; no caching here.
const crashesDialogOpen = ref(false)
const crashesTarget = ref<Agent | null>(null)

function openCrashes(a: Agent) {
  crashesTarget.value = a
  crashesDialogOpen.value = true
}

// Logs-viewer modal state (rc.74). Same no-cache, fetch-on-open
// pattern as the crashes dialog — the AgentLogsDialog refetches the
// recent uploaded log batches each time it opens.
const logsDialogOpen = ref(false)
const logsTarget = ref<Agent | null>(null)

function openLogs(a: Agent) {
  logsTarget.value = a
  logsDialogOpen.value = true
}

// Fleet RPC — the device console and its policy editor. Same fetch-on-open
// pattern as the dialogs above; the console additionally reads the ORG
// kill-switch so it can explain a refusal before the operator types anything.
const consoleDialogOpen = ref(false)
const consoleTarget = ref<Agent | null>(null)

function openConsole(a: Agent) {
  consoleTarget.value = a
  consoleDialogOpen.value = true
}

const execPolicyDialogOpen = ref(false)
const execPolicyTarget = ref<Agent | null>(null)

function openExecPolicy(a: Agent) {
  execPolicyTarget.value = a
  execPolicyDialogOpen.value = true
}

const sshPolicyDialogOpen = ref(false)
const sshPolicyTarget = ref<Agent | null>(null)

function openSshPolicy(a: Agent) {
  sshPolicyTarget.value = a
  sshPolicyDialogOpen.value = true
}

const externalAccessDialogOpen = ref(false)
const externalAccessTarget = ref<Agent | null>(null)

function openExternalAccess(a: Agent) {
  externalAccessTarget.value = a
  externalAccessDialogOpen.value = true
}

const remoteConfigDialogOpen = ref(false)
const remoteConfigTarget = ref<Agent | null>(null)

function openRemoteConfig(a: Agent) {
  remoteConfigTarget.value = a
  remoteConfigDialogOpen.value = true
}

/** The row badge for a device with a pending / refused / failed config
 *  request. `null` for `applied` and for devices nobody is managing — a
 *  steady-state chip on every row is noise that trains people to stop reading
 *  the row, and the states worth interrupting for are the ones that need
 *  someone to do something. */
function remoteConfigChip(
  a: Agent,
): { color: string; icon: string; text: string; tooltip: string } | null {
  const state = a.remote_config?.state
  switch (state) {
    case 'needs_restart':
      return {
        color: 'warning',
        icon: 'mdi-restart-alert',
        text: tr('mh.dev.rc.restart'),
        tooltip: tr('mh.dev.rc.restartTip'),
      }
    case 'refused':
      return {
        color: 'warning',
        icon: 'mdi-hand-back-left-outline',
        text: tr('mh.dev.rc.refused'),
        tooltip:
          a.remote_config?.report?.outcome === 'not_primary'
            ? tr('mh.dev.rc.notPrimary')
            : tr('mh.dev.rc.notOptedIn'),
      }
    case 'failed':
      return {
        color: 'error',
        icon: 'mdi-alert-circle-outline',
        text: tr('mh.dev.rc.failed'),
        tooltip: a.remote_config?.report?.detail ?? tr('mh.dev.rc.failedTip'),
      }
    case 'pending':
      return {
        color: 'info',
        icon: 'mdi-clock-outline',
        text: tr('mh.dev.rc.pending'),
        tooltip: tr('mh.dev.rc.pendingTip'),
      }
    case 'reports_unsupported':
    case 'push_unsupported':
      return {
        color: 'grey',
        icon: 'mdi-update',
        text: tr('mh.dev.rc.old'),
        tooltip:
          state === 'push_unsupported'
            ? tr('mh.dev.rc.oldPush')
            : tr('mh.dev.rc.oldReport'),
      }
    default:
      return null
  }
}

function osIcon(os: string) {
  switch (os) {
    case 'linux': return 'mdi-linux'
    case 'macos': return 'mdi-apple'
    case 'windows': return 'mdi-microsoft-windows'
    default: return 'mdi-desktop-classic'
  }
}

function fmtDate(iso: string): string {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

function fmtRelative(iso: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const diff = Date.now() - d.getTime()
  if (diff < 0) return 'just now'
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days}d ago`
  const months = Math.floor(days / 30)
  if (months < 12) return `${months}mo ago`
  return `${Math.floor(months / 12)}y ago`
}

// FR-12 — `/devices?enroll=1` opens this dialog, so a tutorial step can land
// on the real thing instead of describing a button. The param is stripped
// immediately: opening MINTS a single-use enrollment token, and a bookmarked
// or refreshed URL must not keep minting them.
watch(
  () => route.query.enroll,
  (v) => {
    if (!v) return
    const { enroll: _dropped, ...rest } = route.query
    void router.replace({ query: rest })
    void openEnrollDialog()
  },
  { immediate: true },
)

// Bound as a click handler, so it takes no argument: Vue would pass the event.
async function openEnrollDialog() {
  enrollDialogOpen.value = true
  await mintEnrollToken(false)
}

/** FR-104 — the dialog's "also anchor" box: a new token, with or without the
 *  anchor claim. The one shown before stays valid until its own expiry. */
function reissueEnrollToken(anchor: boolean) {
  void mintEnrollToken(anchor)
}

async function mintEnrollToken(anchor: boolean) {
  enrollLoading.value = true
  enrollToken.value = null
  enrollError.value = null
  try {
    enrollToken.value = await agentStore.issueEnrollmentToken(props.tenantId, { anchor })
  } catch (e) {
    enrollError.value = (e as Error).message
  } finally {
    enrollLoading.value = false
  }
}

function closeEnrollDialog() {
  enrollDialogOpen.value = false
  enrollToken.value = null
}

/**
 * Copy an agent's hex ObjectId to the clipboard so the operator can
 * paste it into `roomler forward --agent <hex>` (or any other
 * CLI / API call that needs the agent identifier).
 *
 * Surfaces transient success state via [`copiedAgentId`] for 2 s —
 * the row's copy button swaps to mdi-check during that window.
 *
 * Best-effort: a clipboard-write failure is logged but otherwise
 * silently swallowed; the operator can fall back to copying from
 * the tooltip (the full id is rendered in the row's `title`
 * attribute, so a long-hover surfaces it natively).
 */
async function copyAgentId(id: string) {
  try {
    await navigator.clipboard.writeText(id)
    copiedAgentId.value = id
    if (copiedAgentIdTimer !== null) {
      clearTimeout(copiedAgentIdTimer)
    }
    copiedAgentIdTimer = setTimeout(() => {
      copiedAgentId.value = null
      copiedAgentIdTimer = null
    }, 2000)
  } catch (err) {
    console.warn('copyAgentId: clipboard write failed', err)
  }
}

/**
 * Truncate a hex id to a 6-char prefix + ellipsis for inline display.
 * The full id is always available via the cell's `title` attribute
 * (long-press / hover tooltip) and the Copy button puts the full
 * value on the clipboard. Inline truncation keeps the Agents table
 * from blowing past the Actions column on mid-width viewports.
 */
function shortId(id: string): string {
  if (!id) return '—'
  if (id.length <= 8) return id
  return `${id.slice(0, 6)}…`
}

function confirmDelete(a: Agent) {
  deleteTarget.value = a
  deleteDialogOpen.value = true
}

async function performDelete() {
  if (!deleteTarget.value) return
  deleting.value = true
  try {
    await agentStore.deleteAgent(props.tenantId, deleteTarget.value.id)
    deleteDialogOpen.value = false
    deleteTarget.value = null
    fetchGrid()
  } finally {
    deleting.value = false
  }
}

// Owner reassignment (MANAGE_AGENTS). Resolve owner_user_id → a name via the
// tenant members, and pick a new owner from that list.
// Multi-org — "Add to another organization". The target list comes from the
// server (orgs where this caller holds MANAGE_AGENTS), so the picker can
// never offer a choice that 403s.
const joinOrgDialogOpen = ref(false)
const joinOrgTarget = ref<Agent | null>(null)
const joinOrgTargetTenant = ref<string>('')
const joinOrgOverlayMode = ref<string>('off')
const joinOrgBusy = ref(false)
const joinOrgLoading = ref(false)
const joinOrgLoaded = ref(false)
const joinOrgSupported = ref(true)
const joinOrgOnline = ref(true)
// Whether picking "Join the mesh" gets a mesh now or after a restart. Only
// consulted when `tun` is selected — an `off` join never touches the TUN.
const joinOrgMeshReady = ref(true)
const joinOrgError = ref('')
const joinOrgItems = ref<
  Array<{ tenant_id: string; name: string; slug: string; already_enrolled: boolean }>
>([])
const joinOrgSelectItems = computed(() =>
  joinOrgItems.value.map((o) => ({
    title: o.already_enrolled ? `${o.name} — already added` : o.name,
    value: o.tenant_id,
    props: { disabled: o.already_enrolled },
  })),
)
async function openJoinOrg(a: Agent) {
  joinOrgTarget.value = a
  joinOrgTargetTenant.value = ''
  joinOrgOverlayMode.value = 'off'
  joinOrgError.value = ''
  joinOrgItems.value = []
  joinOrgLoaded.value = false
  joinOrgDialogOpen.value = true
  joinOrgLoading.value = true
  try {
    const res = await agentStore.fetchJoinTargets(props.tenantId, a.id)
    joinOrgItems.value = res.items
    joinOrgSupported.value = res.supported
    joinOrgOnline.value = res.online
    // Older servers omit the field; assume ready so we never invent a
    // restart warning for a device that doesn't need one.
    joinOrgMeshReady.value = res.mesh_ready !== false
  } catch (e) {
    joinOrgError.value = (e as Error).message
  } finally {
    joinOrgLoading.value = false
    joinOrgLoaded.value = true
  }
}
async function confirmJoinOrg() {
  if (!joinOrgTarget.value || !joinOrgTargetTenant.value) return
  joinOrgBusy.value = true
  joinOrgError.value = ''
  try {
    const res = await agentStore.joinOrg(
      props.tenantId,
      joinOrgTarget.value.id,
      joinOrgTargetTenant.value,
      { overlayMode: joinOrgOverlayMode.value },
    )
    joinOrgDialogOpen.value = false
    // The device enrolls itself a beat later; say what actually happened
    // rather than implying the row is already there.
    const base = res.already_enrolled
      ? `${deviceLabel(joinOrgTarget.value)} was already in that organization — its enrollment was refreshed.`
      : `${deviceLabel(joinOrgTarget.value)} is joining as "${res.label}". It appears in that organization's device list shortly.`
    // Say the quiet part: the enrollment landed, the MESH did not.
    updateNotice.value = res.restart_required
      ? `${base} Mesh access is configured but starts after the device's agent restarts — the next auto-update delivers that.`
      : base
  } catch (e) {
    joinOrgError.value = (e as Error).message
  } finally {
    joinOrgBusy.value = false
  }
}

const reassignDialogOpen = ref(false)
const reassignTarget = ref<Agent | null>(null)
const reassignOwnerId = ref<string>('')
const reassignBusy = ref(false)
const memberSelectItems = computed(() =>
  agentStore.tenantMembers.map((m) => ({
    title: m.display_name || m.nickname || m.user_id,
    value: m.user_id,
  })),
)
function openReassign(a: Agent) {
  reassignTarget.value = a
  reassignOwnerId.value = a.owner_user_id
  reassignDialogOpen.value = true
}
async function confirmReassign() {
  if (!reassignTarget.value || !reassignOwnerId.value) return
  reassignBusy.value = true
  try {
    await agentStore.updateOwner(props.tenantId, reassignTarget.value.id, reassignOwnerId.value)
    reassignDialogOpen.value = false
  } catch (e) {
    agentStore.error = (e as Error).message
  } finally {
    reassignBusy.value = false
  }
}

// Subnet routes (mesh subnet-router, Phase 2 — MANAGE_AGENTS). Edit the agent's
// advertised route CIDRs; the mesh longest-prefix-matches a LAN target IP
// against these. The draft is applied atomically on Save via a full-replace PUT.
const routesDialogOpen = ref(false)
const routesTarget = ref<Agent | null>(null)
const routesDraft = ref<string[]>([])
const routeInput = ref('')
const routeInputError = ref<string | null>(null)
const routesBusy = ref(false)

function openRoutes(a: Agent) {
  routesTarget.value = a
  routesDraft.value = [...(a.routes ?? [])]
  routeInput.value = ''
  routeInputError.value = null
  routesDialogOpen.value = true
}

/**
 * Validate a CIDR and return its canonical network form — IPv4 host bits are
 * masked to the network address, so `10.66.24.53/24` → `10.66.24.0/24`.
 * Returns null for anything that isn't valid CIDR notation: a bare IP (no
 * prefix), a bad octet, or an out-of-range prefix. IPv6 is validated loosely
 * and returned as-typed; the server canonicalizes authoritatively (both ends
 * share the same `ipnet` semantics). Mirrors `normalize_routes` in the API.
 */
function canonicalizeCidr(raw: string): string | null {
  const t = raw.trim()
  const m = t.match(/^([^/]+)\/(\d{1,3})$/)
  if (!m) return null
  const addr = m[1]!
  const prefix = Number(m[2])
  if (addr.includes(':')) {
    // IPv6 — loose check; the server has the authoritative parser.
    if (prefix < 0 || prefix > 128 || !/^[0-9a-fA-F:]+$/.test(addr)) return null
    return `${addr}/${prefix}`
  }
  const octets = addr.split('.')
  if (octets.length !== 4) return null
  if (!octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255)) return null
  if (prefix < 0 || prefix > 32) return null
  const nums = octets.map((o) => Number(o))
  const bits = ((nums[0]! << 24) | (nums[1]! << 16) | (nums[2]! << 8) | nums[3]!) >>> 0
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
  const net = (bits & mask) >>> 0
  const masked = [(net >>> 24) & 255, (net >>> 16) & 255, (net >>> 8) & 255, net & 255].join('.')
  return `${masked}/${prefix}`
}

function addRoute() {
  const canonical = canonicalizeCidr(routeInput.value)
  if (!canonical) {
    routeInputError.value = tr('mh.dev.routes.invalid')
    return
  }
  if (!routesDraft.value.includes(canonical)) {
    routesDraft.value.push(canonical)
  }
  routeInput.value = ''
  routeInputError.value = null
}

function removeRoute(cidr: string) {
  routesDraft.value = routesDraft.value.filter((r) => r !== cidr)
}

/** Advertised routes the agent proposed that aren't already in the draft —
 *  canonicalized + deduped so they compare cleanly against approved routes.
 *  Approving one moves it into the routes draft (and it drops off this list). */
const advertisedSuggestions = computed<string[]>(() => {
  const adv = routesTarget.value?.advertised_routes ?? []
  const seen = new Set(routesDraft.value)
  const out: string[] = []
  for (const raw of adv) {
    const c = canonicalizeCidr(raw)
    if (c && !seen.has(c) && !out.includes(c)) out.push(c)
  }
  return out
})

/** Approve an advertised CIDR (already canonical from `advertisedSuggestions`)
 *  into the routes draft; Save then persists it to the agent's approved routes. */
function approveAdvertised(cidr: string) {
  if (!routesDraft.value.includes(cidr)) {
    routesDraft.value.push(cidr)
  }
}

async function saveRoutes() {
  if (!routesTarget.value) return
  routesBusy.value = true
  try {
    await agentStore.updateRoutes(props.tenantId, routesTarget.value.id, routesDraft.value)
    routesDialogOpen.value = false
  } catch (e) {
    agentStore.error = (e as Error).message
  } finally {
    routesBusy.value = false
  }
}

/** The two network-owned stores, loaded only where the server mounts `network`.
 *
 *  ⚠️ The TEMPLATE has always been gated (`v-if="caps.has('network')"`), but
 *  these fetches were not — so on a `remote` profile the devices page fired
 *  `/tenant/{id}/tunnel-client` and `/tenant/{id}/overlay-node` at a server
 *  that correctly does not mount them, collecting four 404s and four console
 *  errors on every visit. The server was right; the client was asking for
 *  doors it had already decided not to draw. FR-69 P9's rule is that the SPA
 *  gates on `/api/capabilities` — that has to cover what it FETCHES, not only
 *  what it renders. (Found by the FR-75 profile matrix, #1447.) */
function loadNetworkStores(tid: string) {
  if (!caps.has('network')) return
  overlayStore.fetchNodes(tid)
  tunnelClientStore.fetchTunnelClients(tid)
}

onMounted(() => {
  // The GRID's own fetch fires from @update:options on mount; the cards have
  // no such event, so below md the first page is fetched here.
  if (mobile.value) fetchGrid()
  // The rich per-device stores the action menus and the cards' agent-only
  // fields read.
  agentStore.fetchAgents(props.tenantId)
  agentStore.fetchTenantMembers(props.tenantId)
  loadNetworkStores(props.tenantId)
  // FR-106 — the release list the "not updating" chip reads (cached 30 min).
  agentStore.fetchReleases()
})

watch(() => props.tenantId, (tid) => {
  if (tid) {
    agentStore.fetchAgents(tid)
    loadNetworkStores(tid)
    // Reset the grid to a clean first page for the new org.
    gridSearch.value = ''
    if (gridPage.value !== 1) gridPage.value = 1
    else fetchGrid()
  }
})
</script>

<style scoped>
/* FR-116 D1 — the Consent cell's summary is its toggle: text-styled, a focus
   ring for the keyboard. */
.consent-toggle {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  max-width: 240px;
  white-space: normal;
  padding: 0;
  border: 0;
  background: none;
  color: inherit;
  font: inherit;
  text-align: left;
  cursor: pointer;
}
.consent-toggle:focus-visible {
  outline: 2px solid rgb(var(--v-theme-primary));
  outline-offset: 2px;
  border-radius: 4px;
}
/* Action column: keep it leftmost AND narrow so mid-width viewports never
   push it off-screen. Two icon buttons fit in ~96px. */
.agents-table :deep(th.agents-actions-col),
.agents-table :deep(td.agents-actions-col) {
  width: 96px;
  min-width: 96px;
  white-space: nowrap;
}

/* Never squeeze the columns into the viewport — every cell keeps its
   natural width (max two lines per cell: e.g. name over id·version,
   consent over input mode) and the WRAPPER scrolls horizontally.
   (House rule: wide tables scroll in their own container.) */
.agents-table :deep(.v-table__wrapper) {
  overflow-x: auto;
}
.agents-table :deep(table) {
  width: max-content;
  min-width: 100%;
}
.agents-table :deep(th),
.agents-table :deep(td) {
  white-space: nowrap;
}

/* The two stacked selects (consent / input mode) need room to render
   their labels on one line each instead of clipping. */
.agents-table :deep(.consent-select) {
  min-width: 170px;
}

/* FR-27 — the companion-version skew note. Warning-toned so it reads as
   "something here is behind", not as a second neutral fact next to the
   daemon version. */
/* The phone/tablet cards. Panel titles are one line — the policy summary
   truncates rather than pushing every card a line taller. */
.device-search--full {
  flex: 1 1 100%;
}
.device-card__head {
  min-width: 0;
}
.device-card__panels :deep(.v-expansion-panel-title) {
  min-height: 44px;
  padding: 8px 12px;
}
.device-card__panels :deep(.v-expansion-panel-title--active) {
  min-height: 44px;
}
.device-card__panels :deep(.v-expansion-panel-text__wrapper) {
  padding: 4px 12px 12px;
}
.device-card__panels :deep(.v-expansion-panel) {
  border-top: thin solid rgba(var(--v-border-color), var(--v-border-opacity));
}
.device-card__panel-title {
  display: flex;
  align-items: baseline;
  gap: 8px;
  min-width: 0;
  overflow: hidden;
}
.device-card__panel-summary {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.device-card__facts {
  display: grid;
  grid-template-columns: max-content minmax(0, 1fr);
  column-gap: 12px;
  row-gap: 4px;
  margin: 0;
}
.device-card__facts dt {
  color: rgba(var(--v-theme-on-surface), var(--v-medium-emphasis-opacity));
}
.device-card__facts dd {
  margin: 0;
  min-width: 0;
  overflow-wrap: anywhere;
}

.companion-skew {
  color: rgb(var(--v-theme-warning));
}
</style>
