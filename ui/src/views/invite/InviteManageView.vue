<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-container fluid class="pa-2 pa-md-4 pa-xl-6">
    <div class="d-flex align-center flex-wrap ga-2 mb-2 mb-md-4">
      <h2 class="text-h5">{{ t('mh.invite.title') }}</h2>
      <v-spacer />
      <!-- FR-11: server-side search over code / target email + status filter.
           FR-116: on a phone the two share a row of their own, under the
           title, and the buttons take the next one. -->
      <v-text-field
        v-model="gridSearch"
        density="compact"
        hide-details
        clearable
        prepend-inner-icon="mdi-magnify"
        :placeholder="t('mh.invite.search')"
        :style="xs ? 'flex: 1 1 60%' : 'max-width: 220px'"
        :class="xs ? 'order-1' : 'flex-grow-0'"
      />
      <v-select
        v-model="gridStatus"
        :items="statusOptions.map((s) => ({ title: t(`mh.invite.st.${s}`), value: s }))"
        density="compact"
        hide-details
        clearable
        :placeholder="t('mh.invite.status')"
        :style="xs ? 'flex: 0 0 128px' : 'max-width: 150px'"
        :class="xs ? 'order-1' : 'flex-grow-0'"
      />
      <v-btn
        icon="mdi-table-cog"
        size="small"
        variant="text"
        :color="colsCustomized ? 'primary' : undefined"
        :title="t('mh.files.columns')"
        :aria-label="t('mh.files.columns')"
        @click="colDialogOpen = true"
      />
      <v-btn
        variant="outlined"
        color="primary"
        :class="{ 'order-2 flex-grow-1': xs }"
        @click="showBatchDialog = true"
      >
        <v-icon start>mdi-email-multiple</v-icon>
        {{ t('mh.invite.batch') }}
      </v-btn>
      <v-btn color="primary" :class="{ 'order-2 flex-grow-1': xs }" @click="showCreateDialog = true">
        <v-icon start>mdi-plus</v-icon>
        {{ t('mh.invite.create') }}
      </v-btn>
    </div>

    <v-alert v-if="inviteStore.error" type="error" density="compact" class="mb-4">
      {{ inviteStore.error }}
    </v-alert>

    <v-card>
      <v-data-table-server
        v-model:page="gridPage"
        v-model:items-per-page="gridPerPage"
        :headers="effectiveHeaders"
        :items="inviteStore.invites"
        :items-length="inviteStore.total"
        :loading="inviteStore.loading"
        :items-per-page-options="[10, 25, 50, 100]"
        density="compact"
        class="invites-table"
        :class="{ 'invites-table--stacked': xs }"
        item-value="id"
        :mobile="xs"
        @update:options="onGridOptions"
      >
            <template #item.code="{ item }">
              <div class="d-flex align-center">
                <code class="text-body-2">{{ item.code }}</code>
                <v-btn
                  icon
                  size="x-small"
                  variant="text"
                  @click="copyLink(item.code)"
                >
                  <v-icon size="16">mdi-content-copy</v-icon>
                </v-btn>
              </div>
            </template>
            <template #item.status="{ item }">
              <v-chip
                :color="statusColor(item.status)"
                size="small"
                variant="tonal"
              >
                {{ statusOptions.includes(item.status) ? t(`mh.invite.st.${item.status}`) : item.status }}
              </v-chip>
            </template>
            <template #item.usage="{ item }">
              {{ item.use_count }} / {{ item.max_uses ?? t('mh.invite.unlimited') }}
            </template>
            <template #item.target_email="{ item }">
              {{ item.target_email || t('mh.invite.anyone') }}
            </template>
            <template #item.created_at="{ item }">
              {{ new Date(item.created_at).toLocaleDateString() }}
            </template>
            <template #item.actions="{ item }">
              <v-btn
                v-if="item.status === 'active'"
                icon
                size="small"
                variant="text"
                color="error"
                @click="handleRevoke(item.id)"
              >
                <v-icon>mdi-close-circle</v-icon>
              </v-btn>
            </template>
      </v-data-table-server>
    </v-card>

    <GridColumnPickerDialog
      v-model="colDialogOpen"
      :entries="colEntries"
      @toggle="colToggle"
      @reorder="colReorder"
      @reset="colReset"
    />

    <!-- Create invite dialog -->
    <v-dialog v-model="showCreateDialog" max-width="500">
          <v-card>
            <v-card-title>{{ t('mh.invite.create') }}</v-card-title>
            <v-card-text>
              <v-radio-group v-model="inviteType" inline class="mb-4">
                <v-radio :label="t('mh.invite.shareable')" value="link" />
                <v-radio :label="t('mh.invite.emailInvite')" value="email" />
              </v-radio-group>

              <v-text-field
                v-if="inviteType === 'email'"
                v-model="targetEmail"
                :label="t('mh.invite.email')"
                type="email"
                :rules="[rules.email]"
              />

              <v-text-field
                v-if="inviteType === 'link'"
                v-model.number="maxUses"
                :label="t('mh.invite.maxUses')"
                type="number"
                min="1"
              />

              <v-text-field
                v-model.number="expiresInHours"
                :label="t('mh.invite.expires')"
                type="number"
                min="1"
                :placeholder="t('mh.invite.expiresDefault')"
              />
            </v-card-text>
            <v-card-actions>
              <v-spacer />
              <v-btn @click="showCreateDialog = false">{{ t('common.cancel') }}</v-btn>
              <v-btn color="primary" :loading="creating" @click="handleCreate">
                {{ t('mh.invite.createBtn') }}
              </v-btn>
            </v-card-actions>
          </v-card>
        </v-dialog>

    <!-- Batch invite dialog -->
    <batch-invite-dialog
      v-model="showBatchDialog"
      :tenant-id="tenantId"
      :roles="roleStore.roles"
    />
  </v-container>
</template>

<script setup lang="ts">
import { appOrigin } from '@/utils/deployment'
import { ref, computed, watch, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useDisplay } from 'vuetify'
import { useInviteStore } from '@/stores/invite'
import { useRoleStore } from '@/stores/role'
import { useAuthStore } from '@/stores/auth'
import { useSnackbar } from '@/composables/useSnackbar'
import { useValidation } from '@/composables/useValidation'
import { useGridColumns } from '@/composables/useGridColumns'
import GridColumnPickerDialog from '@/components/common/GridColumnPickerDialog.vue'
import BatchInviteDialog from '@/components/invite/BatchInviteDialog.vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const route = useRoute()
const inviteStore = useInviteStore()
const roleStore = useRoleStore()
const auth = useAuthStore()
// FR-116 — below 600 px each invite is a stacked row (Vuetify's mobile rows,
// from the same headers): Uses, Created and Revoke were behind a sideways
// scroll inside the table.
const { xs } = useDisplay()
const { showSuccess, showError } = useSnackbar()
const { rules } = useValidation()

const tenantId = ref(route.params.tenantId as string)
const showCreateDialog = ref(false)
const showBatchDialog = ref(false)
const creating = ref(false)

const inviteType = ref<'link' | 'email'>('link')
const targetEmail = ref('')
const maxUses = ref<number | undefined>(undefined)
const expiresInHours = ref<number | undefined>(undefined)

// ── grid state (devices-grid kit, FR-11) ───────────────────────────

const gridPage = ref(1)
const gridPerPage = ref(25)
const gridSearch = ref('')
const gridStatus = ref<string | null>(null)
const gridSort = ref<string | undefined>(undefined)
const gridDir = ref<'asc' | 'desc' | undefined>(undefined)

const statusOptions = ['active', 'expired', 'revoked', 'exhausted']

const inviteHeaders = computed(() => [
  { title: t('mh.invite.col.code'), key: 'code', sortable: false },
  // Sortable keys double as the server whitelist (status | target_email | created_at).
  { title: t('mh.invite.col.status'), key: 'status', sortable: true },
  { title: t('mh.invite.col.target'), key: 'target_email', sortable: true },
  { title: t('mh.invite.col.usage'), key: 'usage', sortable: false },
  { title: t('mh.invite.col.created'), key: 'created_at', sortable: true },
  { title: t('mh.invite.col.actions'), key: 'actions', sortable: false, width: 60 },
])
const colDialogOpen = ref(false)
const {
  effectiveHeaders,
  entries: colEntries,
  toggle: colToggle,
  reorder: colReorder,
  reset: colReset,
  customized: colsCustomized,
} = useGridColumns({
  headers: inviteHeaders,
  gridId: 'invites',
  scope: () => `${auth.user?.id ?? 'anon'}:${tenantId.value}`,
})

function fetchGrid() {
  void inviteStore
    .listInvites(tenantId.value, {
      page: gridPage.value,
      perPage: gridPerPage.value,
      q: gridSearch.value || undefined,
      status: gridStatus.value || undefined,
      sort: gridSort.value,
      dir: gridDir.value,
    })
    .catch(() => {})
}

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
    if (gridPage.value !== 1) gridPage.value = 1 // options handler fetches
    else fetchGrid()
  }, 300)
})

watch(gridStatus, () => {
  if (gridPage.value !== 1) gridPage.value = 1 // options handler fetches
  else fetchGrid()
})

// Batch creation happens inside the dialog — refresh the grid when it
// closes so new rows appear without a manual reload.
watch(showBatchDialog, (open) => {
  if (!open) fetchGrid()
})

function statusColor(status: string) {
  switch (status) {
    case 'active':
      return 'success'
    case 'revoked':
      return 'error'
    case 'exhausted':
      return 'warning'
    case 'expired':
      return 'grey'
    default:
      return 'grey'
  }
}

function copyLink(code: string) {
  const url = `${appOrigin(window.location.origin)}/invite/${code}`
  navigator.clipboard.writeText(url)
  showSuccess(t('mh.invite.copied'))
}

async function handleCreate() {
  creating.value = true
  try {
    await inviteStore.createInvite(tenantId.value, {
      target_email: inviteType.value === 'email' ? targetEmail.value : undefined,
      max_uses: inviteType.value === 'link' ? maxUses.value : undefined,
      expires_in_hours: expiresInHours.value,
    })
    showCreateDialog.value = false
    targetEmail.value = ''
    maxUses.value = undefined
    expiresInHours.value = undefined
    showSuccess(t('mh.invite.created'))
    fetchGrid()
  } catch (e) {
    showError(e instanceof Error ? e.message : t('mh.invite.createFailed'))
  } finally {
    creating.value = false
  }
}

async function handleRevoke(inviteId: string) {
  try {
    await inviteStore.revokeInvite(tenantId.value, inviteId)
    showSuccess(t('mh.invite.revoked'))
  } catch (e) {
    showError(e instanceof Error ? e.message : t('mh.invite.revokeFailed'))
  }
}

onMounted(() => {
  // The grid's own fetch fires from @update:options on mount — only the
  // roles (for the batch dialog) load here.
  roleStore.fetchRoles(tenantId.value)
})
</script>

<style scoped>
/* Never squeeze the columns into the viewport — cells keep their natural
   width and the WRAPPER scrolls horizontally (house rule: wide tables
   scroll in their own container). FR-116: the desktop layout only — in the
   stacked rows of a phone these rules pushed every value off the edge. */
.invites-table :deep(.v-table__wrapper) {
  overflow-x: auto;
}
.invites-table:not(.invites-table--stacked) :deep(table) {
  width: max-content;
  min-width: 100%;
}
.invites-table:not(.invites-table--stacked) :deep(th),
.invites-table:not(.invites-table--stacked) :deep(td) {
  white-space: nowrap;
}
/* FR-116 — a stacked row's value can be one long unbroken token (an email,
   a file name): it wraps rather than widening the row past the screen. */
.invites-table--stacked :deep(.v-data-table__td-value) {
  min-width: 0;
  overflow-wrap: anywhere;
}
</style>
