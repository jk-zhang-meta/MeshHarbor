<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-card>
    <v-card-title class="d-flex align-center flex-wrap ga-2">
      <span>{{ t('mh.members.title') }}</span>
      <v-spacer />
      <!-- FR-11: server-side search over display name / email / nickname.
           FR-116: a row of its own on a phone, where 260 px beside the
           title left it ~100 px ("Searc"). -->
      <v-text-field
        v-model="gridSearch"
        density="compact"
        hide-details
        clearable
        prepend-inner-icon="mdi-magnify"
        :placeholder="t('mh.members.search')"
        :style="xs ? 'flex: 1 1 100%' : 'max-width: 260px'"
        :class="xs ? 'order-last' : 'flex-grow-0'"
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
        v-if="canAdd"
        color="primary"
        size="small"
        prepend-icon="mdi-account-plus"
        @click="openAddDialog"
      >
        {{ t('mh.members.add') }}
      </v-btn>
      <span class="text-body-2 text-medium-emphasis">{{ t('mh.members.total', { n: membersStore.total }) }}</span>
    </v-card-title>

    <v-card-text>
      <v-alert
        v-if="membersStore.error"
        type="error"
        variant="tonal"
        closable
        class="mb-4"
        @click:close="membersStore.error = null"
      >
        {{ membersStore.error }}
      </v-alert>

      <!-- Role chips + the assignment dialog need the role list; a failed
           role fetch must not masquerade as "member has no roles". -->
      <v-alert
        v-if="roleStore.error"
        type="error"
        variant="tonal"
        closable
        class="mb-4"
        @click:close="roleStore.error = null"
      >
        {{ t('mh.members.rolesFailed', { error: roleStore.error }) }}
      </v-alert>

      <p class="text-body-2 text-medium-emphasis mb-4">
        <i18n-t keypath="mh.members.intro" tag="span" scope="global">
          <template #perm><span class="font-weight-medium">{{ permissionLabel('MANAGE_ROLES') }}</span></template>
        </i18n-t>
      </p>

      <v-data-table-server
        v-model:page="gridPage"
        v-model:items-per-page="gridPerPage"
        :headers="effectiveHeaders"
        :items="membersStore.items"
        :items-length="membersStore.total"
        :loading="membersStore.loading"
        :items-per-page-options="[10, 25, 50, 100]"
        density="compact"
        class="members-table"
        :class="{ 'members-table--stacked': xs }"
        item-value="id"
        :mobile="xs"
        @update:options="onGridOptions"
      >
        <template #item.name="{ item }">
          <div class="font-weight-medium">{{ item.display_name || '(unknown)' }}</div>
          <div v-if="item.nickname" class="text-caption text-medium-emphasis">
            {{ item.nickname }}
          </div>
        </template>
        <template #item.email="{ item }">
          <span v-if="item.email">{{ item.email }}</span>
          <span v-else class="text-caption text-medium-emphasis">—</span>
        </template>
        <template #item.roles="{ item }">
          <template v-if="item.role_ids.length">
            <v-chip
              v-for="role in rolesOf(item)"
              :key="role.id"
              size="x-small"
              variant="tonal"
              class="mr-1 mb-1"
              :style="chipStyle(role)"
            >
              {{ role.name }}
            </v-chip>
          </template>
          <span v-else class="text-caption text-medium-emphasis">—</span>
        </template>
        <template #item.joined_at="{ item }">
          {{ joinedLabel(item.joined_at) }}
        </template>
        <template #item.actions="{ item }">
          <div class="text-no-wrap">
            <v-btn
              size="small"
              variant="text"
              prepend-icon="mdi-shield-account"
              @click="openRolesDialog(item)"
            >
              Roles
            </v-btn>
            <!-- The owner is unremovable (server 409s as the backstop);
                 removing YOURSELF is "leave". -->
            <v-btn
              v-if="item.user_id !== ownerId"
              size="small"
              variant="text"
              color="error"
              :prepend-icon="item.user_id === myUserId ? 'mdi-exit-run' : 'mdi-account-remove'"
              @click="askRemove(item)"
            >
              {{ item.user_id === myUserId ? t('mh.members.leave') : t('mh.members.remove') }}
            </v-btn>
            <v-tooltip v-else :text="t('mh.members.ownerFixed')" location="top">
              <template #activator="{ props: tipProps }">
                <v-icon v-bind="tipProps" size="small" class="ml-2 text-medium-emphasis">
                  mdi-crown
                </v-icon>
              </template>
            </v-tooltip>
          </div>
        </template>
      </v-data-table-server>
    </v-card-text>
  </v-card>

  <GridColumnPickerDialog
    v-model="colDialogOpen"
    :entries="colEntries"
    @toggle="colToggle"
    @reorder="colReorder"
    @reset="colReset"
  />

  <!-- FR-11: add an existing account by email — no invite round-trip. -->
  <v-dialog v-model="addDialog" max-width="440">
    <v-card>
      <v-card-title>{{ t('mh.members.addTitle') }}</v-card-title>
      <v-card-text>
        <v-alert v-if="addError" type="error" variant="tonal" density="compact" class="mb-4">
          {{ addError }}
        </v-alert>
        <p class="text-body-2 text-medium-emphasis mb-3">
          {{ t('mh.members.addBody') }}
        </p>
        <v-text-field
          v-model="addEmail"
          :label="t('mh.members.email')"
          type="email"
          autofocus
          :rules="[rules.email]"
          @keydown.enter="submitAdd"
        />
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="addDialog = false">{{ t('common.cancel') }}</v-btn>
        <v-btn color="primary" :loading="addBusy" :disabled="!addEmail" @click="submitAdd">
          {{ t('mh.members.addBtn') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <ConfirmDialog
    v-model="removeDialog"
    :title="removeTarget?.user_id === myUserId ? t('mh.members.leaveTitle') : t('mh.members.removeTitle')"
    :message="removeMessage"
    confirm-color="error"
    @confirm="doRemove"
  />

  <!-- Per-member role assignment -->
  <v-dialog v-model="rolesDialog" max-width="500">
    <v-card>
      <v-card-title>
        {{ t('mh.members.rolesTitle', { name: dialogMember?.display_name }) }}
      </v-card-title>
      <v-card-text>
        <v-alert v-if="dialogError" type="error" variant="tonal" density="compact" class="mb-4">
          {{ dialogError }}
        </v-alert>

        <p v-if="roleStore.error" class="text-error">
          {{ t('mh.members.rolesUnloaded', { error: roleStore.error }) }}
        </p>
        <p v-else-if="roleStore.roles.length === 0" class="text-medium-emphasis">
          {{ t('mh.members.noRoles') }}
        </p>

        <v-list v-else density="compact">
          <v-list-item v-for="role in sortedRoles" :key="role.id" class="px-0">
            <template #prepend>
              <!-- v-checkbox-btn has no `loading` prop (silent no-op) — the
                   in-flight row shows an explicit spinner instead. -->
              <v-progress-circular
                v-if="busyRoleId === role.id"
                indeterminate
                size="20"
                width="2"
                class="mx-3"
              />
              <v-checkbox-btn
                v-else
                :model-value="memberHasRole(role.id)"
                :disabled="busyRoleId !== null"
                @update:model-value="toggleRole(role, $event as boolean)"
              />
            </template>
            <v-list-item-title>
              <span
                class="role-dot mr-2"
                :style="{ backgroundColor: roleStore.colorHex(role.color) || 'rgb(var(--v-theme-on-surface-variant))' }"
              />
              {{ role.name }}
              <v-chip v-if="role.is_default" size="x-small" variant="tonal" class="ml-1">{{ t('mh.roles.default') }}</v-chip>
            </v-list-item-title>
            <v-list-item-subtitle v-if="role.description">
              {{ role.description }}
            </v-list-item-subtitle>
          </v-list-item>
        </v-list>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="rolesDialog = false">{{ t('mh.members.done') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useDisplay } from 'vuetify'
import { useMembersStore, type Member } from '@/stores/members'
import { useRoleStore, type Role } from '@/stores/role'
import { useTenantStore } from '@/stores/tenant'
import { useAuthStore } from '@/stores/auth'
import { useValidation } from '@/composables/useValidation'
import { canManageInvites, permissionLabel } from '@/utils/permissions'
import { useGridColumns } from '@/composables/useGridColumns'
import GridColumnPickerDialog from '@/components/common/GridColumnPickerDialog.vue'
import ConfirmDialog from '@/components/common/ConfirmDialog.vue'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps<{ tenantId: string }>()

const membersStore = useMembersStore()
const roleStore = useRoleStore()
const tenantStore = useTenantStore()
const auth = useAuthStore()
const { rules } = useValidation()
// FR-116 — below 600 px each member is a stacked row (Vuetify's mobile
// rows, from the same headers): the Roles column and the Roles / Remove
// actions were behind a sideways scroll inside the table.
const { xs } = useDisplay()

const myUserId = computed(() => auth.user?.id)
const ownerId = computed(() => tenantStore.current?.owner_id)
const canAdd = computed(() => canManageInvites(tenantStore.myPermissions, tenantStore.isOwner))

// ── grid state (devices-grid kit) ──────────────────────────────────

const gridPage = ref(1)
const gridPerPage = ref(25)
const gridSearch = ref('')
const gridSort = ref<string | undefined>(undefined)
const gridDir = ref<'asc' | 'desc' | undefined>(undefined)

const memberHeaders = computed(() => [
  // Keys double as the server sort keys (name | email | joined_at).
  { title: t('mh.members.col.member'), key: 'name', sortable: true },
  { title: t('mh.members.col.email'), key: 'email', sortable: true },
  { title: t('mh.members.col.roles'), key: 'roles', sortable: false },
  { title: t('mh.members.col.joined'), key: 'joined_at', sortable: true },
  { title: t('mh.members.col.actions'), key: 'actions', sortable: false, align: 'end' as const },
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
  headers: memberHeaders,
  gridId: 'members',
  scope: () => `${auth.user?.id ?? 'anon'}:${props.tenantId}`,
})

function fetchGrid() {
  void membersStore.fetchMembers(props.tenantId, {
    page: gridPage.value,
    perPage: gridPerPage.value,
    q: gridSearch.value || undefined,
    sort: gridSort.value,
    dir: gridDir.value,
  })
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

// Roles for the chips — cheap and idempotent if the Roles section already
// loaded them. (The grid itself first fetches from @update:options.)
void roleStore.fetchRoles(props.tenantId)

const sortedRoles = computed(() =>
  [...roleStore.roles].sort((a, b) => a.position - b.position || a.name.localeCompare(b.name)),
)

function rolesOf(member: Member): Role[] {
  return sortedRoles.value.filter((r) => member.role_ids.includes(r.id))
}

function chipStyle(role: Role) {
  const color = roleStore.colorHex(role.color)
  return color ? { color } : undefined
}

function joinedLabel(iso: string): string {
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleDateString()
}

// ── add by email (FR-11) ───────────────────────────────────────────

const addDialog = ref(false)
const addEmail = ref('')
const addError = ref<string | null>(null)
const addBusy = ref(false)

function openAddDialog() {
  addEmail.value = ''
  addError.value = null
  addDialog.value = true
}

async function submitAdd() {
  if (!addEmail.value || addBusy.value) return
  addBusy.value = true
  addError.value = null
  try {
    await membersStore.addByEmail(props.tenantId, addEmail.value.trim())
    addDialog.value = false
    fetchGrid()
  } catch (e) {
    addError.value = (e as Error).message
  } finally {
    addBusy.value = false
  }
}

// ── remove / leave (FR-11) ─────────────────────────────────────────

const removeDialog = ref(false)
const removeTarget = ref<Member | null>(null)

const removeMessage = computed(() => {
  const m = removeTarget.value
  if (!m) return ''
  return m.user_id === myUserId.value
    ? t('mh.members.leaveMsg')
    : t('mh.members.removeMsg', { who: m.display_name || m.email || t('mh.members.thisMember') })
})

function askRemove(member: Member) {
  removeTarget.value = member
  removeDialog.value = true
}

async function doRemove() {
  const m = removeTarget.value
  if (!m) return
  try {
    await membersStore.removeMember(props.tenantId, m.user_id)
    fetchGrid()
  } catch (e) {
    membersStore.error = (e as Error).message
  }
}

// ── per-member role dialog ─────────────────────────────────────────
// Toggles apply IMMEDIATELY (one API call each, matching the endpoint
// granularity); the members store mirrors the change locally so the table
// row updates without a refetch.

const rolesDialog = ref(false)
const dialogMember = ref<Member | null>(null)
const dialogError = ref<string | null>(null)
const busyRoleId = ref<string | null>(null)

function openRolesDialog(member: Member) {
  dialogMember.value = member
  dialogError.value = null
  rolesDialog.value = true
}

function memberHasRole(roleId: string): boolean {
  return dialogMember.value?.role_ids.includes(roleId) ?? false
}

async function toggleRole(role: Role, on: boolean) {
  const member = dialogMember.value
  if (!member || busyRoleId.value) return
  busyRoleId.value = role.id
  dialogError.value = null
  try {
    if (on) {
      await roleStore.assignRole(props.tenantId, role.id, member.user_id)
    } else {
      await roleStore.unassignRole(props.tenantId, role.id, member.user_id)
    }
    membersStore.setMemberRole(member.user_id, role.id, on)
  } catch (e) {
    dialogError.value = (e as Error).message
  } finally {
    busyRoleId.value = null
  }
}
</script>

<style scoped>
.role-dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
}

/* Never squeeze the columns into the viewport — cells keep their natural
   width and the WRAPPER scrolls horizontally (house rule: wide tables
   scroll in their own container). FR-116: the desktop layout only — in the
   stacked rows of a phone these rules pushed every value off the edge. */
.members-table :deep(.v-table__wrapper) {
  overflow-x: auto;
}
.members-table:not(.members-table--stacked) :deep(table) {
  width: max-content;
  min-width: 100%;
}
.members-table:not(.members-table--stacked) :deep(th),
.members-table:not(.members-table--stacked) :deep(td) {
  white-space: nowrap;
}
/* FR-116 — a stacked row's value can be one long unbroken token (an email,
   a file name): it wraps rather than widening the row past the screen. */
.members-table--stacked :deep(.v-data-table__td-value) {
  min-width: 0;
  overflow-wrap: anywhere;
}
</style>
