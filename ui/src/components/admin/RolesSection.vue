<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-card>
    <v-card-title class="d-flex align-center">
      <span>{{ t('mh.roles.title') }}</span>
      <v-spacer />
      <v-btn
        prepend-icon="mdi-plus"
        color="primary"
        variant="flat"
        size="small"
        @click="openCreateDialog"
      >
        {{ t('mh.roles.new') }}
      </v-btn>
    </v-card-title>

    <v-card-text>
      <v-alert
        v-if="roleStore.error"
        type="error"
        variant="tonal"
        closable
        class="mb-4"
        @click:close="roleStore.error = null"
      >
        {{ roleStore.error }}
      </v-alert>

      <p class="text-body-2 text-medium-emphasis mb-4">
        <i18n-t keypath="mh.roles.intro" tag="span" scope="global">
          <template #perm><span class="font-weight-medium">{{ permissionLabel('MANAGE_ROLES') }}</span></template>
        </i18n-t>
      </p>

      <div v-if="roleStore.loading && roleStore.roles.length === 0" class="d-flex justify-center pa-8">
        <v-progress-circular indeterminate />
      </div>

      <p
        v-else-if="roleStore.roles.length === 0"
        class="text-medium-emphasis pa-4 pa-md-6"
      >
        {{ t('mh.roles.empty') }}
      </p>

      <!-- FR-116: `table-stack-xs` — on a phone each role is a block, with
           its actions on screen (the delete button sat past the edge). -->
      <v-table v-else density="compact" class="table-stack-xs">
        <thead>
          <tr>
            <th>{{ t('mh.roles.col.role') }}</th>
            <th>{{ t('mh.roles.col.permissions') }}</th>
            <th class="text-right">{{ t('mh.roles.col.actions') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="role in sortedRoles" :key="role.id">
            <td>
              <div class="d-flex align-center">
                <span
                  class="role-dot mr-2"
                  :style="{ backgroundColor: roleStore.colorHex(role.color) || 'rgb(var(--v-theme-on-surface-variant))' }"
                />
                <div>
                  <div class="font-weight-medium">
                    {{ role.name }}
                    <v-chip v-if="role.is_default" size="x-small" variant="tonal" class="ml-1">{{ t('mh.roles.default') }}</v-chip>
                    <v-chip v-if="role.is_managed" size="x-small" variant="tonal" class="ml-1">{{ t('mh.roles.managed') }}</v-chip>
                  </div>
                  <div v-if="role.description" class="text-caption text-medium-emphasis">
                    {{ role.description }}
                  </div>
                </div>
              </div>
            </td>
            <td data-label="Permissions">
              <v-chip
                v-if="isAdministrator(role.permissions)"
                size="x-small"
                color="warning"
                variant="tonal"
              >
                {{ t('mh.roles.adminAll') }}
              </v-chip>
              <template v-else>
                <!-- FR-116 — what a role grants was a hover tooltip and
                     nothing else, so a touch screen could not read it. A tap
                     (or Enter) now lists the grants under the count, at every
                     width; a mouse still gets the tooltip. -->
                <v-tooltip location="bottom" max-width="420" :disabled="touchOnly">
                  <template #activator="{ props: tip }">
                    <span
                      v-bind="tip"
                      class="text-body-2 grants-toggle"
                      role="button"
                      tabindex="0"
                      :aria-expanded="openGrants === role.id"
                      :data-testid="`role-grants-${role.id}`"
                      @click="toggleGrants(role.id)"
                      @keydown.enter.prevent="toggleGrants(role.id)"
                      @keydown.space.prevent="toggleGrants(role.id)"
                    >
                      {{ permissionSummary(role.permissions) }}
                    </span>
                  </template>
                  <span>{{ describePermissions(role.permissions).join(' · ') || t('mh.roles.noPermissions') }}</span>
                </v-tooltip>
                <div v-if="openGrants === role.id" class="d-flex flex-wrap ga-1 mt-1">
                  <v-chip
                    v-for="grant in describePermissions(role.permissions)"
                    :key="grant"
                    size="x-small"
                    variant="tonal"
                  >
                    {{ grant }}
                  </v-chip>
                </div>
              </template>
            </td>
            <td class="text-right text-no-wrap">
              <v-btn
                icon="mdi-pencil"
                size="small"
                variant="text"
                :disabled="role.is_managed"
                @click="openEditDialog(role)"
              />
              <v-btn
                icon="mdi-delete"
                size="small"
                variant="text"
                color="error"
                :disabled="role.is_default || role.is_managed"
                @click="openDeleteDialog(role)"
              />
            </td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>

  <!-- Create / edit dialog -->
  <!-- FR-116: full screen on a phone, scrolling inside so Save and Cancel stay
       on screen below ~30 permission boxes. -->
  <v-dialog
    v-model="editDialog"
    max-width="900"
    persistent
    :fullscreen="fullscreen"
    :scrollable="fullscreen"
  >
    <v-card>
      <v-card-title>{{ editingId ? t('mh.roles.edit') : t('mh.roles.new') }}</v-card-title>
      <v-card-text>
        <v-alert v-if="formError" type="error" variant="tonal" density="compact" class="mb-4">
          {{ formError }}
        </v-alert>

        <v-row dense>
          <v-col cols="12" md="6">
            <v-text-field
              v-model="form.name"
              :label="t('mh.roles.name')"
              variant="outlined"
              density="compact"
              hide-details
            />
          </v-col>
          <v-col cols="12" md="6">
            <v-text-field
              v-model.number="form.position"
              :label="t('mh.roles.position')"
              type="number"
              min="0"
              variant="outlined"
              density="compact"
              hide-details
            />
          </v-col>
          <v-col cols="12">
            <v-text-field
              v-model="form.description"
              :label="t('mh.roles.description')"
              variant="outlined"
              density="compact"
              hide-details
            />
          </v-col>
        </v-row>

        <div class="text-caption text-medium-emphasis mt-4 mb-1">{{ t('mh.roles.color') }}</div>
        <div class="d-flex align-center flex-wrap ga-1">
          <!-- 0 is the "no color" sentinel: the server stores it verbatim and
               colorHex(0) renders as colorless, which makes clearing an
               existing color possible (an omitted field is left unchanged). -->
          <v-btn
            v-for="swatch in COLOR_SWATCHES"
            :key="swatch"
            class="swatch"
            :style="swatch !== 0 ? { backgroundColor: hex(swatch) } : undefined"
            :icon="swatch === 0 ? 'mdi-water-off' : form.color === swatch ? 'mdi-check' : undefined"
            :variant="swatch === 0 ? 'outlined' : 'flat'"
            :class="{ 'swatch-selected': form.color === swatch }"
            @click="form.color = swatch"
          />
        </div>

        <div class="d-flex align-center flex-wrap mt-4 mb-1">
          <span
            class="text-caption text-medium-emphasis"
            :style="fullscreen ? 'flex-basis: 100%' : undefined"
          >{{ t('mh.roles.col.permissions') }}</span>
          <v-spacer />
          <v-btn size="x-small" variant="text" @click="applyPreset(DEFAULT_MEMBER)">{{ t('mh.roles.memberDefaults') }}</v-btn>
          <v-btn size="x-small" variant="text" @click="applyPreset(DEFAULT_ADMIN)">{{ t('mh.roles.adminDefaults') }}</v-btn>
          <v-btn size="x-small" variant="text" @click="applyPreset(0)">{{ t('mh.roles.none') }}</v-btn>
        </div>

        <v-alert
          v-if="maskHas(form.permissions, ADMINISTRATOR)"
          type="warning"
          variant="tonal"
          density="compact"
          class="mb-2"
        >
          {{ t('mh.roles.adminWarn') }}
        </v-alert>

        <v-row dense>
          <v-col v-for="group in PERMISSION_GROUPS" :key="group" cols="12" sm="6" md="4">
            <div class="text-caption font-weight-medium mb-1">{{ permissionGroupLabel(group) }}</div>
            <!-- FR-116 — on a touch screen the description is a hint under
                 the box: as a tooltip on the label, the tap meant to read it
                 toggled the permission instead. -->
            <v-checkbox
              v-for="flag in flagsFor(group)"
              :key="flag.key"
              :model-value="maskHas(form.permissions, flag.bit)"
              :label="flag.label"
              density="compact"
              :hide-details="touchOnly && flag.description ? 'auto' : true"
              :hint="touchOnly ? flag.description : undefined"
              :persistent-hint="touchOnly"
              @update:model-value="toggleFlag(flag.bit, $event as boolean)"
            >
              <template v-if="flag.description && !touchOnly" #label>
                <v-tooltip location="bottom" max-width="360">
                  <template #activator="{ props: tip }">
                    <span v-bind="tip">{{ flag.label }}</span>
                  </template>
                  <span>{{ flag.description }}</span>
                </v-tooltip>
              </template>
            </v-checkbox>
          </v-col>
        </v-row>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" :disabled="saving" @click="editDialog = false">{{ t('common.cancel') }}</v-btn>
        <v-btn color="primary" variant="flat" :loading="saving" @click="saveRole">
          {{ editingId ? t('mh.roles.save') : t('mh.roles.create') }}
        </v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <!-- Delete confirm -->
  <v-dialog v-model="deleteDialog" max-width="500">
    <v-card>
      <v-card-title>{{ t('mh.roles.deleteTitle') }}</v-card-title>
      <v-card-text>
        <i18n-t keypath="mh.roles.deleteBody" tag="span" scope="global">
          <template #name><span class="font-weight-medium">{{ deleteTarget?.name }}</span></template>
        </i18n-t>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" :disabled="deleting" @click="deleteDialog = false">{{ t('common.cancel') }}</v-btn>
        <v-btn color="error" variant="flat" :loading="deleting" @click="doDelete">{{ t('mh.common.delete') }}</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoleStore, type Role } from '@/stores/role'
import { useResponsiveDialog } from '@/composables/useResponsiveDialog'
import {
  ADMINISTRATOR,
  DEFAULT_ADMIN,
  DEFAULT_MEMBER,
  PERMISSION_FLAGS,
  PERMISSION_GROUPS,
  describePermissions,
  permissionGroupLabel,
  permissionLabel,
  maskHas,
  maskSet,
  maskClear,
} from '@/utils/permissions'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const props = defineProps<{ tenantId: string }>()

const roleStore = useRoleStore()
const { fullscreen } = useResponsiveDialog()

// FR-116 — a touch screen has no hover: tooltips give way to a tap that
// lists a role's grants, and to hints under the permission boxes.
const touchOnly = typeof window !== 'undefined' && !!window.matchMedia?.('(hover: none)').matches
const openGrants = ref<string | null>(null)
function toggleGrants(roleId: string) {
  openGrants.value = openGrants.value === roleId ? null : roleId
}

const sortedRoles = computed(() =>
  [...roleStore.roles].sort((a, b) => a.position - b.position || a.name.localeCompare(b.name)),
)

// A small predefined palette (stored as 0xRRGGBB u32; 0 = no color — the
// server round-trips it and colorHex(0) renders colorless).
const COLOR_SWATCHES: number[] = [
  0, 0x1976d2, 0x0d9488, 0x15803d, 0x65a30d, 0xb45309, 0xdc2626, 0xdb2777,
  0x7c3aed, 0x475569,
]

function hex(color: number): string {
  return `#${color.toString(16).padStart(6, '0')}`
}

function isAdministrator(mask: number): boolean {
  return maskHas(mask, ADMINISTRATOR)
}

function permissionSummary(mask: number): string {
  const n = describePermissions(mask).length
  return n === 0 ? t('mh.roles.noPermissions') : t(n === 1 ? 'mh.roles.permOne' : 'mh.roles.permMany', { n })
}

function flagsFor(group: string) {
  return PERMISSION_FLAGS.filter((f) => f.group === group)
}

// ── create / edit ──────────────────────────────────────────────────

interface RoleForm {
  name: string
  description: string
  color: number
  position: number
  permissions: number
}

function emptyForm(): RoleForm {
  return { name: '', description: '', color: 0, position: 100, permissions: DEFAULT_MEMBER }
}

const form = reactive<RoleForm>(emptyForm())
const editDialog = ref(false)
const editingId = ref<string | null>(null)
const saving = ref(false)
const formError = ref<string | null>(null)

function openCreateDialog() {
  Object.assign(form, emptyForm())
  editingId.value = null
  formError.value = null
  editDialog.value = true
}

function openEditDialog(role: Role) {
  Object.assign(form, {
    name: role.name,
    description: role.description ?? '',
    color: role.color ?? 0,
    position: role.position,
    permissions: role.permissions,
  })
  editingId.value = role.id
  formError.value = null
  editDialog.value = true
}

// #888: `|` and `&~` coerce to signed int32, which silently truncates any bit
// above 30 — and this is the WRITE path, so the corrupted mask is what gets
// saved. It would not throw; the role would just come back missing permissions.
function toggleFlag(bit: number, on: boolean) {
  form.permissions = on ? maskSet(form.permissions, bit) : maskClear(form.permissions, bit)
}

function applyPreset(mask: number) {
  form.permissions = mask
}

function validateForm(): string | null {
  if (!form.name.trim()) return t('mh.roles.nameRequired')
  if (!Number.isInteger(form.position) || form.position < 0) return t('mh.roles.positionInvalid')
  return null
}

function buildPayload() {
  // description/color are sent even when "empty" ('' / 0) — an OMITTED field
  // is left unchanged server-side, so omission would make clearing impossible.
  return {
    name: form.name.trim(),
    description: form.description.trim(),
    color: form.color,
    position: form.position,
    permissions: form.permissions,
  }
}

async function saveRole() {
  const invalid = validateForm()
  if (invalid) {
    formError.value = invalid
    return
  }
  saving.value = true
  formError.value = null
  try {
    if (editingId.value) {
      await roleStore.updateRole(props.tenantId, editingId.value, buildPayload())
    } else {
      await roleStore.createRole(props.tenantId, buildPayload())
    }
    editDialog.value = false
  } catch (e) {
    formError.value = (e as Error).message
  } finally {
    saving.value = false
  }
}

// ── delete ─────────────────────────────────────────────────────────

const deleteDialog = ref(false)
const deleteTarget = ref<Role | null>(null)
const deleting = ref(false)

function openDeleteDialog(role: Role) {
  deleteTarget.value = role
  deleteDialog.value = true
}

async function doDelete() {
  if (!deleteTarget.value) return
  deleting.value = true
  try {
    await roleStore.deleteRole(props.tenantId, deleteTarget.value.id)
    deleteDialog.value = false
  } catch (e) {
    roleStore.error = (e as Error).message
    deleteDialog.value = false
  } finally {
    deleting.value = false
  }
}

onMounted(() => roleStore.fetchRoles(props.tenantId))
</script>

<style scoped>
.role-dot {
  display: inline-block;
  width: 12px;
  height: 12px;
  border-radius: 50%;
  flex: 0 0 12px;
}
.swatch {
  width: 26px;
  height: 26px;
  min-width: 26px;
  border-radius: 50%;
}
.swatch-selected {
  outline: 2px solid rgb(var(--v-theme-primary));
  outline-offset: 1px;
}
.grants-toggle {
  cursor: pointer;
}
</style>
