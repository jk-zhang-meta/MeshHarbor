<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 G ROX EOOD -->
<template>
  <v-list density="compact" max-width="400" class="notification-panel">
    <v-list-subheader class="d-flex align-center">
      <span>{{ t('mh.notif.title') }}</span>
      <v-spacer />
      <v-btn
        v-if="store.unreadCount > 0"
        variant="text"
        size="small"
        @click="store.markAllRead()"
      >
        {{ t('mh.notif.markAllRead') }}
      </v-btn>
    </v-list-subheader>

    <div v-if="store.loading" class="text-center pa-4">
      <v-progress-circular size="20" indeterminate />
    </div>

    <template v-else-if="store.notifications.length === 0">
      <v-list-item class="text-medium-emphasis text-center">
        {{ t('mh.notif.empty') }}
      </v-list-item>
    </template>

    <template v-else>
      <v-list-item
        v-for="notif in store.notifications"
        :key="notif.id"
        :class="{ 'notification-unread': !notif.is_read }"
        @click="handleClick(notif)"
        lines="two"
      >
        <template #prepend>
          <v-icon
            :color="notif.is_read ? undefined : 'primary'"
            size="small"
          >
            {{ iconFor(notif.notification_type) }}
          </v-icon>
        </template>
        <!-- Wraps: the title is the whole notification; one clipped line
             could only be read by tapping it, which also navigates away. -->
        <v-list-item-title class="text-body-2 text-wrap">{{ notif.title }}</v-list-item-title>
        <v-list-item-subtitle class="text-caption">
          {{ formatTime(notif.created_at) }}
        </v-list-item-subtitle>
      </v-list-item>
    </template>
  </v-list>
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useNotificationStore, type Notification } from '@/stores/notification'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()

const store = useNotificationStore()
const router = useRouter()

const emit = defineEmits<{
  close: []
}>()

function iconFor(type: string): string {
  switch (type) {
    case 'mention': return 'mdi-at'
    case 'message': return 'mdi-message-text'
    case 'reaction': return 'mdi-emoticon'
    case 'invite': return 'mdi-account-plus'
    case 'call': return 'mdi-phone'
    // FR-90 — an agent session waits for a driver.
    case 'approval_request': return 'mdi-shield-key'
    default: return 'mdi-bell'
  }
}

function formatTime(iso: string): string {
  const d = new Date(iso)
  const now = new Date()
  const diff = now.getTime() - d.getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return t('mh.ago.now')
  if (mins < 60) return t('mh.ago.m', { n: mins })
  const hours = Math.floor(mins / 60)
  if (hours < 24) return t('mh.ago.h', { n: hours })
  const days = Math.floor(hours / 24)
  return t('mh.ago.d', { n: days })
}

function handleClick(notif: Notification) {
  if (!notif.is_read) {
    store.markRead(notif.id)
  }
  if (notif.link) {
    router.push(notif.link)
  }
  emit('close')
}

onMounted(() => {
  store.fetchNotifications()
})
</script>

<style scoped>
.notification-panel {
  max-height: 400px;
  overflow-y: auto;
}
.notification-unread {
  background: rgba(var(--v-theme-primary), 0.06);
}
</style>
