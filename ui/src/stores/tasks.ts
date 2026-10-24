// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { appPath } from '@/utils/deployment'
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'

interface BackgroundTask {
  id: string
  task_type: string
  status: string
  progress: number
  file_name?: string
  error?: string
  created_at: string
}

export const useTaskStore = defineStore('tasks', () => {
  const tasks = ref<BackgroundTask[]>([])
  const loading = ref(false)

  async function fetchTasks(tenantId: string) {
    loading.value = true
    try {
      const data = await api.get<{ items: BackgroundTask[] }>(`/tenant/${tenantId}/task`)
      tasks.value = data.items
    } finally {
      loading.value = false
    }
  }

  async function getTask(tenantId: string, taskId: string) {
    return api.get<BackgroundTask>(`/tenant/${tenantId}/task/${taskId}`)
  }

  function updateFromWs(task: BackgroundTask) {
    const idx = tasks.value.findIndex((t) => t.id === task.id)
    if (idx !== -1) {
      tasks.value[idx] = task
    } else {
      tasks.value.push(task)
    }
  }

  function downloadUrl(tenantId: string, taskId: string): string {
    return appPath(`/api/tenant/${tenantId}/task/${taskId}/download`)
  }

  return { tasks, loading, fetchTasks, getTask, updateFromWs, downloadUrl }
})
