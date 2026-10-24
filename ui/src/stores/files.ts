// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { appPath } from '@/utils/deployment'
import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api } from '@/api/client'

interface FileEntry {
  id: string
  tenant_id: string
  filename: string
  content_type: string
  size: number
  uploaded_by: string
  created_at: string
  room_id?: string
  room_name?: string
}

interface FilesPage {
  items: FileEntry[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

/** FR-11 grid params — mirrors the server's flat FileListQuery. */
export interface FileFetchOpts {
  page?: number
  perPage?: number
  q?: string
  /** Server whitelist: filename | size | created_at (absent = created_at desc). */
  sort?: string
  dir?: 'asc' | 'desc'
}

export const useFileStore = defineStore('files', () => {
  const files = ref<FileEntry[]>([])
  const total = ref(0)
  const page = ref(1)
  const perPage = ref(25)
  const totalPages = ref(1)
  const loading = ref(false)

  // Stale-response guard (devices-grid pattern): the LAST issued fetch wins.
  let seq = 0

  function buildQuery(o: FileFetchOpts): string {
    const params = new URLSearchParams()
    params.set('page', String(o.page ?? 1))
    params.set('per_page', String(o.perPage ?? perPage.value))
    if (o.q) params.set('q', o.q)
    if (o.sort) {
      params.set('sort', o.sort)
      if (o.dir) params.set('dir', o.dir)
    }
    return params.toString()
  }

  async function fetchPage(path: string, mySeq: number) {
    loading.value = true
    try {
      const data = await api.get<FilesPage>(path)
      if (mySeq !== seq) return
      files.value = data.items
      total.value = data.total
      page.value = data.page
      perPage.value = data.per_page
      totalPages.value = data.total_pages
    } finally {
      if (mySeq === seq) loading.value = false
    }
  }

  async function fetchFiles(tenantId: string, roomId: string, opts: FileFetchOpts = {}) {
    await fetchPage(`/tenant/${tenantId}/room/${roomId}/file?${buildQuery(opts)}`, ++seq)
  }

  async function fetchTenantFiles(tenantId: string, opts: FileFetchOpts = {}) {
    await fetchPage(`/tenant/${tenantId}/file?${buildQuery(opts)}`, ++seq)
  }

  async function uploadFile(tenantId: string, roomId: string, file: File) {
    const form = new FormData()
    form.append('file', file)
    form.append('room_id', roomId)
    const entry = await api.upload<FileEntry>(
      `/tenant/${tenantId}/file/upload`,
      form,
    )
    files.value.push(entry)
    return entry
  }

  async function deleteFile(tenantId: string, fileId: string) {
    await api.delete(`/tenant/${tenantId}/file/${fileId}`)
    files.value = files.value.filter((f) => f.id !== fileId)
  }

  function downloadUrl(tenantId: string, fileId: string): string {
    return appPath(`/api/tenant/${tenantId}/file/${fileId}/download`)
  }

  return {
    files,
    total,
    page,
    perPage,
    totalPages,
    loading,
    fetchFiles,
    fetchTenantFiles,
    uploadFile,
    deleteFile,
    downloadUrl,
  }
})
