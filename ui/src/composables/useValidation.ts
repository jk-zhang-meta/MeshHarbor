// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import i18n from '@/plugins/i18n'

// Messages are read at validation time, so they follow the interface language.
const tr = (key: string, params: Record<string, unknown> = {}) => i18n.global.t(key, params)

export function useValidation() {
  const rules = {
    required: (v: unknown) => !!v || v === 0 || tr('mh.valid.required'),
    email: (v: string) => !v || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) || tr('mh.valid.email'),
    minLength: (n: number) => (v: string) => !v || v.length >= n || tr('mh.valid.minLength', { n }),
    maxLength: (n: number) => (v: string) => !v || v.length <= n || tr('mh.valid.maxLength', { n }),
    positiveNumber: (v: unknown) => (!v && v !== 0) || (Number(v) > 0) || tr('mh.valid.positive'),
    slug: (v: string) => !v || /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(v) || tr('mh.valid.slug'),
  }

  return { rules }
}
