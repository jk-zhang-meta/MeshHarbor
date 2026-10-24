// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from 'vitest'
import { PRODUCT_NAME, PRODUCT_NAME_ZH, PRODUCT_TITLE, UPSTREAM_ATTRIBUTION } from '@/utils/product'

describe('MeshHarbor display identity', () => {
  it('names the fork, including its Chinese name', () => {
    expect(PRODUCT_NAME).toBe('MeshHarbor')
    expect(PRODUCT_NAME_ZH).toBe('织港')
    expect(PRODUCT_TITLE).toBe('MeshHarbor · 织港')
  })
  it('retains explicit upstream attribution, not upstream product impersonation', () => {
    expect(UPSTREAM_ATTRIBUTION).toContain('Roomler')
    expect(UPSTREAM_ATTRIBUTION).toContain('G ROX EOOD')
  })
})
