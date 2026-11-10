// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
import { beforeEach, describe, expect, it } from 'vitest'
import { ref } from 'vue'
import {
  deviceLabel,
  hideDeviceNameKey,
  secondaryDeviceName,
  useHideDeviceName,
} from '@/composables/useHideDeviceName'

describe('useHideDeviceName', () => {
  beforeEach(() => localStorage.clear())

  it('keeps the key the Devices grid has always written, so saved choices carry over', () => {
    expect(hideDeviceNameKey('u1:t1')).toBe('meshharbor:grid-name-pref:u1:t1:devices')
    localStorage.setItem('meshharbor:grid-name-pref:u1:t1:devices', '0')
    expect(useHideDeviceName(() => 'u1:t1').value).toBe(false)
  })

  it('defaults to hiding when nothing is stored', () => {
    expect(useHideDeviceName(() => 'u1:t1').value).toBe(true)
  })

  it('persists a flip, and a surface already mounted sees it at once', () => {
    const grid = useHideDeviceName(() => 'u1:t1')
    const remote = useHideDeviceName(() => 'u1:t1')
    expect(remote.value).toBe(true)
    grid.value = false
    expect(localStorage.getItem('meshharbor:grid-name-pref:u1:t1:devices')).toBe('0')
    expect(remote.value).toBe(false)
    remote.value = true
    expect(grid.value).toBe(true)
  })

  it('is per user and per org', () => {
    useHideDeviceName(() => 'u1:t1').value = false
    expect(useHideDeviceName(() => 'u1:t2').value).toBe(true)
    expect(useHideDeviceName(() => 'u2:t1').value).toBe(true)
  })

  it('re-reads when the scope changes (org switch, or the user arriving late)', () => {
    localStorage.setItem('meshharbor:grid-name-pref:u1:t2:devices', '0')
    const scope = ref('u1:t1')
    const pref = useHideDeviceName(scope)
    expect(pref.value).toBe(true)
    scope.value = 'u1:t2'
    expect(pref.value).toBe(false)
  })

  it('follows a flip made in another tab', () => {
    const pref = useHideDeviceName(() => 'u1:t1')
    expect(pref.value).toBe(true)
    localStorage.setItem('meshharbor:grid-name-pref:u1:t1:devices', '0')
    window.dispatchEvent(
      new StorageEvent('storage', { key: 'meshharbor:grid-name-pref:u1:t1:devices', newValue: '0' }),
    )
    expect(pref.value).toBe(false)
  })
})

describe('secondaryDeviceName', () => {
  const named = { name: 'DESKTOP-8F3K2L', display_name: 'Reception PC' }

  it('shows the machine name beside a display name only when not hidden', () => {
    expect(secondaryDeviceName(named, false)).toBe('DESKTOP-8F3K2L')
    expect(secondaryDeviceName(named, true)).toBeNull()
  })

  it('adds nothing when there is no display name, or it equals the name', () => {
    expect(secondaryDeviceName({ name: 'DESKTOP-8F3K2L' }, false)).toBeNull()
    expect(secondaryDeviceName({ name: 'DESKTOP-8F3K2L', display_name: '' }, false)).toBeNull()
    expect(secondaryDeviceName({ name: 'pc', display_name: 'pc' }, false)).toBeNull()
    expect(secondaryDeviceName(null, false)).toBeNull()
  })
})

describe('deviceLabel', () => {
  it('is the display name when one is set, else the machine name', () => {
    expect(deviceLabel({ name: 'build-01', display_name: 'Build Server' })).toBe('Build Server')
    expect(deviceLabel({ name: 'build-01' })).toBe('build-01')
    expect(deviceLabel({ name: 'build-01', display_name: '' })).toBe('build-01')
    expect(deviceLabel({ name: 'build-01', display_name: null })).toBe('build-01')
  })

  it('is empty, never "undefined", for no device', () => {
    expect(deviceLabel(null)).toBe('')
    expect(deviceLabel(undefined)).toBe('')
  })
})
