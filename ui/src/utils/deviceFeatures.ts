// SPDX-License-Identifier: AGPL-3.0-only
/** The host's accepted choices, not an administrator's requested permissions. */
export const deviceFeatureKeys = [
  'desktop_view', 'desktop_control', 'clipboard', 'files', 'ssh', 'exec', 'rdp', 'network',
] as const
export type DeviceFeature = typeof deviceFeatureKeys[number]
export type DeviceAccessFeatures = Record<DeviceFeature, boolean>

/** Missing legacy selections are unknown, never silently presented as all-on. */
export function enabledDeviceFeatures(value: unknown): DeviceFeature[] | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const row = value as Record<string, unknown>
  if (deviceFeatureKeys.some(key => typeof row[key] !== 'boolean')) return null
  return deviceFeatureKeys.filter(key => row[key] === true)
}
