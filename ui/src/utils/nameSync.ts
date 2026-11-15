// SPDX-License-Identifier: AGPL-3.0-only
/** Device acknowledgement is distinct from a successfully saved server name. */
export interface NameSync {
  revision: string
  acked_revision: string | null
  event_seq?: string
  state: 'pending' | 'synced' | 'failed' | 'unsupported' | 'unverified'
  scope?: 'device' | 'organization_alias'
  error?: string | null
}

function revision(value: string | null | undefined): bigint | null {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,18})$/.test(value)) return null
  const parsed = BigInt(value)
  return parsed <= 9223372036854775807n ? parsed : null
}

export function shouldAcceptNameSync(current: NameSync | undefined, incoming: NameSync): boolean {
  const next = revision(incoming.revision)
  const ack = incoming.acked_revision === null ? 0n : revision(incoming.acked_revision)
  if (next === null || ack === null || ack > next) return false
  if (!current) return true
  const previous = revision(current.revision)
  const previousAck = current.acked_revision === null ? 0n : revision(current.acked_revision)
  if (previous === null || previousAck === null) return true
  const seq = revision(incoming.event_seq)
  const previousSeq = revision(current.event_seq)
  if (previousSeq !== null && seq === null) return false
  if (seq !== null && previousSeq !== null) return seq >= previousSeq && next >= previous
  return next > previous || (next === previous && ack >= previousAck)
}

export function mergeNameSync<T extends { name: string; name_sync?: NameSync }>(current: T, incoming: Partial<T>): T {
  const merged = { ...current, ...incoming }
  if (current.name_sync && (!incoming.name_sync || !shouldAcceptNameSync(current.name_sync, incoming.name_sync))) {
    merged.name = current.name
    merged.name_sync = current.name_sync
  }
  return merged
}

/** Only clear evidence captured before this save, never a newer live ACK. */
export function sameNameSyncSnapshot(current?: NameSync, before?: NameSync): boolean {
  return current === before || !!(current && before && current.event_seq !== undefined &&
    current.event_seq === before.event_seq && current.revision === before.revision)
}

export function nameSyncPresentation(sync?: NameSync) {
  const key = sync?.scope === 'organization_alias' ? 'organizationAlias'
    : !sync || revision(sync.revision) === null ? 'unverified'
      : sync.state === 'synced' && sync.acked_revision !== sync.revision ? 'pending'
        : sync.state
  const color = key === 'synced' || key === 'organizationAlias' ? 'success'
    : key === 'failed' ? 'error' : key === 'pending' ? 'info' : 'warning'
  return { key, color } as const
}
