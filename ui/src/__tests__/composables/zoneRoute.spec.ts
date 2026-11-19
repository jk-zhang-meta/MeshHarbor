import { describe, expect, it } from 'vitest'
import {
  parseLocalRelayDescriptor,
  zoneRoutePlan,
  type LocalRelayDescriptor,
} from '@/composables/useRemoteControl'

// FR-121 — the viewer follows the hub's zone route for the session.
const desc: LocalRelayDescriptor = {
  turn_port: 41000,
  overlay_ip: '100.64.7.20',
  username: 'u',
  credential: 'c',
  agent_id: '6af76f0e52bb0000aaaa0001',
}

describe('zoneRoutePlan', () => {
  it('changes nothing for a tenant without zones', () => {
    expect(zoneRoutePlan(undefined, desc)).toBe('none')
    expect(zoneRoutePlan(null, null)).toBe('none')
  })
  it('adds the local relay on every zoned route when there is a local agent', () => {
    for (const route of ['direct', 'direct_mesh', 'mesh', 'a-word-from-a-newer-server']) {
      expect(zoneRoutePlan(route, desc)).toBe('add_local_relay')
    }
  })
  it('knows when a zoned session has no local agent to relay through', () => {
    expect(zoneRoutePlan('direct', null)).toBe('no_local_agent')
  })
})

describe('parseLocalRelayDescriptor', () => {
  it('keeps the local agent id when the agent names it', () => {
    expect(parseLocalRelayDescriptor(desc)?.agent_id).toBe(desc.agent_id)
    const { agent_id: _drop, ...older } = desc
    expect(parseLocalRelayDescriptor(older)).toEqual(older)
  })
})
