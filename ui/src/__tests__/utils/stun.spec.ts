import { describe, expect, it } from 'vitest'
import { defaultStunServers } from '@/utils/stun'

describe('STUN provider redundancy', () => {
  it('matches API/native discovery without fake TURN credentials or forcing relay', () => {
    const servers = defaultStunServers()
    expect(servers).toEqual([{ urls: ['stun:stun.cloudflare.com:3478', 'stun:stun.l.google.com:19302'] }])
    expect(servers[0]!.urls.every((url) => url.startsWith('stun:'))).toBe(true)
    expect(servers[0]).not.toHaveProperty('username')
    expect(servers[0]).not.toHaveProperty('credential')
  })
  it('does not let a prior caller mutate a later fallback', () => {
    defaultStunServers()[0]!.urls.length = 0
    expect(defaultStunServers()[0]!.urls).toHaveLength(2)
  })
})
