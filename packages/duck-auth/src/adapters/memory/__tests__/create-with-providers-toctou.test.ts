import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '..'

describe('MemoryAdapter.create - provider-sub uniqueness', () => {
  it('two concurrent creates with the same (providerId, sub): exactly one succeeds', async () => {
    const adapter = new MemoryAdapter<{ email: string; username: string }>()
    const link = { providerId: 'authGoogle', providerSub: 'sub-X', addedAt: new Date() }
    const results = await Promise.allSettled([
      adapter.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' }, providers: [link] }, {}),
      adapter.identities.create({ profile: { email: 'b@x.com', username: 'b@x.com' }, providers: [link] }, {}),
    ])
    const fulfilled = results.filter((r) => r.status === 'fulfilled')
    const rejected = results.filter((r) => r.status === 'rejected')
    expect(fulfilled).toHaveLength(1)
    expect(rejected).toHaveLength(1)
    const first = rejected[0]
    if (first && first.status === 'rejected') {
      expect(first.reason).toMatchObject({
        code: 'AUTH_PROVIDER_FAILED',
        meta: { detail: 'provider sub already linked to a different identity' },
      })
    } else {
      throw new Error('expected one rejection')
    }
  })

  it('many concurrent creates: exactly one wins', async () => {
    const adapter = new MemoryAdapter<{ email: string; username: string }>()
    const link = { providerId: 'authGithub', providerSub: 'race-sub', addedAt: new Date() }
    const calls = Array.from({ length: 15 }, (_, i) =>
      adapter.identities.create({ profile: { email: `r-${i}@x.com`, username: `r-${i}` }, providers: [link] }, {}),
    )
    const results = await Promise.allSettled(calls)
    const fulfilled = results.filter((r) => r.status === 'fulfilled')
    expect(fulfilled).toHaveLength(1)
    expect(results.filter((r) => r.status === 'rejected')).toHaveLength(14)
  })

  it('create without providers (empty) is unaffected', async () => {
    const adapter = new MemoryAdapter<{ email: string; username: string }>()
    const a = await adapter.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' }, providers: [] }, {})
    const b = await adapter.identities.create({ profile: { email: 'b@x.com', username: 'b@x.com' }, providers: [] }, {})
    expect(a.id).not.toBe(b.id)
  })

  it('create with provider link that has undefined sub (magic-link-style) is allowed', async () => {
    const adapter = new MemoryAdapter<{ email: string; username: string }>()
    const a = await adapter.identities.create(
      {
        profile: { email: 'a@x.com', username: 'a@x.com' },
        providers: [{ providerId: 'magic-link', providerSub: null, addedAt: new Date() }],
      },
      {},
    )
    // Second create with the same providerId (no sub) - should succeed
    // because the uniqueness invariant only applies when both sides
    // carry a sub.
    const b = await adapter.identities.create(
      {
        profile: { email: 'b@x.com', username: 'b@x.com' },
        providers: [{ providerId: 'magic-link', providerSub: null, addedAt: new Date() }],
      },
      {},
    )
    expect(a.id).not.toBe(b.id)
  })

  it('after race, findByProviderSub returns exactly ONE identity', async () => {
    const adapter = new MemoryAdapter<{ email: string; username: string }>()
    const link = { providerId: 'authGoogle', providerSub: 'race-X', addedAt: new Date() }
    await Promise.allSettled([
      adapter.identities.create({ profile: { email: 'a@x.com', username: 'a@x.com' }, providers: [link] }, {}),
      adapter.identities.create({ profile: { email: 'b@x.com', username: 'b@x.com' }, providers: [link] }, {}),
      adapter.identities.create({ profile: { email: 'c@x.com', username: 'c@x.com' }, providers: [link] }, {}),
    ])
    const found = await adapter.identities.findByProviderSub('authGoogle', 'race-X', {})
    expect(found).not.toBeNull()
    // Only one row should exist with this sub. Verify by counting.
    let count = 0
    const store = (
      adapter as unknown as { _identities: Map<string, { providers: { providerId: string; providerSub?: string }[] }> }
    )._identities
    for (const i of store.values()) {
      if (i.providers.some((p) => p.providerId === 'authGoogle' && p.providerSub === 'race-X')) {
        count++
      }
    }
    expect(count).toBe(1)
  })
})
