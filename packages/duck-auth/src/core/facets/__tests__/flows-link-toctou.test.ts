import { beforeEach, describe, expect, it } from 'vitest'
import { MemoryAdapter } from '../../../adapters/memory'
import { AuthMemoryLimiter } from '../../../limiters/memory'
import { AuthEngine } from '../../auth'
import { ScryptHasher } from '../../password/scrypt'
import { AuthCookieTransport } from '../../transport/cookie'

interface ProfileShape {
  email: string
}

function build() {
  const adapter = new MemoryAdapter<ProfileShape>()
  const auth = new AuthEngine<ProfileShape>({
    baseUrl: 'https://app.test',
    transport: new AuthCookieTransport({ secure: false, name: 'duck-sid' }),
    stores: {
      identities: adapter.identities,
      sessions: adapter.sessions,
      credentials: adapter.credentials,
    },
    limiter: new AuthMemoryLimiter({ max: 50, windowMs: 60_000 }),
    passwords: { hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) },
  })
  return { auth, adapter }
}

describe('FlowsFacet.linkProvider - TOCTOU defense', () => {
  let auth: AuthEngine<ProfileShape>
  let adapter: MemoryAdapter<ProfileShape>
  let identityA: string
  let identityB: string

  beforeEach(async () => {
    ;({ auth, adapter } = build())
    const a = await auth.identities.create({ profile: { email: 'a@x.com' } })
    const b = await auth.identities.create({ profile: { email: 'b@x.com' } })
    identityA = a.id
    identityB = b.id
  })

  it('two concurrent linkProvider calls for same (providerId, providerSub) onto DIFFERENT identities: exactly one succeeds', async () => {
    const results = await Promise.allSettled([
      auth.flows.linkProvider({ identityId: identityA, providerId: 'authGoogle', providerSub: 'sub-X' }),
      auth.flows.linkProvider({ identityId: identityB, providerId: 'authGoogle', providerSub: 'sub-X' }),
    ])
    const fulfilled = results.filter((r) => r.status === 'fulfilled')
    const rejected = results.filter((r) => r.status === 'rejected')
    expect(fulfilled).toHaveLength(1)
    expect(rejected).toHaveLength(1)
    const firstRejected = rejected[0]
    if (firstRejected && firstRejected.status === 'rejected') {
      expect(firstRejected.reason).toMatchObject({
        code: 'AUTH/PROVIDER_FAILED',
        meta: { detail: 'provider sub already linked to a different identity' },
      })
    } else {
      throw new Error('expected at least one rejection')
    }
  })

  it('after race, findByProviderSub returns exactly ONE identity (no inconsistent state)', async () => {
    await Promise.allSettled([
      auth.flows.linkProvider({ identityId: identityA, providerId: 'authGoogle', providerSub: 'sub-X' }),
      auth.flows.linkProvider({ identityId: identityB, providerId: 'authGoogle', providerSub: 'sub-X' }),
    ])
    // Whichever identity won, ONLY that one has the link.
    const found = await adapter.identities.findByProviderSub('authGoogle', 'sub-X', {})
    expect(found).not.toBeNull()
    const otherId = found?.id === identityA ? identityB : identityA
    const other = await adapter.identities.findById(otherId, {})
    expect(other?.providers.find((p) => p.providerSub === 'sub-X')).toBeUndefined()
  })

  it('many concurrent linkProvider calls onto distinct identities: exactly one wins', async () => {
    // Spawn 10 distinct identities, all racing to link the same sub.
    const identities: string[] = []
    for (let i = 0; i < 10; i++) {
      const ident = await auth.identities.create({ profile: { email: `r-${i}@x.com` } })
      identities.push(ident.id)
    }
    const calls = identities.map((id) =>
      auth.flows.linkProvider({ identityId: id, providerId: 'authGithub', providerSub: 'race-sub' }),
    )
    const results = await Promise.allSettled(calls)
    const fulfilled = results.filter((r) => r.status === 'fulfilled')
    expect(fulfilled).toHaveLength(1)
    expect(results.filter((r) => r.status === 'rejected')).toHaveLength(9)
  })

  it('idempotent re-link onto SAME identity is allowed (no false race)', async () => {
    await auth.flows.linkProvider({ identityId: identityA, providerId: 'authGoogle', providerSub: 'sub-Y' })
    // Second link to same identity is a no-op (the facet's
    // alreadyLinked check fires before the store call).
    const r = await auth.flows.linkProvider({
      identityId: identityA,
      providerId: 'authGoogle',
      providerSub: 'sub-Y',
    })
    expect(r.identityId).toBe(identityA)
  })

  it('store-level guard fires when called directly (bypassing facet pre-check)', async () => {
    // Some app code uses the store directly. The atomic guard must
    // catch the duplicate even without the facet's pre-check.
    await adapter.identities.link(
      identityA,
      { providerId: 'authGithub', providerSub: 'direct-sub', addedAt: Date.now() },
      {},
    )
    await expect(
      adapter.identities.link(
        identityB,
        { providerId: 'authGithub', providerSub: 'direct-sub', addedAt: Date.now() },
        {},
      ),
    ).rejects.toMatchObject({
      code: 'AUTH/PROVIDER_FAILED',
      meta: { detail: 'provider sub already linked to a different identity' },
    })
  })

  it('link without providerSub (magic-link-style) is allowed across identities (no sub-uniqueness applies)', async () => {
    // The magic-link provider creates links with `providerSub:
    // undefined`. The uniqueness invariant only applies when both
    // sides have a sub.
    await adapter.identities.link(identityA, { providerId: 'magic-link', addedAt: Date.now() }, {})
    await adapter.identities.link(identityB, { providerId: 'magic-link', addedAt: Date.now() }, {})
    // Both succeeded - no error.
    expect(true).toBe(true)
  })
})
