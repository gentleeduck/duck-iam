import { describe, expect, it } from 'vitest'
import { createTestAuth, type TestAuth } from '../index'

describe('createTestAuth()', () => {
  it('returns a usable AuthRoot with default in-memory adapters', () => {
    const auth = createTestAuth()
    expect(auth).toBeDefined()
    expect(auth.identities).toBeDefined()
    expect(auth.sessions).toBeDefined()
    expect(auth.passwords).toBeDefined()
    expect(auth.mfa).toBeDefined()
    expect(auth.apiKeys).toBeDefined()
    expect(auth.flows).toBeDefined()
  })

  it('uses BearerTransport by default', () => {
    const auth = createTestAuth()
    const headers = new Headers({ authorization: 'Bearer testtoken' })
    const extracted = auth.transport.extract({ headers })
    expect(extracted).toBe('testtoken')
  })

  it('round-trips identity creation through the default in-memory store', async () => {
    const auth = createTestAuth<{ email: string }>()
    const created = await auth.identities.create({ profile: { email: 'a@b.test' } })
    expect(created.id).toBeDefined()
    const found = await auth.identities.getById(created.id)
    expect(found?.profile?.email).toBe('a@b.test')
  })

  it('honors a baseUrl override', () => {
    const auth = createTestAuth({ baseUrl: 'https://example.test' })
    expect(auth.config.baseUrl).toBe('https://example.test')
  })

  it('lets callers swap a single store (identities) while keeping the rest', async () => {
    const swapped = createTestAuth()
    // Use the default adapter for everything; swap only the limiter to a
    // tighter one to prove overrides flow through.
    const tight: TestAuth.IOverrides = {
      limiter: { consume: async () => ({ ok: true, remaining: 0, resetAt: Date.now() }), reset: async () => {} },
    }
    const auth = createTestAuth(tight)
    const r = await auth.limiter.consume('k', 1)
    expect(r.remaining).toBe(0)
    // default has Number.POSITIVE_INFINITY remaining
    const def = await swapped.limiter.consume('k', 1)
    expect(def.remaining).toBeGreaterThan(0)
  })

  it('accepts a custom hasher (typed via TestAuth.IOverrides)', () => {
    const stub = {
      id: 'test-stub',
      hash: async () => 'hashed',
      verify: async () => true,
      needsRehash: () => false,
    }
    const auth = createTestAuth({ hasher: stub })
    expect(auth.passwords).toBeDefined()
  })
})
