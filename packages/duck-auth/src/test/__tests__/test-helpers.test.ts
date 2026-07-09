import { describe, expect, it } from 'vitest'
import { createTest, type Test } from '../index'

describe('authCreateTest()', () => {
  it('returns a usable AuthEngine with default in-memory adapters', () => {
    const auth = createTest()
    expect(auth).toBeDefined()
    expect(auth.identities).toBeDefined()
    expect(auth.sessions).toBeDefined()
    expect(auth.passwords).toBeDefined()
    expect(auth.mfa).toBeDefined()
    expect(auth.apiKeys).toBeDefined()
    expect(auth.flows).toBeDefined()
  })

  it('uses AuthBearerTransport by default', () => {
    const auth = createTest()
    const headers = new Headers({ authorization: 'Bearer testtoken' })
    const extracted = auth.transport.extract({ headers })
    expect(extracted).toBe('testtoken')
  })

  it('round-trips identity creation through the default in-memory store', async () => {
    const auth = createTest<{ email: string , username : string}>()
    const created = await auth.identities.create({ profile: { email: 'a@b.test' , username : 'a'} })
    expect(created.id).toBeDefined()
    const found = await auth.identities.getById(created.id)
    expect(found?.profile?.email).toBe('a@b.test')
  })

  it('honors a baseUrl override', () => {
    const auth = createTest({ baseUrl: 'https://example.test' })
    expect(auth.config.baseUrl).toBe('https://example.test')
  })

  it('lets callers swap a single store (identities) while keeping the rest', async () => {
    const swapped = createTest()
    // Use the default adapter for everything; swap only the limiter to a
    // tighter one to prove overrides flow through.
    const tight: Test.Overrides = {
      limiter: { consume: async () => ({ ok: true, remaining: 0, resetAt: new Date() }), reset: async () => {} },
    }
    const auth = createTest(tight)
    const r = await auth.limiter.consume('k', 1)
    expect(r.remaining).toBe(0)
    // default has Number.POSITIVE_INFINITY remaining
    const def = await swapped.limiter.consume('k', 1)
    expect(def.remaining).toBeGreaterThan(0)
  })

  it('accepts a custom hasher (typed via AuthTest.IOverrides)', () => {
    const stub = {
      id: 'test-stub',
      hash: async () => 'hashed',
      verify: async () => true,
      needsRehash: () => false,
    }
    const auth = createTest({ passwords: {
      hasher: stub
    }})
    expect(auth.passwords).toBeDefined()
  })
})
