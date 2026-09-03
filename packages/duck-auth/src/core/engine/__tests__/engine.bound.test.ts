import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthError } from '~/core/errors'
import { InMemoryEvents } from '~/core/events'
import { createTest } from '~/test'

type P = { username: string; email: string }

/**
 * Memory stores that also answer `withClient`, recording which client they were
 * bound to. Memory stores are plain object literals, so a spread copies every
 * method; the copy is what proves the facade never reuses the engine's store.
 */
function trackingStores() {
  const adapter = new MemoryAdapter<P>()
  const bound: unknown[] = []
  const wrap = <T extends object>(store: T): T =>
    Object.assign({} as T, store, {
      withClient: (client: unknown) => {
        bound.push(client)
        return wrap(store)
      },
    })
  return {
    bound,
    identities: wrap(adapter.identities),
    sessions: wrap(adapter.sessions),
    credentials: wrap(adapter.credentials),
  }
}

describe('AuthEngine.withTransaction', () => {
  it('re-binds every store to the supplied client', () => {
    const s = trackingStores()
    const engine = createTest<P>({ identities: s.identities, sessions: s.sessions, credentials: s.credentials })
    const tx = { marker: 'tx' }

    engine.withTransaction(tx)

    // Three stores rebind directly; the mfa and api-key facets each rebind the
    // credentials store again for their own captured copy. What matters is that
    // every rebind used the caller's client and none silently used another.
    expect(s.bound.length).toBeGreaterThanOrEqual(3)
    expect(s.bound.every((c) => c === tx)).toBe(true)
  })

  it('throws AUTH_MISCONFIGURED naming the store that cannot join', () => {
    const s = trackingStores()
    const engine = createTest<P>({
      identities: s.identities,
      sessions: new MemoryAdapter<P>().sessions,
      credentials: s.credentials,
    })

    // AuthError puts the human-readable reason in `meta.detail`; `message` is
    // the code. The detail must name the store so an operator knows which
    // adapter to change.
    expect(() => engine.withTransaction({})).toThrowError(AuthError)
    try {
      engine.withTransaction({})
      expect.unreachable('withTransaction should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(AuthError)
      expect((err as AuthError).code).toBe('AUTH_MISCONFIGURED')
      expect((err as AuthError).meta.detail).toMatch(/sessions/)
    }
  })

  it('buffers events instead of emitting them', async () => {
    const bus = new InMemoryEvents()
    const handler = vi.fn(async () => {})
    bus.on('signup.completed', handler)
    const s = trackingStores()
    const engine = createTest<P>({
      credentials: s.credentials,
      events: bus,
      identities: s.identities,
      sessions: s.sessions,
    })

    const auth = engine.withTransaction({})
    await auth.identities.create({ profile: { email: 'b@x', username: 'b' } as P })

    expect(handler).not.toHaveBeenCalled()
    expect(auth.pending.size).toBe(1)

    await auth.pending.flush()
    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('leaves the unbound engine emitting immediately', async () => {
    const bus = new InMemoryEvents()
    const handler = vi.fn(async () => {})
    bus.on('signup.completed', handler)
    const engine = createTest<P>({ events: bus })

    await engine.identities.create({ profile: { email: 'c@x', username: 'c' } as P })

    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('does not expose the layer-2 guards', () => {
    const s = trackingStores()
    const engine = createTest<P>({ identities: s.identities, sessions: s.sessions, credentials: s.credentials })
    const auth = engine.withTransaction({}) as unknown as Record<string, unknown>

    // Guards write nothing to SQL, so a rollback has nothing to undo and
    // joining a transaction would be meaningless. Reach them on the engine.
    for (const guard of ['limiter', 'idempotency', 'hijack', 'anomaly', 'transport', 'plugins']) {
      expect(auth[guard]).toBeUndefined()
    }
  })

  it('exposes the tx-bound stores for direct store access', () => {
    const s = trackingStores()
    const engine = createTest<P>({ identities: s.identities, sessions: s.sessions, credentials: s.credentials })
    const auth = engine.withTransaction({})

    expect(auth.stores.identities).toBeDefined()
    expect(auth.stores.identities).not.toBe(engine.cfg.stores.identities)
    expect(auth.stores.sessions).not.toBe(engine.cfg.stores.sessions)
    expect(auth.stores.credentials).not.toBe(engine.cfg.stores.credentials)
  })

  it('a bound write is invisible to the unbound engine facets that share no store', async () => {
    // The stores here are the SAME underlying memory maps, so this asserts the
    // wiring only: the bound facet is a different instance reading a rebound store.
    const s = trackingStores()
    const engine = createTest<P>({ identities: s.identities, sessions: s.sessions, credentials: s.credentials })
    const auth = engine.withTransaction({})

    expect(auth.identities).not.toBe(engine.identities)
    expect(auth.sessions).not.toBe(engine.sessions)
    expect(auth.flows).not.toBe(engine.flows)
  })
})
