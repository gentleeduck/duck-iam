import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthError } from '~/core/errors'
import { InMemoryEvents } from '~/core/events'
import { createTest } from '~/test'

type P = { username: string; email: string }

/**
 * A memory adapter whose bag answers `withClient`, recording which client it was bound to. The copies prove
 * the facade never reuses the engine's own stores; each keeps its prototype, since a store is a class and
 * its methods live there rather than on the instance.
 */
function trackingStores() {
  const adapter = new MemoryAdapter<P>()
  const bound: unknown[] = []
  const copy = <T extends object>(store: T): T => Object.assign(Object.create(Object.getPrototypeOf(store)), store)
  return {
    bound,
    credentials: adapter.credentials,
    identities: adapter.identities,
    sessions: adapter.sessions,
    withClient: (client: unknown) => {
      bound.push(client)
      return {
        credentials: copy(adapter.credentials),
        identities: copy(adapter.identities),
        sessions: copy(adapter.sessions),
      }
    },
  }
}

describe('AuthEngine.withTransaction', () => {
  it('re-binds the stores to the supplied client, once', () => {
    const s = trackingStores()
    const engine = createTest<P>({ stores: s })
    const tx = { marker: 'tx' }

    engine.withTransaction(tx)

    // One rebind covers every facet: they come off one adapter and share its connection. The mfa and
    // api-key facets are handed the result rather than rebinding a store each of their own.
    expect(s.bound).toEqual([tx])
  })

  it('throws AUTH_MISCONFIGURED when the stores cannot join', () => {
    const adapter = new MemoryAdapter<P>()
    const engine = createTest<P>({
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    })

    // AuthError puts the human-readable reason in `meta.detail`; `message` is the code. The detail must say
    // what is missing so an operator knows what to change.
    expect(() => engine.withTransaction({})).toThrowError(AuthError)
    try {
      engine.withTransaction({})
      expect.unreachable('withTransaction should have thrown')
    } catch (err) {
      expect(err).toBeInstanceOf(AuthError)
      expect((err as AuthError).code).toBe('AUTH_MISCONFIGURED')
      expect((err as AuthError).meta.detail).toMatch(/withClient/)
    }
  })

  it('buffers events instead of emitting them', async () => {
    const bus = new InMemoryEvents()
    const handler = vi.fn(async () => {})
    bus.on('signup.completed', handler)
    const s = trackingStores()
    const engine = createTest<P>({ events: bus, stores: s })

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
    const engine = createTest<P>({ stores: s })
    const auth = engine.withTransaction({}) as unknown as Record<string, unknown>

    // Guards write nothing to SQL, so a rollback has nothing to undo and
    // joining a transaction would be meaningless. Reach them on the engine.
    for (const guard of ['limiter', 'idempotency', 'hijack', 'anomaly', 'transport', 'plugins']) {
      expect(auth[guard]).toBeUndefined()
    }
  })

  it('exposes the tx-bound stores for direct store access', () => {
    const s = trackingStores()
    const engine = createTest<P>({ stores: s })
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
    const engine = createTest<P>({ stores: s })
    const auth = engine.withTransaction({})

    expect(auth.identities).not.toBe(engine.identities)
    expect(auth.sessions).not.toBe(engine.sessions)
    expect(auth.flows).not.toBe(engine.flows)
  })
})
