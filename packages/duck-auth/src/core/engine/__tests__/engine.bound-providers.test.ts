import { describe, expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { OrgsImpl } from '~/core/orgs'
import { ApiKeysFacet } from '~/providers/api-key'
import { MfaFacet } from '~/providers/mfa'
import { PasswordsImpl } from '~/providers/passwords'
import { createTest } from '~/test'

type P = { username: string; email: string }

/**
 * A memory adapter whose bag rebinds as one, recording every `create` that lands on the REBOUND copy. The
 * mfa and api-key facets are handed that copy, so a transaction has one bound credentials store rather than
 * one per facet, and `reboundCreates` says whether a write reached it or the engine's own.
 */
function bindableStores() {
  const adapter = new MemoryAdapter<P>()
  const reboundCreates: string[] = []
  // The copy keeps the prototype: a store is a class, so its methods live there, not on the instance. The
  // engine gets copies too, so a spy on its own store cannot be mistaken for the bound one.
  const copy = <T extends object>(store: T): T => Object.assign(Object.create(Object.getPrototypeOf(store)), store)
  const recording = <T extends object>(store: T): T => {
    const bound = copy(store)
    const create = (bound as { create?: (...a: never[]) => unknown }).create
    if (typeof create === 'function') {
      Object.assign(bound, {
        create: (...args: never[]) => {
          reboundCreates.push('create')
          return create.apply(store, args)
        },
      })
    }
    return bound
  }
  return {
    credentials: copy(adapter.credentials),
    identities: copy(adapter.identities),
    reboundCreates,
    sessions: copy(adapter.sessions),
    withClient: () => ({
      credentials: recording(adapter.credentials),
      identities: recording(adapter.identities),
      sessions: recording(adapter.sessions),
    }),
  }
}

describe('bound facade - provider-owned facets', () => {
  it('exposes mfa, apiKeys and passwords', () => {
    const auth = createTest<P>({ stores: bindableStores() }).withTransaction({})

    expect(auth.mfa).toBeInstanceOf(MfaFacet)
    expect(auth.apiKeys).toBeInstanceOf(ApiKeysFacet)
    expect(auth.passwords).toBeInstanceOf(PasswordsImpl)
  })

  it('the bound facets are fresh instances, not the engine own', () => {
    const engine = createTest<P>({ stores: bindableStores() })
    const auth = engine.withTransaction({})

    expect(auth.mfa).not.toBe(engine.mfa)
    expect(auth.apiKeys).not.toBe(engine.apiKeys)
    expect(auth.providers).not.toBe(engine.providers)
  })

  it('the bound registry keeps every capability, by id and by class', () => {
    const engine = createTest<P>({ stores: bindableStores() })
    const auth = engine.withTransaction({})

    expect(
      auth.providers
        .list()
        .map((c) => c.id)
        .sort(),
    ).toEqual(
      engine.providers
        .list()
        .map((c) => c.id)
        .sort(),
    )
    // The FACET registers as 'api-keys'; the sign-in provider is 'api-key'.
    expect(auth.providers.has('api-keys')).toBe(true)
  })

  it('bound apiKeys writes through a bound credentials store, not the engine own', async () => {
    const stores = bindableStores()
    const engine = createTest<P>({ stores })
    const identity = await engine.identities.create({ profile: { email: 'k@x', username: 'k' } as P })
    const unbound = vi.spyOn(engine.cfg.stores.credentials, 'create')
    stores.reboundCreates.length = 0

    const auth = engine.withTransaction({})
    await auth.apiKeys.create(identity.id, { name: 'test', scopes: ['read'] })

    expect(stores.reboundCreates).toHaveLength(1)
    expect(unbound).not.toHaveBeenCalled()
  })

  it('bound mfa writes through a bound credentials store, not the engine own', async () => {
    const stores = bindableStores()
    const engine = createTest<P>({ stores })
    const identity = await engine.identities.create({ profile: { email: 'm@x', username: 'm' } as P })
    const unbound = vi.spyOn(engine.cfg.stores.credentials, 'create')
    stores.reboundCreates.length = 0

    const auth = engine.withTransaction({})
    await auth.mfa.beginTotpEnrollment(identity.id, 'm@x')

    expect(stores.reboundCreates).toHaveLength(1)
    expect(unbound).not.toHaveBeenCalled()
  })

  it('bound mfa buffers its events instead of emitting them', async () => {
    const engine = createTest<P>({ stores: bindableStores() })
    const identity = await engine.identities.create({ profile: { email: 'e@x', username: 'e' } as P })
    const emitted: string[] = []
    engine.events.on('mfa.removed', async () => {
      emitted.push('mfa.removed')
    })

    const auth = engine.withTransaction({})
    await auth.mfa.beginTotpEnrollment(identity.id, 'e@x')
    await auth.mfa.removeTotp(identity.id)

    expect(emitted).toEqual([])
    expect(auth.pending.size).toBeGreaterThan(0)

    await auth.pending.flush()
    expect(emitted).toEqual(['mfa.removed'])
  })

  /** The bound facade carries the same `orgs` contract as the engine, or a caller inside a transaction
   *  still has to null-check the one property the engine no longer makes them null-check. */
  it('exposes orgs the way the engine does, throwing when no org store was bound', () => {
    const withoutOrgs = createTest<P>({ stores: bindableStores() }).withTransaction({})
    expect(() => withoutOrgs.orgs).toThrow(/AUTH_PROVIDER_NOT_REGISTERED/)

    const bag = bindableStores()
    const orgs = new MemoryAdapter<P>().orgs
    const stores = { ...bag, orgs, withClient: () => ({ ...bag.withClient(), orgs }) }
    expect(createTest<P>({ stores }).withTransaction({}).orgs).toBeInstanceOf(OrgsImpl)
  })

  it('a capability with no withClient is carried through unchanged', () => {
    const engine = createTest<P>({ stores: bindableStores() })
    const bound = engine.providers.withClient(engine.cfg.stores, engine.events)

    // PasswordsImpl reads its stores from Provider.Context, so it needs no
    // rebinding and must survive the copy as the very same instance.
    expect(bound.resolve(PasswordsImpl)).toBe(engine.providers.resolve(PasswordsImpl))
  })
})
