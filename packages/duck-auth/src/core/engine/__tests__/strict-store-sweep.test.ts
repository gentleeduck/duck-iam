/**
 * `strict()`'s store sweep is introduced by a comment reading "Over every store", and then lists three of
 * them by hand. `Engine.Stores` has a fourth slot, `orgs`, and the only org store this package ships is the
 * memory adapter's — which carries the very `__isMemoryStore` brand the sweep looks for. A deployment
 * wiring real identity, session and credential stores beside `adapter.orgs` passed the production gate with
 * its membership rows and role grants living in one process.
 *
 * `orgs` is refused rather than left open: `Org.Store` is documented as a read interface over the host's
 * own tables, so a production host is meant to have one already, and the memory store is the dev stand-in
 * for it. The challenge and DPoP nonce stores were the two exceptions to that and no longer are - the
 * first is refused through the provider's brand, the second refuses itself, `strict()` having no handle
 * on a verifier built outside the engine.
 *
 * The list is now taken from the stores bag itself, so a fifth slot cannot be added past the sweep.
 */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { InMemoryEvents } from '~/core/events'
import type { Events } from '~/core/events/events.types'
import type { Idempotency } from '~/core/idempotency/idempotency.types'
import type { Org } from '~/core/orgs/orgs.types'
import type { Limiter } from '~/limiters'
import { CookieTransport } from '../../transport/cookie.transport'
import { AuthEngine } from '../engine'
import type { Engine } from '../engine.types'

const foreignLimiter: Limiter.Me = {
  consume: async () => ({ ok: true, remaining: 1, resetAt: new Date(Date.now() + 60_000) }),
  reset: async () => {},
}

const foreignIdempotency: Idempotency.Store = {
  claim: async () => true,
  delete: async () => {},
  get: async () => ({ body: null, createdAt: new Date(), headers: {}, status: 200 }),
  put: async () => {},
}

/** The brand removed, which is what a drizzle or redis facet looks like to `strict()`. */
const unbranded = <T extends object>(facet: T): T => {
  const copy = { ...facet }
  Reflect.deleteProperty(copy, '__isMemoryStore')
  return copy
}

function foreignStores(): Engine.Stores {
  const adapter = new MemoryAdapter()
  return {
    credentials: unbranded(adapter.credentials),
    identities: unbranded(adapter.identities),
    sessions: unbranded(adapter.sessions),
  }
}

/** A bus carrying no in-process brand, which is what a fleet-safe one looks like to `strict()`. It
 *  keeps `listenerCount`, or the `lockout` check would be skipped rather than satisfied. */
function foreignEvents(): Events.IBus & { listenerCount(event: Events.EventName): number } {
  const bus = new InMemoryEvents()
  return {
    emit: (event, payload) => bus.emit(event, payload),
    listenerCount: (event) => bus.listenerCount(event),
    on: (event, handler) => bus.on(event, handler),
  }
}
/** Production-clean but for the stores handed in. */
function makeAuth(stores: Engine.Stores) {
  const auth = new AuthEngine({
    baseUrl: 'https://app.example.com',
    events: foreignEvents(),
    idempotency: foreignIdempotency,
    limiter: foreignLimiter,
    stores,
    transport: new CookieTransport({ name: 'duck-sid', secure: true }),
  })
  auth.providers.register({
    async begin() {
      return []
    },
    async complete() {
      return []
    },
    id: 'fake',
    kind: 'password',
  })
  auth.events.on('lockout', () => {})
  return auth
}

const strictly = (stores: Engine.Stores) => () => makeAuth(stores).strict({ env: 'production' })

/** The checks that failed. An `AuthError`'s `message` is its bare code, so a regex on the thrown error
 *  would match `AUTH_MISCONFIGURED` and nothing about stores. */
function refusals(stores: Engine.Stores): string {
  try {
    strictly(stores)()
  } catch (err) {
    return String((err as { meta: { detail: string } }).meta.detail)
  }
  return ''
}

describe('the production store sweep covers every slot in the stores bag', () => {
  it('refuses a memory org store beside three real ones', () => {
    expect(refusals({ ...foreignStores(), orgs: new MemoryAdapter().orgs })).toContain('Memory adapter (orgs)')
  })

  it('still accepts a deployment whose org store is the host', () => {
    // The same wiring with the brand gone: proof the refusal keys on the brand, not on `orgs` being set.
    expect(strictly({ ...foreignStores(), orgs: unbranded(new MemoryAdapter().orgs) })).not.toThrow()
  })

  it('leaves orgs optional, an app with no org concept wiring none', () => {
    expect(strictly(foreignStores())).not.toThrow()
  })

  it('names all four when all four are the memory adapter', () => {
    const adapter = new MemoryAdapter()
    const detail = refusals({
      credentials: adapter.credentials,
      identities: adapter.identities,
      orgs: adapter.orgs,
      sessions: adapter.sessions,
    })
    for (const label of ['identities', 'sessions', 'credentials', 'orgs']) {
      expect(detail).toContain(`Memory adapter (${label})`)
    }
  })

  it('sweeps a slot the hand-written list never knew about', () => {
    // A store added to the bag later, standing in for the next `orgs`. The sweep reads the bag, so it is
    // covered the day it is added rather than the day someone remembers to extend a list.
    const stores = Object.assign(foreignStores(), { future: { __isMemoryStore: true } })
    expect(refusals(stores)).toContain('Memory adapter (future)')
  })

  it('does not mistake `withClient` for a store', () => {
    // It is a function on the same bag, and reading a brand off it must not invent a rejection.
    const stores = foreignStores()
    expect(strictly({ ...stores, withClient: () => stores })).not.toThrow()
  })

  it('survives an optional store wired as undefined', () => {
    // `orgs` is optional, so `orgs: cfg.orgs` is type-legal and leaves the key present holding undefined.
    // The bag is enumerated, so unlike a named read this one reaches it.
    expect(strictly({ ...foreignStores(), orgs: undefined })).not.toThrow()
  })
})
