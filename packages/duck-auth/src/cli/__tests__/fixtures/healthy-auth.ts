/** An `auth.ts` with nothing `strict({ env: 'production' })` objects to, for `duck-auth doctor` to import.
 *  Not a test file: it is the module under `doctor`'s `await import(...)`. */
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import type { Limiter } from '~/limiters'

/** Brandless, as a redis limiter is: `strict()` refuses the in-process one by brand. */
const limiter: Limiter.Me = {
  consume: async () => ({ ok: true, remaining: 1, resetAt: new Date(Date.now() + 60_000) }),
  reset: async () => {},
}

/** The memory facets with the brand stripped, standing in for drizzle or redis. */
function stores() {
  const adapter = new MemoryAdapter()
  const strip = <T extends object>(facet: T): T => {
    const copy = { ...facet }
    Reflect.deleteProperty(copy, '__isMemoryStore')
    return copy
  }
  return {
    credentials: strip(adapter.credentials),
    identities: strip(adapter.identities),
    sessions: strip(adapter.sessions),
  }
}

export const auth = new AuthEngine({
  baseUrl: 'https://app.example.com',
  idempotency: {
    claim: async () => true,
    delete: async () => {},
    get: async () => ({ body: null, createdAt: new Date(), headers: {}, status: 200 }),
    put: async () => {},
  },
  limiter,
  stores: stores(),
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
