/**
 * `refuseRateLimited` is where a spent bucket becomes a refusal, and its docstring says every limiter
 * guard goes through it. This provider did not: it built the 429 by hand, with the bare
 * `resetAt.getTime()` the shared helper carries a SECURITY note about avoiding.
 */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { randomToken, sha256, timingSafeEqual } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import { InMemoryEvents } from '~/core/events'
import type { Provider } from '~/core/provider/provider.types'
import type { Limiter } from '~/limiters/limiters.types'
import { apiKeysFacet, authApiKey } from '../api-key'

/** A host limiter that reports `resetAt` as epoch milliseconds, which is what a redis or http-backed one
 *  deserialises to unless it remembers to revive the Date. */
const epochMsLimiter: Limiter.Me = {
  // @ts-expect-error epoch milliseconds where the contract says Date
  consume: async () => ({ ok: false, remaining: 0, resetAt: Date.now() + 30_000 }),
  reset: async () => undefined,
}

/** The refusal's `retryAfter`, since only an `AuthError` carries one. */
const retryAfter = (err: unknown): unknown => (err instanceof AuthError ? err.meta.retryAfter : undefined)

describe('a spent bucket is a refusal, whatever shape the limiter reports it in', () => {
  const build = () => {
    const adapter = new MemoryAdapter()
    const events = new InMemoryEvents()
    const facet = apiKeysFacet(adapter.credentials, events, { randomToken, sha256 })
    const provider = authApiKey({ apiKeys: facet })
    const ctx: Provider.Context = {
      baseUrl: 'https://x',
      crypto: { authRandomToken: randomToken, authSha256: sha256, authTimingSafeEqual: timingSafeEqual },
      events,
      limiter: epochMsLimiter,
      stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
      tenant: {},
    }
    return { ctx, provider }
  }

  it('answers AUTH_RATE_LIMITED rather than a TypeError out of the guard', async () => {
    const { ctx, provider } = build()
    await expect(provider.complete(ctx, { token: 'ak_live_whatever' })).rejects.toMatchObject({
      code: 'AUTH_RATE_LIMITED',
    })
  })

  it('still carries a usable retryAfter, floored at one second', async () => {
    const { ctx, provider } = build()
    const err = await provider.complete(ctx, { token: 'ak_live_whatever' }).catch((e: unknown) => e)
    expect(retryAfter(err)).toBeGreaterThanOrEqual(1)
  })

  it('a well-behaved Date limiter is unchanged', async () => {
    const { ctx, provider } = build()
    ctx.limiter = {
      consume: async () => ({ ok: false, remaining: 0, resetAt: new Date(Date.now() + 30_000) }),
      reset: async () => undefined,
    }
    const err = await provider.complete(ctx, { token: 'ak_live_whatever' }).catch((e: unknown) => e)
    expect(err).toMatchObject({ code: 'AUTH_RATE_LIMITED' })
    expect(retryAfter(err)).toBeGreaterThan(1)
  })
})
