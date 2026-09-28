/** `resolveSession` slides the idle deadline, so an active user stays signed in up to the absolute cap. */
import { expect, it, vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { createAuth } from '~/core/config/config'
import { sha256 } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { identityInput } from '~/test/store-inputs'
import type { Sessions } from '../../sessions'

const DAY = 86_400_000

/** A signed-in user on the default 7-day idle and 30-day absolute deadlines, with the store's writes counted. */
async function signedIn(mint: Partial<Sessions.MintInput> = {}) {
  const adapter = new MemoryAdapter()
  const writes = { count: 0, refuse: false }
  const sessions: Sessions.Store = {
    ...adapter.sessions,
    update: (id, patch, expectedUpdatedAt) => {
      writes.count++
      if (writes.refuse) return Promise.reject(new AuthError('AUTH_STALE_WRITE'))
      return adapter.sessions.update(id, patch, expectedUpdatedAt)
    },
  }
  const auth = createAuth({
    baseUrl: 'https://x.test',
    providers: [],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions },
    transport: new CookieTransport({ name: 'sid', secure: false }),
  })
  const { id: identityId } = await adapter.identities.create(
    identityInput({ profile: { email: 'a@x.com', username: 'a' }, providers: [] }),
  )
  const { sid } = await auth.sessions.create({ aal: 1, factors: [], identityId, kind: 'user', ...mint })
  const resolve = (afterMs: number) =>
    at(afterMs, () => auth.resolveSession({ headers: new Headers({ cookie: `sid=${sid}` }) }).orNull())
  const row = () => adapter.sessions.getByHash(sha256(sid))
  return { resolve, row, writes }
}

/** Run `fn` as though the clock had moved on by `ms`. */
async function at<T>(ms: number, fn: () => Promise<T>): Promise<T> {
  vi.useFakeTimers({ now: Date.now() + ms })
  try {
    return await fn()
  } finally {
    vi.useRealTimers()
  }
}

it('keeps a user who comes back every six days signed in, until the absolute cap', async () => {
  const { resolve } = await signedIn()
  for (const day of [6, 12, 18, 24, 29]) expect(await resolve(day * DAY)).not.toBeNull()
  expect(await resolve(31 * DAY)).toBeNull()
})

it('signs out a user idle for the whole TTL', async () => {
  const { resolve } = await signedIn()
  expect(await resolve(3 * DAY)).not.toBeNull()
  expect(await resolve(8 * DAY)).toBeNull()
})

it('writes the row only once less than half the TTL is left', async () => {
  const { resolve, row, writes } = await signedIn()
  const minted = (await row()).expiresAt.getTime()
  await resolve(DAY)
  expect(writes.count).toBe(0)
  const slid = await resolve(4 * DAY)
  expect(writes.count).toBe(1)
  expect(slid?.session.expiresAt.getTime()).toBeGreaterThanOrEqual(minted + 4 * DAY)
  expect(slid?.session.expiresAt).toEqual((await row()).expiresAt)
  await resolve(4 * DAY)
  expect(writes.count).toBe(1)
})

it('never writes a session already at its absolute cap', async () => {
  const { resolve, writes } = await signedIn({ ttlMs: DAY })
  expect(await resolve(DAY - 60_000)).not.toBeNull()
  expect(writes.count).toBe(0)
})

it('still resolves when a concurrent request slid the row first', async () => {
  const { resolve, writes } = await signedIn()
  writes.refuse = true
  expect(await resolve(4 * DAY)).not.toBeNull()
  expect(writes.count).toBe(2)
})
