/**
 * E2E: `valkeySessionImpl` against a REAL server.
 *
 * `sessions.redis.e2e.test.ts` covers `RedisSessionImpl` itself; `valkey.e2e.test.ts`
 * covers `valkeyAdapter`'s command translation. This is the layer in between: that
 * `valkeySessionImpl` actually wires a raw ioredis client into a working store.
 *
 * Skips when DUCKAUTH_E2E_REDIS_URL is unset; `globalSetup` provisions a container
 * when docker is available.
 */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { valkeySessionImpl } from '~/core/sessions/sessions.valkey'
import { dropPrefix, e2ePrefix, redisUrl } from '~/test/e2e-env'

const URL = redisUrl()
const suite = URL ? describe : describe.skip

suite('E2E valkeySessionImpl (real server)', () => {
  let raw: Redis
  let prefix: string

  beforeAll(async () => {
    raw = new Redis(URL as string, { lazyConnect: true, maxRetriesPerRequest: 2 })
    await raw.connect()
    prefix = e2ePrefix()
  })

  afterAll(async () => {
    if (raw) {
      await dropPrefix(raw, prefix)
      await raw.quit()
    }
  })

  it('round-trips a session through a real server', async () => {
    const store = valkeySessionImpl({ prefix, redis: raw })
    const now = new Date()
    const id = `sid-${e2ePrefix()}`
    await store.create({
      id,
      identityId: 'i-1',
      tenantId: null,
      kind: 'user',
      aal: 1,
      factors: [],
      csrfHash: null,
      ip: null,
      userAgent: null,
      fingerprint: null,
      createdAt: now,
      rotatedAt: now,
      expiresAt: new Date(now.getTime() + 60_000),
      absoluteExpiresAt: new Date(now.getTime() + 120_000),
      fresh: true,
      actingAs: null,
    })
    const found = await store.getByHash(id)
    expect(found).not.toBeNull()
    expect(found?.identityId).toBe('i-1')
  })

  it('deletes a session through a real server', async () => {
    const store = valkeySessionImpl({ prefix, redis: raw })
    const now = new Date()
    const id = `sid-del-${e2ePrefix()}`
    await store.create({
      id,
      identityId: 'i-2',
      tenantId: null,
      kind: 'user',
      aal: 1,
      factors: [],
      csrfHash: null,
      ip: null,
      userAgent: null,
      fingerprint: null,
      createdAt: now,
      rotatedAt: now,
      expiresAt: new Date(now.getTime() + 60_000),
      absoluteExpiresAt: new Date(now.getTime() + 120_000),
      fresh: true,
      actingAs: null,
    })
    await store.delete(id)
    expect(await store.getByHash(id)).toBeNull()
  })
})
