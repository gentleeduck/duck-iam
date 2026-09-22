/** E2E: `valkeySessionImpl` against a REAL server. */
import Redis from 'ioredis'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { sha256 } from '~/core/crypto'
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
    // A real session id: the sha-256 the library itself stores under. `e2ePrefix`
    // builds a key namespace and carries `:`, which an id may not.
    const id = sha256(`sid-${e2ePrefix()}`)
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
      updatedAt: now,
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
    const id = sha256(`sid-del-${e2ePrefix()}`)
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
      updatedAt: now,
      rotatedAt: now,
      expiresAt: new Date(now.getTime() + 60_000),
      absoluteExpiresAt: new Date(now.getTime() + 120_000),
      fresh: true,
      actingAs: null,
    })
    await store.delete(id)
    await expect(store.getByHash(id)).rejects.toMatchObject({ code: 'AUTH_SESSION_REVOKED' })
  })
})
