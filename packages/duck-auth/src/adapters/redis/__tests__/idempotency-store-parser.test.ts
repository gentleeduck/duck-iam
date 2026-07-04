import { beforeEach, describe, expect, it } from 'vitest'
import { RedisIdempotencyStore } from '../idempotency-store'
import { FakeRedis } from '../redis-like'

const ctx = { tenantId: 'acme' }
const PREFIX = 'test:idem'
const STORAGE_KEY = `${PREFIX}:acme:k1`

describe('RedisIdempotencyStore.get - parser hardening', () => {
  let redis: FakeRedis
  let store: RedisIdempotencyStore

  beforeEach(() => {
    redis = new FakeRedis()
    store = new RedisIdempotencyStore({ redis, prefix: PREFIX })
  })

  describe('malformed JSON', () => {
    it('returns null on truncated JSON (no SyntaxError propagation)', async () => {
      await redis.set(STORAGE_KEY, '{"status":200,"bo')
      await expect(store.get('k1', ctx)).resolves.toBeNull()
    })

    it('returns null on garbage bytes', async () => {
      await redis.set(STORAGE_KEY, 'not-json-at-all-just-binary-blob')
      await expect(store.get('k1', ctx)).resolves.toBeNull()
    })

    it('returns null on empty string body', async () => {
      // SET '' is normally indistinguishable from missing for our store
      // (its `get` returns null for falsy raw). Verify the contract.
      await redis.set(STORAGE_KEY, '')
      await expect(store.get('k1', ctx)).resolves.toBeNull()
    })
  })

  describe('non-object JSON values (the `null.status` crash class)', () => {
    it('returns null on `JSON.parse("null")` - no TypeError on .status', async () => {
      await redis.set(STORAGE_KEY, 'null')
      await expect(store.get('k1', ctx)).resolves.toBeNull()
    })

    it('returns null on a plain number', async () => {
      await redis.set(STORAGE_KEY, '42')
      await expect(store.get('k1', ctx)).resolves.toBeNull()
    })

    it('returns null on a plain string', async () => {
      await redis.set(STORAGE_KEY, '"oops"')
      await expect(store.get('k1', ctx)).resolves.toBeNull()
    })

    it('returns null on a boolean', async () => {
      await redis.set(STORAGE_KEY, 'true')
      await expect(store.get('k1', ctx)).resolves.toBeNull()
    })

    it('returns null on an array (which would silently bypass .status check)', async () => {
      await redis.set(STORAGE_KEY, '[]')
      await expect(store.get('k1', ctx)).resolves.toBeNull()
    })
  })

  describe('wrong-shape objects', () => {
    it('returns null on empty object (no status / createdAt fields)', async () => {
      await redis.set(STORAGE_KEY, '{}')
      await expect(store.get('k1', ctx)).resolves.toBeNull()
    })

    it('returns null when status is a string (not a number)', async () => {
      await redis.set(STORAGE_KEY, JSON.stringify({ status: '200', body: null, createdAt: Date.now() }))
      await expect(store.get('k1', ctx)).resolves.toBeNull()
    })

    it('returns null when status is NaN', async () => {
      // JSON.stringify(NaN) === 'null' so we have to bypass via raw string.
      await redis.set(STORAGE_KEY, '{"status":NaN,"body":null,"createdAt":1}')
      await expect(store.get('k1', ctx)).resolves.toBeNull()
    })

    it('returns null when createdAt is missing', async () => {
      await redis.set(STORAGE_KEY, JSON.stringify({ status: 200, body: null }))
      await expect(store.get('k1', ctx)).resolves.toBeNull()
    })

    it('returns null when createdAt is non-finite', async () => {
      await redis.set(STORAGE_KEY, '{"status":200,"body":null,"createdAt":"yesterday"}')
      await expect(store.get('k1', ctx)).resolves.toBeNull()
    })
  })

  describe('headers field sanitization', () => {
    it('strips non-string header values', async () => {
      await redis.set(
        STORAGE_KEY,
        JSON.stringify({
          status: 200,
          body: { ok: true },
          createdAt: Date.now(),
          headers: { 'X-Foo': 'bar', 'X-Bad': 42, 'X-Also-Bad': null, 'X-Object': { nested: true } },
        }),
      )
      const got = await store.get('k1', ctx)
      expect(got).not.toBeNull()
      expect(got?.headers).toEqual({ 'X-Foo': 'bar' })
    })

    it('drops headers entirely when the field is not a plain object', async () => {
      await redis.set(
        STORAGE_KEY,
        JSON.stringify({
          status: 200,
          body: null,
          createdAt: Date.now(),
          headers: ['X-Foo:bar'],
        }),
      )
      const got = await store.get('k1', ctx)
      expect(got).not.toBeNull()
      expect(got?.headers).toBeUndefined()
    })
  })

  describe('happy paths still work', () => {
    it('round-trips a well-formed entry', async () => {
      await store.put('k1', { status: 200, body: { ok: true }, createdAt: new Date(42) }, 60_000, ctx)
      const got = await store.get('k1', ctx)
      expect(got?.status).toBe(200)
      expect(got?.body).toEqual({ ok: true })
      expect(got?.createdAt).toEqual(new Date(42))
    })

    it('round-trips well-formed entry with valid headers', async () => {
      await store.put(
        'k1',
        { status: 200, body: null, createdAt: new Date(42), headers: { 'X-Trace-Id': 'abc' } },
        60_000,
        ctx,
      )
      const got = await store.get('k1', ctx)
      expect(got?.headers).toEqual({ 'X-Trace-Id': 'abc' })
    })

    it('still filters the claim tombstone', async () => {
      await store.claim('k1', 60_000, ctx)
      await expect(store.get('k1', ctx)).resolves.toBeNull()
    })
  })
})
