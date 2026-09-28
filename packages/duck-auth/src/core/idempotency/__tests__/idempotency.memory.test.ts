import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { orNull } from '~/core/answer'
import { IdempotencyImpl } from '../idempotency'
import { DEFAULT_IDEMPOTENCY_CONFIG } from '../idempotency.constants'
import { MemoryIdempotency } from '../idempotency.memory'

describe('MemoryIdempotencyStore', () => {
  it('get rejects for unseen keys, and orNull reads that back as null', async () => {
    const store = new MemoryIdempotency()
    await expect(store.get('k', {})).rejects.toMatchObject({ code: 'AUTH_IDEMPOTENCY_MISS' })
    await expect(orNull(store.get('k', {}))).resolves.toBeNull()
  })

  it('claim returns true the first time + false on subsequent claims within TTL', async () => {
    const store = new MemoryIdempotency()
    expect(await store.claim('k', 60_000, {})).toBe(true)
    expect(await store.claim('k', 60_000, {})).toBe(false)
  })

  it('put + get roundtrip persists status + body', async () => {
    const store = new MemoryIdempotency()
    await store.put('k', { status: 201, body: { ok: true }, createdAt: new Date() }, 60_000, {})
    const got = await store.get('k', {})
    expect(got.status).toBe(201)
    expect(got.body).toEqual({ ok: true })
  })

  it('respects tenant scope (same key in different tenants do not collide)', async () => {
    const store = new MemoryIdempotency()
    await store.put('k', { status: 200, body: 'A', createdAt: new Date() }, 60_000, { tenantId: 'A' })
    await store.put('k', { status: 200, body: 'B', createdAt: new Date() }, 60_000, { tenantId: 'B' })
    expect((await store.get('k', { tenantId: 'A' })).body).toBe('A')
    expect((await store.get('k', { tenantId: 'B' })).body).toBe('B')
  })

  it('TTL elapses + get rejects as a miss', async () => {
    const store = new MemoryIdempotency()
    await store.put('k', { status: 200, body: 'x', createdAt: new Date() }, 1, {})
    await new Promise((r) => setTimeout(r, 5))
    await expect(store.get('k', {})).rejects.toMatchObject({ code: 'AUTH_IDEMPOTENCY_MISS' })
  })
})

describe('IdempotencyFacet.handle', () => {
  let store: MemoryIdempotency
  let facet: IdempotencyImpl

  beforeEach(() => {
    store = new MemoryIdempotency()
    facet = new IdempotencyImpl(store, DEFAULT_IDEMPOTENCY_CONFIG)
  })

  it('executes once + caches; second call returns the cached response without re-executing', async () => {
    const exec = vi.fn(async () => ({ status: 200, body: { n: 1 }, createdAt: new Date() }))
    const a = await facet.handle('key-1', {}, exec)
    const b = await facet.handle('key-1', {}, exec)
    expect(exec).toHaveBeenCalledOnce()
    expect(a.body).toEqual({ n: 1 })
    expect(b.body).toEqual({ n: 1 })
  })

  it('different keys run the executor independently', async () => {
    const exec = vi.fn(async () => ({ status: 200, body: {}, createdAt: new Date() }))
    await facet.handle('key-1', {}, exec)
    await facet.handle('key-2', {}, exec)
    expect(exec).toHaveBeenCalledTimes(2)
  })

  it('empty key bypasses the cache entirely', async () => {
    const exec = vi.fn(async () => ({ status: 200, body: {}, createdAt: new Date() }))
    await facet.handle('', {}, exec)
    await facet.handle('', {}, exec)
    expect(exec).toHaveBeenCalledTimes(2)
  })

  it("headerName surfaces the configured header for the host's middleware", () => {
    expect(facet.headerName).toBe('idempotency-key')
  })

  it('concurrent same-key callers - executor runs exactly once', async () => {
    // Use a slow executor so the second handle() lands while the first is in flight.
    let calls = 0
    const exec = async () => {
      calls++
      await new Promise((r) => setTimeout(r, 80))
      return { status: 200, body: { n: calls }, createdAt: new Date() }
    }
    const [a, b] = await Promise.all([facet.handle('k', {}, exec), facet.handle('k', {}, exec)])
    expect(calls).toBe(1)
    expect(a.body).toEqual({ n: 1 })
    expect(b.body).toEqual({ n: 1 })
  })

  it('a repeat with the same fingerprint replays; one with another answers 422 and runs nothing', async () => {
    const exec = vi.fn(async () => ({ status: 201, body: { charged: 10 }, createdAt: new Date() }))
    await facet.handle('k', {}, exec, { fingerprint: 'POST /charge amount=10' })
    const same = await facet.handle('k', {}, exec, { fingerprint: 'POST /charge amount=10' })
    const other = await facet.handle('k', {}, exec, { fingerprint: 'POST /charge amount=99' })
    expect(exec).toHaveBeenCalledOnce()
    expect(same.body).toEqual({ charged: 10 })
    expect(other).toMatchObject({ status: 422, body: { error: 'idempotency-key-reused' } })
  })

  it('a concurrent repeat with another fingerprint answers 422 once the original settles', async () => {
    const exec = async () => {
      await new Promise((r) => setTimeout(r, 50))
      return { status: 201, body: { charged: 10 }, createdAt: new Date() }
    }
    const [, other] = await Promise.all([
      facet.handle('k', {}, exec, { fingerprint: 'amount=10' }),
      facet.handle('k', {}, exec, { fingerprint: 'amount=99' }),
    ])
    expect(other.status).toBe(422)
  })

  it('when the originator crashes, the loser returns 409 (does not re-execute)', async () => {
    // Pre-claim the slot in the store with no follow-up put() (simulates a
    // worker that won the race then died before completing the executor).
    // The facet weaves identity scope into the stored key, so the
    // synthetic pre-claim must use the same prefix.
    await store.claim('_anon::orphan-k', DEFAULT_IDEMPOTENCY_CONFIG.ttlMs, {})
    const exec = vi.fn(async () => ({ status: 200, body: { ran: true }, createdAt: new Date() }))
    const tightFacet = new IdempotencyImpl(store, { ...DEFAULT_IDEMPOTENCY_CONFIG, pollTimeoutMs: 100 })
    const r = await tightFacet.handle('orphan-k', {}, exec)
    expect(exec).not.toHaveBeenCalled()
    expect(r.status).toBe(409)
    expect(r.body).toMatchObject({ error: 'idempotency-conflict' })
  })

  it('identity scoping - Alice and Bob can use the same key without collision', async () => {
    const facet2 = new IdempotencyImpl(store, DEFAULT_IDEMPOTENCY_CONFIG)
    const aExec = vi.fn(async () => ({ status: 200, body: { who: 'alice' }, createdAt: new Date() }))
    const bExec = vi.fn(async () => ({ status: 200, body: { who: 'bob' }, createdAt: new Date() }))
    const a = await facet2.handle('same-key', {}, aExec, { identityId: 'alice' })
    const b = await facet2.handle('same-key', {}, bExec, { identityId: 'bob' })
    expect(aExec).toHaveBeenCalledOnce()
    expect(bExec).toHaveBeenCalledOnce()
    expect(a.body).toEqual({ who: 'alice' })
    expect(b.body).toEqual({ who: 'bob' })
  })

  it('identity scoping - without an identityId the key alone authorises the replay', async () => {
    // The counterpart to the Alice/Bob case above, and the one the isolation claim does NOT cover.
    // Two unrelated anonymous callers presenting one key share a bucket, so the second is answered
    // with the first's body.
    const facet2 = new IdempotencyImpl(store, DEFAULT_IDEMPOTENCY_CONFIG)
    const mine = vi.fn(async () => ({ body: { token: 'victim-session' }, createdAt: new Date(), status: 200 }))
    const theirs = vi.fn(async () => ({ body: { token: 'attacker-session' }, createdAt: new Date(), status: 200 }))
    const first = await facet2.handle('shared-key', {}, mine)
    const second = await facet2.handle('shared-key', {}, theirs)
    expect(theirs).not.toHaveBeenCalled()
    expect(second.body).toEqual(first.body)
  })

  it('identity scoping - same identity replaying same key gets the cached response (not re-executed)', async () => {
    const facet2 = new IdempotencyImpl(store, DEFAULT_IDEMPOTENCY_CONFIG)
    const exec = vi.fn(async () => ({ status: 200, body: { ok: true }, createdAt: new Date() }))
    await facet2.handle('k', {}, exec, { identityId: 'alice' })
    await facet2.handle('k', {}, exec, { identityId: 'alice' })
    expect(exec).toHaveBeenCalledOnce()
  })

  it('MemoryIdempotencyStore.get filters its own tombstone (matches Redis semantics)', async () => {
    await store.claim('k-tomb', 60_000, {})
    // After claim() the entry exists but the put() has not landed. A tombstone is not a miss, but it is
    // refused with the same code: `handle` must fall through to `claim` and then poll, and a third-party
    // store that only rejected "never seen" would serve the tombstone and break that protocol.
    await expect(store.get('k-tomb', {})).rejects.toMatchObject({ code: 'AUTH_IDEMPOTENCY_MISS' })
  })
})

describe('the facet windows', () => {
  afterEach(() => vi.useRealTimers())

  const exec = () => vi.fn(async () => ({ status: 200, body: {}, createdAt: new Date() }))

  it('keeps a key for the whole ttl configured, past a day', async () => {
    vi.useFakeTimers({ now: 0 })
    const facet = new IdempotencyImpl(new MemoryIdempotency(), { ttlMs: 48 * 3_600_000 })
    const run = exec()
    await facet.handle('k', {}, run)
    vi.setSystemTime(25 * 3_600_000)
    await facet.handle('k', {}, run)
    expect(run).toHaveBeenCalledOnce()
    vi.setSystemTime(48 * 3_600_000 + 1)
    await facet.handle('k', {}, run)
    expect(run).toHaveBeenCalledTimes(2)
  })

  it.each([Number.NaN, Number.POSITIVE_INFINITY])(
    'the store holds a key handed a ttl of %o for a minute, then frees it',
    async (ttl) => {
      vi.useFakeTimers({ now: 0 })
      const store = new MemoryIdempotency()
      expect(await store.claim('k', ttl, {})).toBe(true)
      expect(await store.claim('k', ttl, {})).toBe(false)
      vi.setSystemTime(60_001)
      expect(await store.claim('k', ttl, {})).toBe(true)
    },
  )

  it.each([Number.NaN, 0, -1, Number.POSITIVE_INFINITY])('refuses a ttlMs of %o', (ttlMs) => {
    expect(() => new IdempotencyImpl(new MemoryIdempotency(), { ttlMs })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it.each([Number.NaN, -1, Number.POSITIVE_INFINITY])('refuses a pollTimeoutMs of %o', (pollTimeoutMs) => {
    expect(() => new IdempotencyImpl(new MemoryIdempotency(), { pollTimeoutMs })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
  })

  it('takes a pollTimeoutMs of 0, which answers a concurrent retry 409 without waiting', async () => {
    const store = new MemoryIdempotency()
    await store.claim('_anon::k', 60_000, {})
    const run = exec()
    const r = await new IdempotencyImpl(store, { pollTimeoutMs: 0 }).handle('k', {}, run)
    expect(r.status).toBe(409)
    expect(run).not.toHaveBeenCalled()
  })
})
