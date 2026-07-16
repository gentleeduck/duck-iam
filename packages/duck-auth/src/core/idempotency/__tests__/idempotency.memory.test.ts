import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IdempotencyImpl } from '../idempotency'
import { DEFAULT_IDEMPOTENCY_CONFIG } from '../idempotency.constants'
import { MemoryIdempotency } from '../idempotency.memory'

describe('MemoryIdempotencyStore', () => {
  it('get returns null for unseen keys', async () => {
    const store = new MemoryIdempotency()
    expect(await store.get('k', {})).toBeNull()
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
    expect(got?.status).toBe(201)
    expect(got?.body).toEqual({ ok: true })
  })

  it('respects tenant scope (same key in different tenants do not collide)', async () => {
    const store = new MemoryIdempotency()
    await store.put('k', { status: 200, body: 'A', createdAt: new Date() }, 60_000, { tenantId: 'A' })
    await store.put('k', { status: 200, body: 'B', createdAt: new Date() }, 60_000, { tenantId: 'B' })
    expect((await store.get('k', { tenantId: 'A' }))?.body).toBe('A')
    expect((await store.get('k', { tenantId: 'B' }))?.body).toBe('B')
  })

  it('TTL elapses + get returns null', async () => {
    const store = new MemoryIdempotency()
    await store.put('k', { status: 200, body: 'x', createdAt: new Date() }, 1, {})
    await new Promise((r) => setTimeout(r, 5))
    expect(await store.get('k', {})).toBeNull()
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

  it('disabled facet (null store) bypasses the cache entirely', async () => {
    const disabled = new IdempotencyImpl(null, DEFAULT_IDEMPOTENCY_CONFIG)
    expect(disabled.enabled()).toBe(false)
    const exec = vi.fn(async () => ({ status: 200, body: {}, createdAt: new Date() }))
    await disabled.handle('k', {}, exec)
    await disabled.handle('k', {}, exec)
    expect(exec).toHaveBeenCalledTimes(2)
  })

  it('headerName surfaces the configured header for adapter use', () => {
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

  it('identity scoping - same identity replaying same key gets the cached response (not re-executed)', async () => {
    const facet2 = new IdempotencyImpl(store, DEFAULT_IDEMPOTENCY_CONFIG)
    const exec = vi.fn(async () => ({ status: 200, body: { ok: true }, createdAt: new Date() }))
    await facet2.handle('k', {}, exec, { identityId: 'alice' })
    await facet2.handle('k', {}, exec, { identityId: 'alice' })
    expect(exec).toHaveBeenCalledOnce()
  })

  it('MemoryIdempotencyStore.get filters its own tombstone (matches Redis semantics)', async () => {
    await store.claim('k-tomb', 60_000, {})
    // After claim() the entry exists but the put() has not landed.
    // get() must report null so handle() does not serve the tombstone.
    expect(await store.get('k-tomb', {})).toBeNull()
  })
})
