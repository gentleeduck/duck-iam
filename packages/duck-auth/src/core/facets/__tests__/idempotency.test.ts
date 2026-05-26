/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { DEFAULT_IDEMPOTENCY_CONFIG, IdempotencyFacet, MemoryIdempotencyStore } from '../idempotency'

describe('MemoryIdempotencyStore', () => {
  it('get returns null for unseen keys', async () => {
    const store = new MemoryIdempotencyStore()
    expect(await store.get('k', {})).toBeNull()
  })

  it('claim returns true the first time + false on subsequent claims within TTL', async () => {
    const store = new MemoryIdempotencyStore()
    expect(await store.claim('k', 60_000, {})).toBe(true)
    expect(await store.claim('k', 60_000, {})).toBe(false)
  })

  it('put + get roundtrip persists status + body', async () => {
    const store = new MemoryIdempotencyStore()
    await store.put('k', { status: 201, body: { ok: true }, createdAt: Date.now() }, 60_000, {})
    const got = await store.get('k', {})
    expect(got?.status).toBe(201)
    expect(got?.body).toEqual({ ok: true })
  })

  it('respects tenant scope (same key in different tenants do not collide)', async () => {
    const store = new MemoryIdempotencyStore()
    await store.put('k', { status: 200, body: 'A', createdAt: Date.now() }, 60_000, { tenantId: 'A' })
    await store.put('k', { status: 200, body: 'B', createdAt: Date.now() }, 60_000, { tenantId: 'B' })
    expect((await store.get('k', { tenantId: 'A' }))?.body).toBe('A')
    expect((await store.get('k', { tenantId: 'B' }))?.body).toBe('B')
  })

  it('TTL elapses + get returns null', async () => {
    const store = new MemoryIdempotencyStore()
    await store.put('k', { status: 200, body: 'x', createdAt: Date.now() }, 1, {})
    await new Promise((r) => setTimeout(r, 5))
    expect(await store.get('k', {})).toBeNull()
  })
})

describe('IdempotencyFacet.handle', () => {
  let store: MemoryIdempotencyStore
  let facet: IdempotencyFacet

  beforeEach(() => {
    store = new MemoryIdempotencyStore()
    facet = new IdempotencyFacet(store, DEFAULT_IDEMPOTENCY_CONFIG)
  })

  it('executes once + caches; second call returns the cached response without re-executing', async () => {
    const exec = vi.fn(async () => ({ status: 200, body: { n: 1 }, createdAt: Date.now() }))
    const a = await facet.handle('key-1', {}, exec)
    const b = await facet.handle('key-1', {}, exec)
    expect(exec).toHaveBeenCalledOnce()
    expect(a.body).toEqual({ n: 1 })
    expect(b.body).toEqual({ n: 1 })
  })

  it('different keys run the executor independently', async () => {
    const exec = vi.fn(async () => ({ status: 200, body: {}, createdAt: Date.now() }))
    await facet.handle('key-1', {}, exec)
    await facet.handle('key-2', {}, exec)
    expect(exec).toHaveBeenCalledTimes(2)
  })

  it('empty key bypasses the cache entirely', async () => {
    const exec = vi.fn(async () => ({ status: 200, body: {}, createdAt: Date.now() }))
    await facet.handle('', {}, exec)
    await facet.handle('', {}, exec)
    expect(exec).toHaveBeenCalledTimes(2)
  })

  it('disabled facet (null store) bypasses the cache entirely', async () => {
    const disabled = new IdempotencyFacet(null, DEFAULT_IDEMPOTENCY_CONFIG)
    expect(disabled.enabled()).toBe(false)
    const exec = vi.fn(async () => ({ status: 200, body: {}, createdAt: Date.now() }))
    await disabled.handle('k', {}, exec)
    await disabled.handle('k', {}, exec)
    expect(exec).toHaveBeenCalledTimes(2)
  })

  it('headerName surfaces the configured header for adapter use', () => {
    expect(facet.headerName).toBe('idempotency-key')
  })
})
