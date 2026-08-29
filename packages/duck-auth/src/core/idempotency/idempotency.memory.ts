import { env } from 'node:process'
import { isExpiredAt } from '../credentials/credentials'
import type { TenantContext } from '../tenant/tenant.types'
import { IdempotencyImpl } from './idempotency'
import type { Idempotency } from './idempotency.types'

/**
 * In-memory Idempotency store. Dev / test only; production swaps in a
 * Redis-backed implementation via `SET NX EX` for true atomic claim
 * across multiple processes.
 *
 * Keys are scoped by tenantId so two tenants supplying the same
 * Idempotency-Key cannot collide.
 */
export class MemoryIdempotency implements Idempotency.Store {
  private readonly _entries = new Map<
    string,
    { response: Idempotency.CachedResponse; expiresAt: number; claimedAt: number }
  >()

  constructor(
    private readonly cfg?: {
      /** Escape hatch to allow this store under `NODE_ENV=production`. */
      development?: boolean
    },
  ) {
    // Only production is refused. Requiring `development: true` everywhere made the
    // no-arg constructor unusable, including the engine's own fallback.
    if (env.NODE_ENV === 'production' && !this.cfg?.development) {
      throw new Error('MemoryIdempotency is not production ready')
    }
  }

  /** Compose a tenant-scoped storage key. */
  private _k(key: string, ctx: TenantContext): string {
    return `${ctx.tenantId ?? '_default'}::${key}`
  }

  async get(key: string, ctx: TenantContext): Promise<Idempotency.CachedResponse | null> {
    const entry = this._entries.get(this._k(key, ctx))
    if (!entry) return null
    // Non-finite expiresAt would slip `NaN < now == false` past TTL.
    if (isExpiredAt(entry.expiresAt)) {
      this._entries.delete(this._k(key, ctx))
      return null
    }
    // Tombstone (status 0, body null) reports as "not yet" so caller polls.
    if (entry.response.status === 0 && entry.response.body === null) return null
    return entry.response
  }

  async claim(key: string, ttlMs: number, ctx: TenantContext): Promise<boolean> {
    const storeKey = this._k(key, ctx)
    const existing = this._entries.get(storeKey)
    const now = Date.now()
    if (existing && existing.expiresAt >= now) return false
    // Non-finite ttlMs would set expiresAt=NaN and freeze the slot forever
    // (NaN >= N evaluates false). Clamp to a sane window.
    const safeTtl = Number.isFinite(ttlMs) && ttlMs > 0 ? Math.min(ttlMs, 24 * 60 * 60 * 1000) : 60_000
    this._entries.set(storeKey, {
      response: { status: 0, body: null, createdAt: new Date(now) },
      expiresAt: now + safeTtl,
      claimedAt: now,
    })
    return true
  }

  async put(key: string, response: Idempotency.CachedResponse, ttlMs: number, ctx: TenantContext): Promise<void> {
    // Same NaN-bypass defense as claim(): clamp ttl to a sane window.
    const safeTtl = Number.isFinite(ttlMs) && ttlMs > 0 ? Math.min(ttlMs, 24 * 60 * 60 * 1000) : 60_000
    const now = Date.now()
    this._entries.set(this._k(key, ctx), {
      response: { ...response, createdAt: response.createdAt ?? new Date(now) },
      expiresAt: now + safeTtl,
      claimedAt: now,
    })
  }

  async delete(key: string, ctx: TenantContext): Promise<void> {
    this._entries.delete(this._k(key, ctx))
  }
}

/**
 * Build an in-memory idempotency facet in one call. Same shape as
 * {@link redisIdempotency}: store knobs and facet knobs in one object.
 *
 * Reach for `new MemoryIdempotency(...)` when you want the bare store.
 */
export function memoryIdempotency(cfg?: { development?: boolean } & Partial<Idempotency.Cfg>): IdempotencyImpl {
  return new IdempotencyImpl(new MemoryIdempotency(cfg), cfg)
}
