import { env } from 'node:process'
import { AuthError } from '~/core/errors'
import { isExpiredAt } from '../predicates/predicates'
import type { TenantContext } from '../tenant/tenant.types'
import { IdempotencyImpl } from './idempotency'
import type { Idempotency } from './idempotency.types'

/**
 * Dev and test only: production needs the Redis store, whose `SET NX EX` claim is atomic across
 * processes. Keys are scoped by an encoded tenantId, so two tenants sending one Idempotency-Key cannot
 * collide however the host spells its tenant ids.
 */
export class MemoryIdempotency implements Idempotency.Store {
  /** Read by `strict()`, which must not go by constructor name: every plain-object store would answer to one. */
  readonly __isInProcessIdempotency = true as const
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
    // Only production is refused: requiring `development: true` everywhere made the no-arg constructor
    // unusable, the engine's own fallback included.
    if (env.NODE_ENV === 'production' && !this.cfg?.development) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'MemoryIdempotency is not production ready' })
    }
  }

  private _k(key: string, ctx: TenantContext): string {
    // The tenant segment is encoded and absence is the empty string, not a name a tenant could hold.
    // Raw, tenant `a::b` key `k` and tenant `a` key `b::k` were one entry, and the key half is the
    // client's `Idempotency-Key` header - so a tenant read the response cached for its own prefix.
    return `${encodeURIComponent(ctx.tenantId ?? '')}::${key}`
  }

  /** The cached response, throwing `AUTH_IDEMPOTENCY_MISS` when the key holds none. */
  async get(key: string, ctx: TenantContext): Promise<Idempotency.CachedResponse> {
    const entry = this._entries.get(this._k(key, ctx))
    if (!entry) throw new AuthError('AUTH_IDEMPOTENCY_MISS')
    // Non-finite expiresAt would slip `NaN < now == false` past TTL.
    if (isExpiredAt(entry.expiresAt)) {
      this._entries.delete(this._k(key, ctx))
      throw new AuthError('AUTH_IDEMPOTENCY_MISS')
    }
    // Tombstone (status 0, body null) reports as "not yet" so caller polls.
    if (entry.response.status === 0 && entry.response.body === null) {
      throw new AuthError('AUTH_IDEMPOTENCY_MISS')
    }
    return entry.response
  }

  /** Takes the key for this caller, answering false when someone else already holds it. */
  async claim(key: string, ttlMs: number, ctx: TenantContext): Promise<boolean> {
    const storeKey = this._k(key, ctx)
    const existing = this._entries.get(storeKey)
    const now = Date.now()
    if (existing && existing.expiresAt >= now) return false
    // A non-finite ttlMs sets expiresAt to NaN, and `NaN >= N` is false, so the slot never frees.
    const safeTtl = Number.isFinite(ttlMs) && ttlMs > 0 ? Math.min(ttlMs, 24 * 60 * 60 * 1000) : 60_000
    this._entries.set(storeKey, {
      response: { status: 0, body: null, createdAt: new Date(now) },
      expiresAt: now + safeTtl,
      claimedAt: now,
    })
    return true
  }

  /** Stores the response, so a replay of the key answers from cache. */
  async put(key: string, response: Idempotency.CachedResponse, ttlMs: number, ctx: TenantContext): Promise<void> {
    // The same NaN bypass as claim().
    const safeTtl = Number.isFinite(ttlMs) && ttlMs > 0 ? Math.min(ttlMs, 24 * 60 * 60 * 1000) : 60_000
    const now = Date.now()
    this._entries.set(this._k(key, ctx), {
      response: { ...response, createdAt: response.createdAt ?? new Date(now) },
      expiresAt: now + safeTtl,
      claimedAt: now,
    })
  }

  /** Drops the key, so the next request carrying it runs for real. */
  async delete(key: string, ctx: TenantContext): Promise<void> {
    this._entries.delete(this._k(key, ctx))
  }
}

/** Store knobs and facet knobs in one object, the shape `redisIdempotency` takes. Reach for
 *  `new MemoryIdempotency(...)` when the bare store is what is wanted. */
export function memoryIdempotency(cfg?: { development?: boolean } & Partial<Idempotency.Cfg>): IdempotencyImpl {
  return new IdempotencyImpl(new MemoryIdempotency(cfg), cfg)
}
