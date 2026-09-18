import type { RedisLike } from '~/core/drivers/redis-like'
import { AuthError } from '~/core/errors'
import type { Idempotency } from '~/core/idempotency/idempotency.types'
import { isFiniteNumber } from '~/core/predicates/predicates'
import type { TenantContext } from '~/core/tenant/tenant.types'
import { IdempotencyImpl } from './idempotency'

export namespace RedisIdempotency {
  export type Cfg<TRedis extends RedisLike.Client = RedisLike.Client> = {
    /** An ioredis, @upstash/redis or FakeRedis client. */
    redis: TRedis
    /** Default `auth:idem`, composing `${prefix}:{tenantId | _default}:{idempotencyKey}`. */
    prefix?: string
  }
}

/** `SET NX EX` makes the claim atomic across processes, and the per-tenant key prefix means two
 *  tenants sending one Idempotency-Key cannot collide. */
export class RedisIdempotency<TRedis extends RedisLike.Client = RedisLike.Client> implements Idempotency.Store {
  private readonly _redis: TRedis
  private readonly _prefix: string

  constructor(cfg: RedisIdempotency.Cfg<TRedis>) {
    this._redis = cfg.redis
    this._prefix = cfg.prefix ?? 'auth:idem'
  }

  private _k(key: string, ctx: TenantContext): string {
    return `${this._prefix}:${ctx.tenantId ?? '_default'}:${key}`
  }

  /** `AUTH_IDEMPOTENCY_MISS` on a miss, on TTL expiry, on a row that no longer parses, and while the claim
   *  tombstone is still there. */
  async get(key: string, ctx: TenantContext): Promise<Idempotency.CachedResponse> {
    const raw = await this._redis.get(this._k(key, ctx))
    if (!raw) throw new AuthError('AUTH_IDEMPOTENCY_MISS')
    const parsed = parseStoredIdempotencyEntry(raw)
    // A row this reader cannot parse is fail-closed to absent, as `parseStoredSession` is for sessions.
    if (parsed === null) throw new AuthError('AUTH_IDEMPOTENCY_MISS')
    // Status 0 with a null body is the claim marker the facet reads as "not yet", sending a racing
    // caller to its own poll loop. Filtered here, so no caller sees the placeholder.
    if (parsed.status === 0 && parsed.body === null) throw new AuthError('AUTH_IDEMPOTENCY_MISS')
    return parsed
  }

  /** Writes a tombstone that `put()` later overwrites. `true` when this caller won the race, `false`
   *  when a prior claim is still alive. */
  async claim(key: string, ttlMs: number, ctx: TenantContext): Promise<boolean> {
    // A NaN or Infinity ttl survives `Math.ceil` and `Math.max` as NaN, and Redis then rejects the
    // command outright.
    const safeMs = Number.isFinite(ttlMs) && ttlMs > 0 ? Math.min(ttlMs, 24 * 60 * 60 * 1000) : 60_000
    const ex = Math.max(1, Math.ceil(safeMs / 1000))
    const result = await this._redis.set(
      this._k(key, ctx),
      JSON.stringify({ status: 0, body: null, createdAt: Date.now() }),
      { nx: true, ex },
    )
    return result === 'OK'
  }

  /** Overwrites the tombstone `claim()` left, resetting the TTL to `ttlMs` so the cached entry
   *  survives a slow executor. */
  async put(key: string, response: Idempotency.CachedResponse, ttlMs: number, ctx: TenantContext): Promise<void> {
    const safeMs = Number.isFinite(ttlMs) && ttlMs > 0 ? Math.min(ttlMs, 24 * 60 * 60 * 1000) : 60_000
    const ex = Math.max(1, Math.ceil(safeMs / 1000))
    await this._redis.set(this._k(key, ctx), JSON.stringify({ ...response, createdAt: response.createdAt.getTime() }), {
      ex,
    })
  }

  /** For tests and flush operations. */
  async delete(key: string, ctx: TenantContext): Promise<void> {
    await this._redis.del(this._k(key, ctx))
  }
}

/** Structural parser for Redis idempotency entries; `null` on any malformed shape. */
function parseStoredIdempotencyEntry(raw: string): Idempotency.CachedResponse | null {
  let obj: unknown
  try {
    obj = JSON.parse(raw)
  } catch {
    return null
  }
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) return null
  const status: unknown = Reflect.get(obj, 'status')
  if (!isFiniteNumber(status)) return null
  const createdAt: unknown = Reflect.get(obj, 'createdAt')
  if (!isFiniteNumber(createdAt)) return null
  const body: unknown = Reflect.get(obj, 'body')
  const headers: unknown = Reflect.get(obj, 'headers')
  // Built explicitly rather than cast: every field is narrowed.
  const out: Idempotency.CachedResponse = { status, body, createdAt: new Date(createdAt) }
  if (typeof headers === 'object' && headers !== null && !Array.isArray(headers)) {
    // The value side is checked too, so a malformed inner shape cannot reach `res.setHeader()`.
    const safe: Record<string, string> = {}
    for (const [k, v] of Object.entries(headers)) {
      if (typeof v === 'string') safe[k] = v
    }
    out.headers = safe
  }
  return out
}

/**
 * Build a redis-backed idempotency facet in one call, the way `redisLimiter`
 * builds a limiter. Store knobs (`redis`, `prefix`) and facet knobs (`ttlMs`,
 * `headerName`, `pollTimeoutMs`) share the one object, so the config key reads
 * `idempotency: redisIdempotency({ prefix: 'auth:idem', redis })`.
 */
export function redisIdempotency<TRedis extends RedisLike.Client = RedisLike.Client>(
  cfg: RedisIdempotency.Cfg<TRedis> & Partial<Idempotency.Cfg>,
): IdempotencyImpl {
  return new IdempotencyImpl(new RedisIdempotency(cfg), cfg)
}
