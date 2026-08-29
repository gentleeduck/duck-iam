import type { RedisLike } from '~/adapters/redis/redis-like'
import { isFiniteNumber } from '~/core/credentials/credentials'
import type { Idempotency } from '~/core/idempotency/idempotency.types'
import type { TenantContext } from '~/core/tenant/tenant.types'
import { IdempotencyImpl } from './idempotency'

export namespace RedisIdempotency {
  /** Cfg knobs for {@link RedisIdempotency}. */
  export type Cfg<TRedis extends RedisLike.Client = RedisLike.Client> = {
    /** RedisLike client (ioredis, @upstash/redis, or FakeRedis). */
    redis: TRedis
    /**
     * Key namespace prefix. Default: `auth:idem`. Composed key:
     * `${prefix}:{tenantId | _default}:{idempotencyKey}`.
     */
    prefix?: string
  }
}

/**
 * Redis-backed `Idempotency.IStore`. Uses `SET NX EX` for atomic
 * cross-process claim semantics. Tenant isolation comes from the
 * per-tenant key prefix; two tenants supplying the same Idempotency-Key
 * cannot collide.
 */
export class RedisIdempotency<TRedis extends RedisLike.Client = RedisLike.Client> implements Idempotency.Store {
  private readonly _redis: TRedis
  private readonly _prefix: string

  constructor(cfg: RedisIdempotency.Cfg<TRedis>) {
    this._redis = cfg.redis
    this._prefix = cfg.prefix ?? 'auth:idem'
  }

  /** Compose tenant-scoped storage key. */
  private _k(key: string, ctx: TenantContext): string {
    return `${this._prefix}:${ctx.tenantId ?? '_default'}:${key}`
  }

  /**
   * Read the cached response for an idempotency key. Returns null on
   * miss, on TTL expiry, or while the claim tombstone is still present.
   */
  async get(key: string, ctx: TenantContext): Promise<Idempotency.CachedResponse | null> {
    const raw = await this._redis.get(this._k(key, ctx))
    if (!raw) return null
    const parsed = parseStoredIdempotencyEntry(raw)
    if (parsed === null) return null
    // Tombstone semantics: status 0 + body null is the claim marker the
    // facet treats as "not yet" so racing callers fall through to their
    // own poll loop. Filter it here so callers never see the placeholder.
    if (parsed.status === 0 && parsed.body === null) return null
    return parsed
  }

  /**
   * Atomic claim via `SET NX EX`. Writes a tombstone the executor will
   * later overwrite with `put()`. Returns true when this caller won the
   * race; false when a prior claim is still alive.
   */
  async claim(key: string, ttlMs: number, ctx: TenantContext): Promise<boolean> {
    // NaN/Infinity/huge ttl would make Math.ceil(NaN/1000)=NaN -> Math.max(1,NaN)=NaN
    // -> Redis would reject. Clamp to a sane window.
    const safeMs = Number.isFinite(ttlMs) && ttlMs > 0 ? Math.min(ttlMs, 24 * 60 * 60 * 1000) : 60_000
    const ex = Math.max(1, Math.ceil(safeMs / 1000))
    const result = await this._redis.set(
      this._k(key, ctx),
      JSON.stringify({ status: 0, body: null, createdAt: Date.now() }),
      { nx: true, ex },
    )
    return result === 'OK'
  }

  /**
   * Store the executor's response, overwriting any tombstone left by
   * `claim()`. TTL is reset to `ttlMs` so the cached entry survives a
   * slow executor.
   */
  async put(key: string, response: Idempotency.CachedResponse, ttlMs: number, ctx: TenantContext): Promise<void> {
    const safeMs = Number.isFinite(ttlMs) && ttlMs > 0 ? Math.min(ttlMs, 24 * 60 * 60 * 1000) : 60_000
    const ex = Math.max(1, Math.ceil(safeMs / 1000))
    await this._redis.set(this._k(key, ctx), JSON.stringify({ ...response, createdAt: response.createdAt.getTime() }), {
      ex,
    })
  }

  /** Drop a key. Used by tests + flush operations. */
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
  // Build the result explicitly - no `as` cast, every field is narrowed.
  const out: Idempotency.CachedResponse = { status, body, createdAt: new Date(createdAt) }
  if (typeof headers === 'object' && headers !== null && !Array.isArray(headers)) {
    // Headers must be a Record<string, string>. Validate the value side
    // so a malformed inner shape can't propagate into res.setHeader().
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
 *
 * Reach for `new RedisIdempotency(...)` when you want the bare store.
 */
export function redisIdempotency<TRedis extends RedisLike.Client = RedisLike.Client>(
  cfg: RedisIdempotency.Cfg<TRedis> & Partial<Idempotency.Cfg>,
): IdempotencyImpl {
  return new IdempotencyImpl(new RedisIdempotency(cfg), cfg)
}
