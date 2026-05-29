import { isFiniteNumber } from '../../core/credential-utils'
import type { TenantContext } from '../../core/types/context'
import type { Idempotency } from '../../core/types/idempotency'
import type { RedisLike } from './redis-like'

/**
 * Public surface for the Redis-backed idempotency store. Every type
 * lives inside the namespace.
 */
export namespace RedisIdempotencyStore {
  /** Config knobs for {@link RedisIdempotencyStore}. */
  export interface IConfig {
    /** RedisLike client (ioredis, @upstash/redis, or FakeRedis). */
    redis: RedisLike.IClient
    /**
     * Key namespace prefix. Default: `auth:idem`. Composed key:
     * `${prefix}:{tenantId | _default}:{idempotencyKey}`.
     */
    prefix?: string
  }
}

/**
 * Tombstone written by `claim()` before the route executor runs. The
 * `status: 0` and `body: null` shape is treated as "claim pending" by
 * `IdempotencyFacet.handle()` -- a second caller racing the first reads
 * this stub and falls through to its own `get()` retry.
 */
const CLAIM_TOMBSTONE = Object.freeze({ status: 0, body: null }) as Idempotency.ICachedResponse

/**
 * Redis-backed `Idempotency.IStore`. Uses `SET NX EX` for atomic
 * cross-process claim semantics. Tenant isolation comes from the
 * per-tenant key prefix; two tenants supplying the same Idempotency-Key
 * cannot collide.
 */
export class RedisIdempotencyStore implements Idempotency.IStore {
  private readonly _redis: RedisLike.IClient
  private readonly _prefix: string

  constructor(cfg: RedisIdempotencyStore.IConfig) {
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
  async get(key: string, ctx: TenantContext): Promise<Idempotency.ICachedResponse | null> {
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
    // NaN/Infinity/huge ttl would make Math.ceil(NaN/1000)=NaN → Math.max(1,NaN)=NaN
    // → Redis would reject. Clamp to a sane window.
    const safeMs = Number.isFinite(ttlMs) && ttlMs > 0 ? Math.min(ttlMs, 24 * 60 * 60 * 1000) : 60_000
    const ex = Math.max(1, Math.ceil(safeMs / 1000))
    const tombstone: Idempotency.ICachedResponse = {
      ...CLAIM_TOMBSTONE,
      createdAt: Date.now(),
    }
    const result = await this._redis.set(this._k(key, ctx), JSON.stringify(tombstone), {
      nx: true,
      ex,
    })
    return result === 'OK'
  }

  /**
   * Store the executor's response, overwriting any tombstone left by
   * `claim()`. TTL is reset to `ttlMs` so the cached entry survives a
   * slow executor.
   */
  async put(key: string, response: Idempotency.ICachedResponse, ttlMs: number, ctx: TenantContext): Promise<void> {
    const safeMs = Number.isFinite(ttlMs) && ttlMs > 0 ? Math.min(ttlMs, 24 * 60 * 60 * 1000) : 60_000
    const ex = Math.max(1, Math.ceil(safeMs / 1000))
    await this._redis.set(
      this._k(key, ctx),
      JSON.stringify({ ...response, createdAt: response.createdAt ?? Date.now() }),
      { ex },
    )
  }

  /**
   * Drop a key. Used by tests + flush operations.
   */
  async delete(key: string, ctx: TenantContext): Promise<void> {
    await this._redis.del(this._k(key, ctx))
  }
}

/**
 * structural parser for `RedisIdempotencyStore`
 * entries. The prior implementation did `JSON.parse(raw) as
 * Idempotency.ICachedResponse` - a cast that lied about Redis-returned
 * `unknown`. Concrete failures the cast masked:
 *
 *  - `raw = '{}'` (corrupted entry / schema drift) -> `parsed.status`
 *    undefined -> tombstone check `=== 0` false -> returns the empty
 *    object as a "successful cached response" to the facet, which
 *    serves it to the client.
 *  - `raw = 'null'` -> `JSON.parse('null') === null` -> the next line
 *    `parsed.status` throws TypeError, propagates to the caller, becomes
 *    HTTP 500 instead of a benign cache miss.
 *  - `raw = '[]'` / `raw = '42'` / `raw = '"oops"'` -> similar - accessing
 *    `.status` either throws or returns undefined.
 *  - `raw = '{"status":"200","body":...}'` (string instead of number) ->
 *    cast accepts it; downstream framework code that calls `res.status(parsed.status)`
 *    receives a string and behaves unpredictably.
 *  - `raw = '<truncated json'` -> `JSON.parse` throws SyntaxError ->
 *    surfaces as 500.
 *
 * Threat-model note: matches the parser pattern applied across duck-auth
 * (`parseStoredSession`, `parseStoredDPoPNonce`, `parseWebauthnMfaMetadata`).
 * Defense in depth - if an attacker has Redis write access they can mint
 * arbitrary cached responses anyway; this catches the far more common
 * causes (corruption / schema drift / wrong-type accidents) safely.
 *
 * Returns `null` on any structural failure so the caller fail-closes
 * (treats the entry as missing -> falls through to executor + claim).
 *
 * The returned object is constructed field-by-field so no `as` cast is
 * needed; every output field has been narrowed to its target type via
 * `typeof` / `isFiniteNumber`.
 */
function parseStoredIdempotencyEntry(raw: string): Idempotency.ICachedResponse | null {
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
  const out: Idempotency.ICachedResponse = { status, body, createdAt }
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
