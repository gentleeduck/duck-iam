/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { TenantContext } from '../../core/types/context'
import type { Idempotency } from '../../core/types/idempotency'
import type { RedisLike } from './redis-like'

/**
 * Config knobs for `RedisIdempotencyStore`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface RedisIdempotencyStoreConfig {
  /** RedisLike client (ioredis, @upstash/redis, or FakeRedis). */
  redis: RedisLike
  /**
   * Key namespace prefix. Default: `auth:idem`. Composed key:
   * `${prefix}:{tenantId | _default}:{idempotencyKey}`.
   */
  prefix?: string
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
 * cross-process claim semantics — the property the memory store cannot
 * provide. Tenant isolation comes from the per-tenant key prefix; two
 * tenants supplying the same Idempotency-Key cannot collide.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class RedisIdempotencyStore implements Idempotency.IStore {
  private readonly _redis: RedisLike
  private readonly _prefix: string

  constructor(cfg: RedisIdempotencyStoreConfig) {
    this._redis = cfg.redis
    this._prefix = cfg.prefix ?? 'auth:idem'
  }

  /** Compose tenant-scoped storage key. */
  private _k(key: string, ctx: TenantContext): string {
    return `${this._prefix}:${ctx.tenantId ?? '_default'}:${key}`
  }

  /**
   * Read the cached response for an idempotency key. Returns null on
   * miss, on TTL expiry, or while the claim tombstone is still present
   * (caller treats null + claim race as "execute again").
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async get(key: string, ctx: TenantContext): Promise<Idempotency.ICachedResponse | null> {
    const raw = await this._redis.get(this._k(key, ctx))
    if (!raw) return null
    const parsed = JSON.parse(raw) as Idempotency.ICachedResponse
    if (parsed.status === 0 && parsed.body === null) return null
    return parsed
  }

  /**
   * Atomic claim via `SET NX EX`. Writes a tombstone the executor will
   * later overwrite with `put()`. Returns true when this caller won the
   * race; false when a prior claim is still alive.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async claim(key: string, ttlMs: number, ctx: TenantContext): Promise<boolean> {
    const ex = Math.max(1, Math.ceil(ttlMs / 1000))
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
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async put(key: string, response: Idempotency.ICachedResponse, ttlMs: number, ctx: TenantContext): Promise<void> {
    const ex = Math.max(1, Math.ceil(ttlMs / 1000))
    await this._redis.set(
      this._k(key, ctx),
      JSON.stringify({ ...response, createdAt: response.createdAt ?? Date.now() }),
      { ex },
    )
  }

  /**
   * Drop a key. Used by tests + flush operations.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async delete(key: string, ctx: TenantContext): Promise<void> {
    await this._redis.del(this._k(key, ctx))
  }
}

/**
 * Namespace merge for `RedisIdempotencyStore`. Co-locates config alongside
 * the class via TS class+namespace merging.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace RedisIdempotencyStore {
  /** Alias for `RedisIdempotencyStoreConfig`. */
  export type IConfig = RedisIdempotencyStoreConfig
}
