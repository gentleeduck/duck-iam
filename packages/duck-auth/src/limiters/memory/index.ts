// Re-exported so a consumer can type the limiter they supply. `strict()` refuses to
// boot production without one, so the interface has to be reachable.
export type { Limiter } from '../limiters.types'

import { AuthError } from '~/core/errors'
import type { Limiter } from '../limiters.types'

export namespace MemoryLimiter {
  export type Cfg = {
    /** Max consumed weight before further consume() returns ok:false. Default 10. */
    max?: number
    /** Window size in ms. Default 15 minutes. */
    windowMs?: number
  }
}

/** Expired buckets are swept only once the map has grown past this, so the cost is amortised: sweeping
 *  on every new key is O(n) per request during exactly the flood it exists to survive. */
const SWEEP_AT = 1024
/** Past this `now + windowMs` stops being a representable `Date`, and a window this long is a ban. */
const WINDOW_MAX_MS = 8_640_000_000_000

/**
 * Token-bucket memory limiter. Dev/test only; production uses Redis.
 * Per-key independent bucket; reset() empties one bucket.
 *
 * WARN: the live set is still unbounded, and deliberately so - evicting a bucket that has not expired
 * hands its owner their budget back, which is the whole limit. Only elapsed ones are dropped. A
 * deployment facing a flood of distinct keys wants the Redis limiter, whose buckets expire in the store.
 */
export class MemoryLimiter implements Limiter.Me {
  /** Read by `AuthEngine.strict({ env: 'production' })`, which refuses this class there: a bucket per
   *  node multiplies every budget by the node count, and a restart returns them all. A tag rather than a
   *  class-identity compare, for the reason `NoopLimiter` carries one. */
  readonly __isInProcessLimiter = true as const
  private readonly _max: number
  private readonly _windowMs: number
  private _buckets = new Map<string, { count: number; resetAt: number }>()

  constructor(cfg: MemoryLimiter.Cfg = {}) {
    this._max = cfg.max ?? 10
    this._windowMs = cfg.windowMs ?? 15 * 60 * 1000
    // SECURITY: `consume` bounds the `weight` a caller passes and the `key` it names, and these two -
    // the numbers that decide whether it limits at all - arrived unchecked. `max` non-finite makes
    // `count > NaN` false on every call, so the limiter answers `ok` to an unbounded number of attempts
    // and the brute-force defence `strict()` insists on is simply off. A `windowMs` that is not a
    // positive number never elapses, so the first budget spent is the last: `resetAt` reads
    // `Invalid Date` and the key is locked out until the process restarts.
    if (!Number.isFinite(this._max) || this._max < 1 || this._max > Number.MAX_SAFE_INTEGER) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `memoryLimiter: max must be a number between 1 and ${Number.MAX_SAFE_INTEGER} (got ${this._max})`,
      })
    }
    if (!Number.isFinite(this._windowMs) || this._windowMs < 1 || this._windowMs > WINDOW_MAX_MS) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `memoryLimiter: windowMs must be a number between 1 and ${WINDOW_MAX_MS} (got ${this._windowMs})`,
      })
    }
  }

  /** Takes `weight` from the key's budget; an unusable key fails closed as rate-limited. */
  async consume(key: string, weight = 1): Promise<Limiter.Result> {
    const now = Date.now()
    if (typeof key !== 'string' || key.length === 0 || key.length > 1024) {
      // Fail closed, reading as rate-limited, so a bogus key cannot probe limiter state.
      return { ok: false, remaining: 0, resetAt: new Date(now + this._windowMs) }
    }
    const w = Number.isFinite(weight) ? Math.max(1, Math.floor(weight)) : 1
    let b = this._buckets.get(key)
    if (!b || b.resetAt < now) {
      // Elapsed buckets are dropped here because nothing else ever removed one: the key is whatever a
      // request can name - an email for the password guard, an identity id elsewhere - so a flood of
      // distinct addresses grew this map for as long as the process lived. `strict()` does not stop that
      // reaching production; it refuses only the noop limiter.
      if (this._buckets.size >= SWEEP_AT) {
        for (const [k, v] of this._buckets) if (v.resetAt < now) this._buckets.delete(k)
      }
      b = { count: 0, resetAt: now + this._windowMs }
      this._buckets.set(key, b)
    }
    if (b.count + w > this._max) {
      return { ok: false, remaining: Math.max(0, this._max - b.count), resetAt: new Date(b.resetAt) }
    }
    b.count += w
    return { ok: true, remaining: this._max - b.count, resetAt: new Date(b.resetAt) }
  }

  /** Drops the key's bucket, so the next call starts from a full budget. */
  async reset(key: string): Promise<void> {
    this._buckets.delete(key)
  }
}

/** Constructs a {@link MemoryLimiter}. Single node only; a fleet needs the Redis limiter. */
export function memoryLimiter(cfg?: Partial<MemoryLimiter.Cfg>): MemoryLimiter {
  return new MemoryLimiter(cfg)
}
