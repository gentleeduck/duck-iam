import type { Limiter } from '../../core/types/infra'

/**
 * Token-bucket memory limiter. Dev/test only; production uses Redis.
 * Per-key independent bucket; reset() empties one bucket.
 */
export class AuthMemoryLimiter implements Limiter.Limiter {
  private readonly _max: number
  private readonly _windowMs: number
  private _buckets = new Map<string, { count: number; resetAt: number }>()

  constructor(cfg: AuthMemoryLimiter.IConfig = {}) {
    this._max = cfg.max ?? 10
    this._windowMs = cfg.windowMs ?? 15 * 60 * 1000
  }

  async consume(key: string, weight = 1): Promise<Limiter.Result> {
    const now = Date.now()
    if (typeof key !== 'string' || key.length === 0 || key.length > 1024) {
      // Refuse the consume - fail-closed (treat as if rate-limited) so
      // bogus keys cannot probe limiter state.
      return { ok: false, remaining: 0, resetAt: new Date(now + this._windowMs) }
    }
    const w = Number.isFinite(weight) ? Math.max(1, Math.floor(weight)) : 1
    let b = this._buckets.get(key)
    if (!b || b.resetAt < now) {
      b = { count: 0, resetAt: now + this._windowMs }
      this._buckets.set(key, b)
    }
    if (b.count + w > this._max) {
      return { ok: false, remaining: Math.max(0, this._max - b.count), resetAt: new Date(b.resetAt) }
    }
    b.count += w
    return { ok: true, remaining: this._max - b.count, resetAt: new Date(b.resetAt) }
  }

  async reset(key: string): Promise<void> {
    this._buckets.delete(key)
  }
}

export namespace AuthMemoryLimiter {
  export interface IConfig {
    /** Max consumed weight before further consume() returns ok:false. Default 10. */
    max?: number
    /** Window size in ms. Default 15 minutes. */
    windowMs?: number
  }
}
