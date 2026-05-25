import type { Limiter } from '../../core/types/limiter'

export interface MemoryLimiterConfig {
  /** Max consumed weight before further consume() returns ok:false. Default 10. */
  max?: number
  /** Window size in ms. Default 15 minutes. */
  windowMs?: number
}

/**
 * Token-bucket memory limiter. Dev/test only; production uses Redis.
 * Per-key independent bucket; reset() empties one bucket.
 */
export class MemoryLimiter implements Limiter.ILimiter {
  private readonly _max: number
  private readonly _windowMs: number
  private _buckets = new Map<string, { count: number; resetAt: number }>()

  constructor(cfg: MemoryLimiterConfig = {}) {
    this._max = cfg.max ?? 10
    this._windowMs = cfg.windowMs ?? 15 * 60 * 1000
  }

  async consume(key: string, weight = 1): Promise<Limiter.IResult> {
    const now = Date.now()
    let b = this._buckets.get(key)
    if (!b || b.resetAt < now) {
      b = { count: 0, resetAt: now + this._windowMs }
      this._buckets.set(key, b)
    }
    if (b.count + weight > this._max) {
      return { ok: false, remaining: Math.max(0, this._max - b.count), resetAt: b.resetAt }
    }
    b.count += weight
    return { ok: true, remaining: this._max - b.count, resetAt: b.resetAt }
  }

  async reset(key: string): Promise<void> {
    this._buckets.delete(key)
  }
}
