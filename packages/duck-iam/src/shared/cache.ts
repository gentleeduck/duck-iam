import type { IamEngine } from '../core'
/**
 * LRU cache with TTL expiration; relies on `Map` insertion order. Used by {@link IamEngine} for policies/roles/subjects.
 *
 * @template V - Type of cached values.
 */
export class IamLRUCache<V> {
  private _map = new Map<string, { value: V; expiresAt: number }>()
  private _maxSize: number
  private _ttl: number
  private _hits = 0
  private _misses = 0

  /**
   * @param maxSize - Sets the maximum number of entries before LRU eviction.
   * @param ttlMs - Sets time-to-live in milliseconds for each entry.
   * @throws `RangeError` when `maxSize < 1` or `ttlMs < 0`.
   */
  constructor(maxSize: number, ttlMs: number) {
    if (!Number.isFinite(maxSize) || maxSize < 1)
      throw new RangeError('IamLRUCache maxSize must be a finite number >= 1')
    if (!Number.isFinite(ttlMs) || ttlMs < 0) throw new RangeError('IamLRUCache ttlMs must be a finite number >= 0')
    this._maxSize = maxSize
    this._ttl = ttlMs
  }

  /**
   * Get + refresh LRU; `undefined` when missing or expired.
   *
   * @param key - Looks up the entry under this cache key.
   * @returns The stored value, or `undefined` when missing or expired.
   */
  get(key: string): V | undefined {
    const entry = this._map.get(key)
    if (!entry) {
      this._misses++
      return undefined
    }
    // `>=`, not `>`: `expiresAt` is an exclusive upper bound everywhere else in
    // this package - a grant is inactive at the exact millisecond it expires -
    // and a `notAfter` cap is only worth anything if the cache agrees. At the
    // TTL's own boundary the difference is one millisecond of extra freshness.
    if (Date.now() >= entry.expiresAt) {
      this._map.delete(key)
      this._misses++
      return undefined
    }
    this._map.delete(key)
    this._map.set(key, entry)
    this._hits++
    return entry.value
  }

  /** Hit/miss counters + current size. */
  get stats(): { hits: number; misses: number; size: number } {
    return { hits: this._hits, misses: this._misses, size: this._map.size }
  }

  /** Zeroes the hit and miss counters without clearing stored entries. */
  resetStats(): void {
    this._hits = 0
    this._misses = 0
  }

  /**
   * Set + TTL refresh; evicts the oldest at capacity.
   *
   * `notAfter` caps the entry's life below the cache's own TTL, for a value
   * that is only true until a known instant. A time-boxed grant is exactly
   * that: the adapter answers `[startsAt, expiresAt)` to the millisecond, and
   * without the cap the snapshot of that answer outlived it by up to a full
   * `cacheTTL` - 60 seconds by default - so a grant issued to expire in 30
   * seconds kept granting for 90.
   *
   * @param key - Stores the entry under this cache key.
   * @param value - Associates this value with the key.
   * @param notAfter - Epoch ms this value stops being true, when that is
   *   known. Ignored unless it is a finite instant earlier than the TTL would
   *   give; an instant already past stores nothing at all.
   */
  set(key: string, value: V, notAfter?: number): void {
    this._map.delete(key)
    const now = Date.now()
    let expiresAt = now + this._ttl
    if (notAfter !== undefined && Number.isFinite(notAfter) && notAfter < expiresAt) {
      if (notAfter <= now) return
      expiresAt = notAfter
    }
    if (this._map.size >= this._maxSize) {
      const first = this._map.keys().next().value
      if (first !== undefined) this._map.delete(first)
    }
    this._map.set(key, { value, expiresAt })
  }

  /**
   * Remove a single entry.
   *
   * @param key - Removes the entry stored under this cache key.
   * @returns `true` when the entry existed and was deleted.
   */
  delete(key: string): boolean {
    return this._map.delete(key)
  }

  /** Clears entries without resetting stat counters. */
  clear(): void {
    this._map.clear()
  }

  get size(): number {
    return this._map.size
  }

  /** Iterate non-expired entries; does NOT refresh LRU order. */
  *entries(): IterableIterator<[string, V]> {
    const now = Date.now()
    for (const [key, entry] of this._map) {
      if (now > entry.expiresAt) continue
      yield [key, entry.value]
    }
  }
}

/** Factory around {@link IamLRUCache}, for callers who prefer functions to `new`. */
export function iamLRUCache<V>(...args: ConstructorParameters<typeof IamLRUCache<V>>): IamLRUCache<V> {
  return new IamLRUCache<V>(...args)
}
