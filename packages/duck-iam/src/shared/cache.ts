import type { Engine } from '../core'
/**
 * LRU cache with TTL expiration; relies on `Map` insertion order. Used by {@link Engine} for policies/roles/subjects.
 *
 * @template V - Type of cached values.
 */
export class LRUCache<V> {
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
    if (!Number.isFinite(maxSize) || maxSize < 1) throw new RangeError('LRUCache maxSize must be a finite number >= 1')
    if (!Number.isFinite(ttlMs) || ttlMs < 0) throw new RangeError('LRUCache ttlMs must be a finite number >= 0')
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
    if (Date.now() > entry.expiresAt) {
      this._map.delete(key)
      this._misses++
      return undefined
    }
    // Move to end (most recently used)
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
   * @param key - Stores the entry under this cache key.
   * @param value - Associates this value with the key.
   */
  set(key: string, value: V): void {
    this._map.delete(key)
    if (this._map.size >= this._maxSize) {
      const first = this._map.keys().next().value
      if (first !== undefined) this._map.delete(first)
    }
    this._map.set(key, { value, expiresAt: Date.now() + this._ttl })
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
