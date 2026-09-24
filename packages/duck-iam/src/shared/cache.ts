import type { IamEngine } from '../core'
/**
 * LRU cache with TTL expiry, ordered by `Map` insertion. Used by {@link IamEngine} for policies, roles and subjects.
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
   * @param maxSize - Max entries before the least recently used one is evicted.
   * @param ttlMs - Time-to-live per entry, in milliseconds.
   * @throws `RangeError` when either is non-finite, `maxSize < 1`, or `ttlMs < 0`.
   */
  constructor(maxSize: number, ttlMs: number) {
    if (!Number.isFinite(maxSize) || maxSize < 1)
      throw new RangeError('IamLRUCache maxSize must be a finite number >= 1')
    if (!Number.isFinite(ttlMs) || ttlMs < 0) throw new RangeError('IamLRUCache ttlMs must be a finite number >= 0')
    this._maxSize = maxSize
    this._ttl = ttlMs
  }

  /** Returns the value and marks it most recently used; `undefined` when missing or expired. */
  get(key: string): V | undefined {
    const entry = this._map.get(key)
    if (!entry) {
      this._misses++
      return undefined
    }
    // NOTE: `>=`, not `>`: `expiresAt` is exclusive, as it is for grants, so a `notAfter` cap holds to the millisecond.
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

  /**
   * The value under `key`, or `undefined` when absent or lapsed. Moves neither LRU order nor stats.
   * NOTE: for internal reads a request did not ask for; `get` would record a hit or miss that skews `cacheHitRate`.
   */
  peek(key: string): V | undefined {
    const entry = this._map.get(key)
    if (!entry) return undefined
    return Date.now() >= entry.expiresAt ? undefined : entry.value
  }

  /**
   * Epoch ms the entry under `key` expires at, or `undefined` when absent or lapsed. Moves neither LRU order nor stats.
   * NOTE: lets a derived cache inherit its source's expiry via {@link IamLRUCache.set}'s `notAfter` instead of a fresh full TTL.
   */
  expiresAt(key: string): number | undefined {
    const entry = this._map.get(key)
    if (!entry) return undefined
    return Date.now() >= entry.expiresAt ? undefined : entry.expiresAt
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
   * Stores `value` with a fresh TTL, evicting the least recently used entry at capacity.
   *
   * @param key - Cache key.
   * @param value - Value to store.
   * @param notAfter - Epoch ms the value stops being true; caps the TTL, and a past instant stores nothing.
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

  /** Removes one entry; `true` when it existed. */
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

  /** Iterates non-expired entries without refreshing LRU order; expiry uses `>=` to agree with {@link IamLRUCache.get}. */
  *entries(): IterableIterator<[string, V]> {
    const now = Date.now()
    for (const [key, entry] of this._map) {
      if (now >= entry.expiresAt) continue
      yield [key, entry.value]
    }
  }
}

/** Factory around {@link IamLRUCache}, for callers who prefer functions to `new`. */
export function iamLRUCache<V>(...args: ConstructorParameters<typeof IamLRUCache<V>>): IamLRUCache<V> {
  return new IamLRUCache<V>(...args)
}
