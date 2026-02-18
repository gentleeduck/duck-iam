export class LRUCache<V> {
  private map = new Map<string, { value: V; expiresAt: number }>()
  private maxSize: number
  private ttl: number

  constructor(maxSize: number, ttlMs: number) {
    this.maxSize = maxSize
    this.ttl = ttlMs
  }

  get(key: string): V | undefined {
    const entry = this.map.get(key)
    if (!entry) return undefined
    if (Date.now() > entry.expiresAt) {
      this.map.delete(key)
      return undefined
    }
    // Move to end (most recently used)
    this.map.delete(key)
    this.map.set(key, entry)
    return entry.value
  }

  set(key: string, value: V): void {
    this.map.delete(key)
    if (this.map.size >= this.maxSize) {
      // Evict oldest
      const first = this.map.keys().next().value
      if (first !== undefined) this.map.delete(first)
    }
    this.map.set(key, { value, expiresAt: Date.now() + this.ttl })
  }

  clear(): void {
    this.map.clear()
  }

  get size(): number {
    return this.map.size
  }
}
