/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

/**
 * Minimal Redis interface the auth adapters consume. Both `ioredis` and
 * `@upstash/redis` already implement this surface, so consumers wire
 * their existing client without an extra peerDep cost.
 *
 * Methods follow Redis semantics:
 *   - `get` returns the value (string) or null
 *   - `set` with `EX ttlSec` writes with TTL; `NX` makes it conditional
 *   - `del` returns 1 when a key was removed, 0 otherwise
 *   - `expire` (re)sets TTL on an existing key
 *   - `scan` matches keys by pattern (cursor-based)
 *
 * Production runs use ioredis or @upstash/redis; tests use the in-tree
 * `FakeRedis` implementation that satisfies the same shape.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface RedisLike {
  /** GET key -> value | null */
  get(key: string): Promise<string | null>
  /** SET key value [EX seconds] [NX] -> 'OK' | null (null = NX failed) */
  set(key: string, value: string, opts?: { ex?: number; nx?: boolean }): Promise<'OK' | null>
  /** DEL key... -> count */
  del(...keys: string[]): Promise<number>
  /** EXPIRE key seconds -> 1 | 0 */
  expire(key: string, seconds: number): Promise<number>
  /** SCAN cursor MATCH pattern COUNT n -> [nextCursor, keys] */
  scan(cursor: string, opts?: { match?: string; count?: number }): Promise<[string, string[]]>
  /** INCR key -> new value (creates key=1 if missing) */
  incr(key: string): Promise<number>
  /** SADD key member... -> added count */
  sadd(key: string, ...members: string[]): Promise<number>
  /** SREM key member... -> removed count */
  srem(key: string, ...members: string[]): Promise<number>
  /** SMEMBERS key -> array of members (empty when key missing) */
  smembers(key: string): Promise<string[]>
  /** EVAL script numKeys keys... args... -> result */
  eval?(script: string, opts: { keys: string[]; args: string[] }): Promise<unknown>
}

/**
 * In-process Redis substitute. Used by tests and by apps that need the
 * adapter shape without a real Redis dependency at runtime. Same surface
 * as ioredis / upstash; TTLs honored via setTimeout cleanup on read.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class FakeRedis implements RedisLike {
  private readonly _data = new Map<string, { value: string; expiresAt: number | null }>()
  private readonly _sets = new Map<string, Set<string>>()

  private _maybeExpire(key: string): void {
    const entry = this._data.get(key)
    if (entry && entry.expiresAt !== null && entry.expiresAt < Date.now()) {
      this._data.delete(key)
    }
  }

  /**
   * `RedisLike.get` substitute. Returns null on miss or after TTL elapsed.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async get(key: string): Promise<string | null> {
    this._maybeExpire(key)
    return this._data.get(key)?.value ?? null
  }

  /**
   * `RedisLike.set` with optional `EX` (TTL seconds) + `NX` (only-if-absent).
   * Returns 'OK' on success, null when NX condition fails.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async set(key: string, value: string, opts: { ex?: number; nx?: boolean } = {}): Promise<'OK' | null> {
    this._maybeExpire(key)
    if (opts.nx && this._data.has(key)) return null
    this._data.set(key, {
      value,
      expiresAt: opts.ex !== undefined ? Date.now() + opts.ex * 1000 : null,
    })
    return 'OK'
  }

  /**
   * `RedisLike.del` variadic. Returns count of keys actually removed.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async del(...keys: string[]): Promise<number> {
    let deleted = 0
    for (const k of keys) {
      if (this._data.delete(k)) deleted++
    }
    return deleted
  }

  /**
   * `RedisLike.expire` (re)sets TTL on a live key. Returns 1 on success,
   * 0 when the key does not exist.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async expire(key: string, seconds: number): Promise<number> {
    this._maybeExpire(key)
    const entry = this._data.get(key)
    if (!entry) return 0
    entry.expiresAt = Date.now() + seconds * 1000
    return 1
  }

  /**
   * `RedisLike.scan` cursor pagination. Match patterns honor `*` wildcard.
   * Walks both string keys and set keys (real Redis SCAN is type-agnostic).
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async scan(cursor: string, opts: { match?: string; count?: number } = {}): Promise<[string, string[]]> {
    const all = [...new Set<string>([...this._data.keys(), ...this._sets.keys()])]
    const start = Number(cursor) || 0
    const count = opts.count ?? 100
    const matched: string[] = []
    let i = start
    for (; i < all.length && matched.length < count; i++) {
      const key = all[i]
      if (!key) continue
      this._maybeExpire(key)
      const liveString = this._data.has(key)
      const liveSet = this._sets.has(key)
      if (!liveString && !liveSet) continue
      if (opts.match && !matchGlob(key, opts.match)) continue
      matched.push(key)
    }
    const nextCursor = i >= all.length ? '0' : String(i)
    return [nextCursor, matched]
  }

  /**
   * `RedisLike.incr` atomic increment. Creates the key at 1 when missing.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async incr(key: string): Promise<number> {
    this._maybeExpire(key)
    const entry = this._data.get(key)
    const cur = entry ? Number(entry.value) : 0
    const next = (Number.isFinite(cur) ? cur : 0) + 1
    this._data.set(key, {
      value: String(next),
      expiresAt: entry?.expiresAt ?? null,
    })
    return next
  }

  /**
   * `RedisLike.sadd` variadic. Returns count of new members.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async sadd(key: string, ...members: string[]): Promise<number> {
    let set = this._sets.get(key)
    if (!set) {
      set = new Set()
      this._sets.set(key, set)
    }
    let added = 0
    for (const m of members) {
      if (!set.has(m)) {
        set.add(m)
        added++
      }
    }
    return added
  }

  /**
   * `RedisLike.srem` variadic. Returns count of removed members.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async srem(key: string, ...members: string[]): Promise<number> {
    const set = this._sets.get(key)
    if (!set) return 0
    let removed = 0
    for (const m of members) {
      if (set.delete(m)) removed++
    }
    if (set.size === 0) this._sets.delete(key)
    return removed
  }

  /**
   * `RedisLike.smembers`. Returns empty array when key missing.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async smembers(key: string): Promise<string[]> {
    return [...(this._sets.get(key) ?? [])]
  }
}

/** Trivial glob-to-regex for Redis MATCH semantics. */
function matchGlob(input: string, pattern: string): boolean {
  const re = new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`)
  return re.test(input)
}

/**
 * Namespace merge for the RedisLike contract. Co-locates the adapter
 * contract + fake under one symbol so consumers import either shape with
 * a single line.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace RedisLike {
  /** Alias for the `RedisLike` interface (preserves the dual export). */
  export type IClient = RedisLike
}
