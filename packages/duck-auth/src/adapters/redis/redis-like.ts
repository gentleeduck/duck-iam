export namespace AuthRedisLike {
  /**
   * Minimal Redis interface the auth adapters consume. Both `ioredis`
   * and `@upstash/redis` already implement this surface; consumers
   * wire their existing client without an extra peerDep cost.
   *
   * Methods follow Redis semantics:
   *   - `get` returns the value (string) or null
   *   - `set` with `EX ttlSec` writes with TTL; `NX` makes it conditional
   *   - `del` returns 1 when a key was removed, 0 otherwise
   *   - `expire` (re)sets TTL on an existing key
   *   - `scan` matches keys by pattern (cursor-based)
   */
  export interface IClient {
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
}

/**
 * In-process Redis substitute. Used by tests and by apps that need the
 * adapter shape without a real Redis dependency at runtime. Same surface
 * as ioredis / upstash; TTLs honored via setTimeout cleanup on read.
 */
export class FakeRedis implements AuthRedisLike.IClient {
  private readonly _data = new Map<string, { value: string; expiresAt: number | null }>()
  private readonly _sets = new Map<string, Set<string>>()
  private readonly _channels = new Map<string, Set<(channel: string, message: string) => void | Promise<void>>>()

  private _maybeExpire(key: string): void {
    const entry = this._data.get(key)
    if (entry && entry.expiresAt !== null && entry.expiresAt < Date.now()) {
      this._data.delete(key)
    }
  }

  /** `AuthRedisLike.get` substitute. Returns null on miss or after TTL elapsed. */
  async get(key: string): Promise<string | null> {
    this._maybeExpire(key)
    return this._data.get(key)?.value ?? null
  }

  /**
   * `AuthRedisLike.set` with optional `EX` (TTL seconds) + `NX` (only-if-absent).
   * Returns 'OK' on success, null when NX condition fails.
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

  /** `AuthRedisLike.del` variadic. Returns count of keys actually removed. */
  async del(...keys: string[]): Promise<number> {
    let deleted = 0
    for (const k of keys) {
      if (this._data.delete(k)) deleted++
    }
    return deleted
  }

  /**
   * `AuthRedisLike.expire` (re)sets TTL on a live key. Returns 1 on success,
   * 0 when the key does not exist.
   */
  async expire(key: string, seconds: number): Promise<number> {
    this._maybeExpire(key)
    const entry = this._data.get(key)
    if (!entry) return 0
    entry.expiresAt = Date.now() + seconds * 1000
    return 1
  }

  /**
   * `AuthRedisLike.scan` cursor pagination. Match patterns honor `*` wildcard.
   * Walks both string keys and set keys (real Redis SCAN is type-agnostic).
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

  /** `AuthRedisLike.incr` atomic increment. Creates the key at 1 when missing. */
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

  /** `AuthRedisLike.sadd` variadic. Returns count of new members. */
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

  /** `AuthRedisLike.srem` variadic. Returns count of removed members. */
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

  /** `AuthRedisLike.smembers`. Returns empty array when key missing. */
  async smembers(key: string): Promise<string[]> {
    return [...(this._sets.get(key) ?? [])]
  }

  /**
   * Pub/sub stub matching `RedisPubSubClient.publish`. Fans out the
   * payload to every subscriber on `channel`. Returns the number of
   * subscribers that received it.
   */
  async publish(channel: string, message: string): Promise<number> {
    const set = this._channels.get(channel)
    if (!set) return 0
    for (const handler of set) {
      void handler(channel, message)
    }
    return set.size
  }

  /**
   * Pub/sub stub matching `RedisPubSubClient.subscribe`. Registers the
   * handler against `channel`; returns an async unsubscribe.
   */
  async subscribe(
    channel: string,
    onMessage: (channel: string, message: string) => void | Promise<void>,
  ): Promise<() => Promise<void>> {
    let set = this._channels.get(channel)
    if (!set) {
      set = new Set()
      this._channels.set(channel, set)
    }
    set.add(onMessage)
    return async () => {
      set?.delete(onMessage)
      if (set && set.size === 0) this._channels.delete(channel)
    }
  }
}

/**
 * linear-time glob matcher for Redis MATCH semantics (only `*`
 * supported; the legacy regex-construction approach was vulnerable to
 *
 *  (1) ReDoS - multiple `*`s in a pattern compile to multiple `.*`
 *      segments. A pattern like `a*a*a*a*a*X` matched against
 *      `aaaaaaaaaaY` (no terminal `X`) drives JS's backtracking
 *      regex engine into super-linear time. Defense in depth even
 *      though MATCH patterns are normally operator-controlled.
 *
 *  (2) Crashes - the escape only covered `[.+^${}()|[]\\]`, leaving
 *      `?` unescaped. A pattern containing `?` (e.g. `?$`) compiled
 *      to an INVALID regex and threw SyntaxError on `new RegExp(...)`,
 *      crashing the scan() loop.
 *
 * Both go away with a textbook two-pointer iterative matcher: O(n*m)
 * worst case (vs. exponential for the regex), and unknown characters
 * in the pattern are treated as literals (no parser to crash). Length
 * caps add a final ceiling.
 */
const MATCH_GLOB_INPUT_MAX = 4096
const MATCH_GLOB_PATTERN_MAX = 256
function matchGlob(input: string, pattern: string): boolean {
  if (input.length > MATCH_GLOB_INPUT_MAX) return false
  if (pattern.length > MATCH_GLOB_PATTERN_MAX) return false
  let i = 0
  let p = 0
  let starIdx = -1
  let matchIdx = 0
  while (i < input.length) {
    if (p < pattern.length && pattern[p] === '*') {
      starIdx = p
      matchIdx = i
      p++
    } else if (p < pattern.length && pattern[p] === input[i]) {
      i++
      p++
    } else if (starIdx !== -1) {
      p = starIdx + 1
      matchIdx++
      i = matchIdx
    } else {
      return false
    }
  }
  while (p < pattern.length && pattern[p] === '*') p++
  return p === pattern.length
}
