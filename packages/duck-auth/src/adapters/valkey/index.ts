import type { RedisLike } from '../redis/redis-like'

/**
 * The subset of `ioredis` this adapter needs. Valkey speaks the same protocol and
 * `iovalkey` is an `ioredis` fork, so one adapter serves both.
 *
 * Declared structurally rather than importing `ioredis`, which would make it a
 * dependency of this package for the sake of a type.
 */
export namespace ValkeyClient {
  export type Me = {
    get(key: string): Promise<string | null>
    del(...keys: string[]): Promise<number>
    expire(key: string, seconds: number): Promise<number>
    incr(key: string): Promise<number>
    sadd(key: string, ...members: string[]): Promise<number>
    srem(key: string, ...members: string[]): Promise<number>
    smembers(key: string): Promise<string[]>

    /**
     * `set`, `scan` and `eval` are declared loosely on purpose. ioredis gives each of
     * them a long overload list ending in an optional callback, and an overloaded
     * function is assignable to no single variadic signature: pinning one here makes
     * a real ioredis client fail to type-check against its own adapter.
     *
     * The bodies below are what constrain these, and they are covered by tests.
     */
    set(key: string, value: string, ...args: any[]): Promise<any>
    scan(cursor: string | number, ...args: any[]): Promise<any>
    eval(script: string, numKeys: number, ...args: any[]): Promise<any>
  }
}

/**
 * Adapts an ioredis or iovalkey client to {@link RedisLike.Client}.
 *
 * This exists because the two disagree about one method. `RedisLike.set` takes
 * options as an object, which is `@upstash/redis`'s shape; ioredis takes them
 * variadically as `set(key, value, 'EX', 60, 'NX')`. Passing an ioredis client
 * straight through therefore silently drops every TTL and every NX guard: the write
 * succeeds, the key never expires, and the conditional write is not conditional.
 *
 * Nothing throws when that happens, which is why this is a named adapter rather than
 * a note in a docblock telling callers the clients are already compatible.
 */
export function valkeyAdapter(client: ValkeyClient.Me): RedisLike.Client {
  return {
    get: (key) => client.get(key),

    set: async (key, value, opts) => {
      const args: (string | number)[] = []
      if (opts?.ex !== undefined) args.push('EX', opts.ex)
      if (opts?.nx) args.push('NX')
      return client.set(key, value, ...args)
    },

    del: (...keys) => client.del(...keys),
    expire: (key, seconds) => client.expire(key, seconds),

    scan: async (cursor, opts) => {
      const args: (string | number)[] = []
      if (opts?.match) args.push('MATCH', opts.match)
      if (opts?.count) args.push('COUNT', opts.count)
      return client.scan(cursor, ...args)
    },

    incr: (key) => client.incr(key),
    sadd: (key, ...members) => client.sadd(key, ...members),
    srem: (key, ...members) => client.srem(key, ...members),
    smembers: (key) => client.smembers(key),

    // ioredis takes the key count positionally, then keys, then args.
    eval: (script, opts) => client.eval(script, opts.keys.length, ...opts.keys, ...opts.args),
  }
}
