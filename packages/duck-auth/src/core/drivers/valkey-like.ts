import type { RedisLike } from './redis-like'

/**
 * The subset of `ioredis` this adapter needs. Valkey speaks the same protocol and
 * `iovalkey` is an `ioredis` fork, so one adapter serves both.
 */
export namespace ValkeyClient {
  export type Me = {
    /** The string at this key, or `null` when it is unset. */
    get(key: string): Promise<string | null>
    /** One entry per key, in the order asked, `null` where unset. */
    mget(...keys: string[]): Promise<(string | null)[]>
    /** Removes keys, answering how many existed. */
    del(...keys: string[]): Promise<number>
    /** Sets the key's TTL, in seconds. */
    expire(key: string, seconds: number): Promise<number>
    /** Adds one, treating a missing key as zero. */
    incr(key: string): Promise<number>
    /** Adds `by`, treating a missing key as zero. */
    incrby(key: string, by: number): Promise<number>
    /** Adds members to a set, answering how many were not already there. */
    sadd(key: string, ...members: string[]): Promise<number>
    /** Removes members from a set, answering how many were there. */
    srem(key: string, ...members: string[]): Promise<number>
    /** Every member of a set. */
    smembers(key: string): Promise<string[]>
    /** Runs a Lua script. Optional so a hand-rolled client is not forced to declare one it never runs;
     *  ioredis and iovalkey both have it, and the adapter forwards it when it is there. */
    eval?(script: string, numkeys: number, ...args: (string | number)[]): Promise<any>
    /** Removes members from a sorted set, answering how many were there. */
    zrem(key: string, ...members: string[]): Promise<number>

    /**
     * `set`/`zadd`/`zrangebyscore` are declared loosely on purpose:
     * ioredis's long overload lists aren't assignable to any single variadic
     * signature, so pinning one here would make a real ioredis client fail to
     * type-check against its own adapter.
     */
    set(key: string, value: string, ...args: any[]): Promise<any>
    zadd(key: string, ...args: any[]): Promise<any>
    zrangebyscore(key: string, min: number | string, max: number | string, ...args: any[]): Promise<any>
  }
}

/**
 * Adapts an ioredis or iovalkey client to {@link RedisLike.Client}. `RedisLike.set`
 * takes options as an object; ioredis takes them variadically (`set(key, value, 'EX',
 * 60, 'NX')`), so passing an ioredis client straight through silently drops every TTL
 * and NX guard rather than throwing.
 */
export function valkeyAdapter(client: ValkeyClient.Me): RedisLike.Client {
  return {
    get: (key) => client.get(key),
    mget: (...keys) => client.mget(...keys),

    set: async (key, value, opts) => {
      const args: (string | number)[] = []
      if (opts?.ex !== undefined) args.push('EX', opts.ex)
      if (opts?.nx) args.push('NX')
      return client.set(key, value, ...args)
    },

    // ioredis counts its keys positionally where `RedisLike` takes them as an array. Spread in rather
    // than declared, so a client without `eval` is reported as not having one instead of failing on the
    // first script.
    ...(client.eval && {
      eval: (script: string, keys: string[], args: (string | number)[]) =>
        // biome-ignore lint/style/noNonNullAssertion: guarded by the spread condition one line above.
        client.eval!(script, keys.length, ...keys, ...args),
    }),

    del: (...keys) => client.del(...keys),
    expire: (key, seconds) => client.expire(key, seconds),

    incr: (key) => client.incr(key),
    incrby: (key, by) => client.incrby(key, by),
    sadd: (key, ...members) => client.sadd(key, ...members),
    srem: (key, ...members) => client.srem(key, ...members),
    smembers: (key) => client.smembers(key),

    zadd: async (key, score, member) => Number(await client.zadd(key, score, member)),
    zrem: (key, ...members) => client.zrem(key, ...members),

    zrangebyscore: async (key, min, max, opts) => {
      // ioredis takes LIMIT variadically, and only accepts it at all when both
      // offset and count are present.
      const args: (string | number)[] = []
      if (opts?.limit) args.push('LIMIT', opts.limit.offset, opts.limit.count)
      return client.zrangebyscore(key, min, max, ...args)
    },
  }
}

/**
 * The dedicated-connection surface a pub/sub adapter needs for the subscribe side.
 * Once an ioredis/iovalkey connection calls `.subscribe()`, that connection is in
 * subscriber mode and cannot run ordinary commands (including `PUBLISH`) until it
 * unsubscribes, so this is always a second, separate client from the command one.
 */
export namespace ValkeySubscriberClient {
  export type Me = {
    subscribe(...channels: string[]): Promise<unknown>
    unsubscribe(...channels: string[]): Promise<unknown>
    on(event: 'message', listener: (channel: string, message: string) => void): unknown
    off(event: 'message', listener: (channel: string, message: string) => void): unknown
  }
}
