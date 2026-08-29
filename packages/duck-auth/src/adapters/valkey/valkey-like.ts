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
     * `set`/`scan`/`eval` are declared loosely on purpose: ioredis's long overload
     * lists aren't assignable to any single variadic signature, so pinning one here
     * would make a real ioredis client fail to type-check against its own adapter.
     */
    set(key: string, value: string, ...args: any[]): Promise<any>
    scan(cursor: string | number, ...args: any[]): Promise<any>
    eval(script: string, numKeys: number, ...args: any[]): Promise<any>
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
