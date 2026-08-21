/**
 * ioredis -> `RedisLike.Client` bridge for the e2e suites.
 *
 * The library only ever consumes `RedisLike`, so every e2e suite needs the same
 * adapter. It lived inline in the sessions suite; sharing it keeps the command
 * translation (notably `SET ... EX ... NX`) defined in exactly one place.
 */
import type Redis from 'ioredis'
import type { RedisLike } from '~/adapters/redis/redis-like'

export function toRedisLike(r: Redis): RedisLike.Client {
  return {
    del: (...keys) => r.del(...keys),
    expire: (k, s) => r.expire(k, s),
    get: (k) => r.get(k),
    incr: (k) => r.incr(k),
    sadd: (k, ...m) => r.sadd(k, ...m),
    scan: async (cursor, opts) => {
      const args: (string | number)[] = [cursor]
      if (opts?.match) args.push('MATCH', opts.match)
      if (opts?.count) args.push('COUNT', opts.count)
      const [next, keys] = (await r.scan(...(args as [string]))) as [string, string[]]
      return [next, keys]
    },
    set: async (k, v, opts) => {
      if (opts?.ex !== undefined && opts?.nx) {
        return (await r.set(k, v, 'EX', opts.ex, 'NX')) as string | null
      }
      if (opts?.ex !== undefined) return (await r.set(k, v, 'EX', opts.ex)) as string | null
      if (opts?.nx) return (await r.set(k, v, 'NX')) as string | null
      return (await r.set(k, v)) as string | null
    },
    smembers: (k) => r.smembers(k),
    srem: (k, ...m) => r.srem(k, ...m),
  } as RedisLike.Client
}
