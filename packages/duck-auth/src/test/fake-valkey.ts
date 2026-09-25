import { FakeRedis } from '~/core/drivers/redis-like'
import type { ValkeyClient, ValkeySubscriberClient } from '~/core/drivers/valkey-like'

/** An ioredis/iovalkey-shaped client over {@link FakeRedis}, so the valkey stores run in-process. */
export class FakeValkey implements ValkeyClient.Me {
  readonly redis: FakeRedis

  constructor(redis: FakeRedis = new FakeRedis()) {
    this.redis = redis
  }

  get(key: string): Promise<string | null> {
    return this.redis.get(key)
  }

  mget(...keys: string[]): Promise<(string | null)[]> {
    return this.redis.mget(...keys)
  }

  del(...keys: string[]): Promise<number> {
    return this.redis.del(...keys)
  }

  expire(key: string, seconds: number): Promise<number> {
    return this.redis.expire(key, seconds)
  }

  incr(key: string): Promise<number> {
    return this.redis.incr(key)
  }

  incrby(key: string, by: number): Promise<number> {
    return this.redis.incrby(key, by)
  }

  sadd(key: string, ...members: string[]): Promise<number> {
    return this.redis.sadd(key, ...members)
  }

  srem(key: string, ...members: string[]): Promise<number> {
    return this.redis.srem(key, ...members)
  }

  smembers(key: string): Promise<string[]> {
    return this.redis.smembers(key)
  }

  zrem(key: string, ...members: string[]): Promise<number> {
    return this.redis.zrem(key, ...members)
  }

  publish(channel: string, message: string): Promise<number> {
    return this.redis.publish(channel, message)
  }

  /** `SET key value [EX seconds] [NX]`, positional as ioredis takes it. */
  set(key: string, value: string, ...args: unknown[]): Promise<'OK' | null> {
    const tokens = args.map(String)
    const ex = tokens.findIndex((t) => t.toUpperCase() === 'EX')
    return this.redis.set(key, value, {
      ...(ex >= 0 ? { ex: Number(tokens[ex + 1]) } : {}),
      nx: tokens.some((t) => t.toUpperCase() === 'NX'),
    })
  }

  /** `ZADD key score member`. */
  zadd(key: string, ...args: unknown[]): Promise<number> {
    return this.redis.zadd(key, Number(args[0]), String(args[1]))
  }

  /** `ZRANGEBYSCORE key min max [LIMIT offset count]`, which ioredis accepts only with both. */
  zrangebyscore(key: string, min: number | string, max: number | string, ...args: unknown[]): Promise<string[]> {
    const tokens = args.map(String)
    const limit = tokens.findIndex((t) => t.toUpperCase() === 'LIMIT')
    return this.redis.zrangebyscore(key, min, max, {
      ...(limit >= 0 ? { limit: { offset: Number(tokens[limit + 1]), count: Number(tokens[limit + 2]) } } : {}),
    })
  }

  // No `eval`: it is optional on `ValkeyClient.Me`, this fake runs no Lua, and declaring one it cannot
  // honour makes the adapter forward it and the store take a path nothing here can serve. Absent, the
  // store takes its documented fallback, as it does with `FakeRedis`, and the script itself is
  // exercised against a real server by the e2e suite.
}

/**
 * The dedicated subscriber connection, which ioredis delivers through one shared `'message'`
 * event rather than a per-call callback. Channels it never subscribed to deliver nothing, so a
 * filter dropped in the adapter shows up as a handler that never fires.
 */
export class FakeValkeySubscriber implements ValkeySubscriberClient.Me {
  private readonly _listeners = new Set<(channel: string, message: string) => void>()
  private readonly _subscribed = new Set<string>()

  constructor(private readonly _redis: FakeRedis) {}

  async subscribe(...channels: string[]): Promise<number> {
    for (const channel of channels) {
      if (this._subscribed.has(channel)) continue
      this._subscribed.add(channel)
      await this._redis.subscribe(channel, (ch, message) => {
        for (const listener of this._listeners) listener(ch, message)
      })
    }
    return this._subscribed.size
  }

  async unsubscribe(...channels: string[]): Promise<number> {
    for (const channel of channels) this._subscribed.delete(channel)
    return this._subscribed.size
  }

  on(_event: 'message', listener: (channel: string, message: string) => void): this {
    this._listeners.add(listener)
    return this
  }

  off(_event: 'message', listener: (channel: string, message: string) => void): this {
    this._listeners.delete(listener)
    return this
  }
}
