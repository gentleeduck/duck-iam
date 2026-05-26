/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { Events } from '../../core/types/events'
import type { RedisLike } from './redis-like'

/**
 * Redis-like client extended with pub/sub. Both `ioredis` and
 * `@upstash/redis` ship the methods - we declare them as optional so
 * tests + apps that only use the K/V surface can still satisfy the
 * `RedisLike` contract.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface RedisPubSubClient extends RedisLike {
  publish(channel: string, message: string): Promise<number>
  /**
   * Subscribe to a channel. Implementations call `onMessage` for every
   * payload received until the returned unsubscribe is invoked.
   */
  subscribe(
    channel: string,
    onMessage: (channel: string, message: string) => void | Promise<void>,
  ): Promise<() => Promise<void>>
}

/**
 * Config knobs for `RedisEvents`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface RedisEventsConfig {
  /** Pub/sub-capable Redis client. */
  redis: RedisPubSubClient
  /** Channel prefix. Final channel is `${prefix}:${eventName}`. Default `auth:events`. */
  prefix?: string
}

/**
 * Redis pub/sub-backed event bus. Each emit publishes the JSON-encoded
 * payload to the per-event channel; every connected `on()` subscriber
 * across the fleet receives the message.
 *
 * Local handler invocation: when an emit originates from the same
 * process, the local handlers fire synchronously off the publish call
 * so call sites do not need a round-trip latency through Redis just to
 * observe their own emit. Remote-only deployments can disable this with
 * `localPassThrough:false`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class RedisEvents implements Events.IBus {
  private readonly _redis: RedisPubSubClient
  private readonly _prefix: string
  private readonly _instanceId: string
  private readonly _localHandlers = new Map<Events.EventName, Set<(payload: unknown) => void | Promise<void>>>()
  private readonly _subscriptions = new Map<Events.EventName, () => Promise<void>>()

  constructor(cfg: RedisEventsConfig) {
    this._redis = cfg.redis
    this._prefix = cfg.prefix ?? 'auth:events'
    // Random per-instance tag so subscribers can skip self-emitted
    // messages and avoid double-dispatch on the same process.
    this._instanceId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
  }

  /** Compose the per-event channel name. */
  private _ch(event: Events.EventName): string {
    return `${this._prefix}:${event}`
  }

  /**
   * Register a handler. On the first subscriber for an event, registers
   * a single Redis SUBSCRIBE so multiple in-process listeners share one
   * underlying connection. Returns an unsubscribe.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  on<K extends Events.EventName>(event: K, handler: Events.Handler<K>): Events.Unsubscribe {
    let set = this._localHandlers.get(event)
    if (!set) {
      set = new Set()
      this._localHandlers.set(event, set)
    }
    const wrapped = handler as (payload: unknown) => void | Promise<void>
    set.add(wrapped)

    // Spawn the Redis subscriber lazily on the first listener for this event.
    if (!this._subscriptions.has(event)) {
      // Fire-and-forget the subscribe registration; if it fails, the
      // local handler still works for in-process emits.
      void this._redis
        .subscribe(this._ch(event), async (_channel, message) => {
          const envelope = JSON.parse(message) as { from: string; payload: unknown }
          // Skip messages this instance emitted - emit() already
          // dispatched them locally to avoid the Redis round-trip.
          if (envelope.from === this._instanceId) return
          await this._dispatchLocal(event, envelope.payload)
        })
        .then((unsubscribe) => {
          this._subscriptions.set(event, unsubscribe)
        })
        .catch(() => {
          // Subscriber failed to register; in-process events still work.
        })
    }

    return () => {
      set?.delete(wrapped)
      if (set && set.size === 0) {
        const unsubscribe = this._subscriptions.get(event)
        if (unsubscribe) {
          void unsubscribe()
          this._subscriptions.delete(event)
        }
      }
    }
  }

  /**
   * Publish the event to Redis and dispatch to local handlers in
   * parallel. The local dispatch is best-effort: a throwing handler is
   * caught + logged so siblings still fire.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async emit<K extends Events.EventName>(event: K, payload: Events.EventMap[K]): Promise<void> {
    const envelope = JSON.stringify({ from: this._instanceId, payload })
    await Promise.all([
      this._redis.publish(this._ch(event), envelope).catch(() => 0),
      this._dispatchLocal(event, payload as unknown),
    ])
  }

  /**
   * Local synchronous dispatch path. Used by both `emit()` (self-fire)
   * and the subscription callback (remote-fire).
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  private async _dispatchLocal<K extends Events.EventName>(event: K, payload: unknown): Promise<void> {
    const set = this._localHandlers.get(event)
    if (!set || set.size === 0) return
    for (const handler of set) {
      try {
        await handler(payload)
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`[@gentleduck/auth] RedisEvents listener for "${event}" threw:`, err)
      }
    }
  }

  /**
   * Diagnostic helper. Returns the number of handlers attached to an
   * event - used by AuthRoot.strict() to assert required listeners.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  listenerCount<K extends Events.EventName>(event: K): number {
    return this._localHandlers.get(event)?.size ?? 0
  }
}

/**
 * Namespace merge for `RedisEvents`. Co-locates the config + client
 * contract alongside the class.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace RedisEvents {
  /** Alias for `RedisEventsConfig`. */
  export type IConfig = RedisEventsConfig
  /** Alias for `RedisPubSubClient`. */
  export type IClient = RedisPubSubClient
}
