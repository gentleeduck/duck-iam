import { randomUUID } from 'node:crypto'
import type { RedisLike } from '~/core/drivers/redis-like'
import type { Events } from '~/core/events/events.types'

export namespace RedisEvents {
  /**
   * Redis-like client extended with pub/sub. Both `ioredis` and
   * `@upstash/redis` ship the methods - declared optional so tests +
   * apps that only use the K/V surface can still satisfy the
   * `RedisLike.Client` contract.
   */
  export type Client = RedisLike.Client & {
    publish(channel: string, message: string): Promise<number>
    /**
     * Subscribe to a channel. Implementations call `onMessage` for
     * every payload received until the returned unsubscribe is invoked.
     */
    subscribe(
      channel: string,
      onMessage: (channel: string, message: string) => void | Promise<void>,
    ): Promise<() => Promise<void>>
  }

  /** Cfg knobs for {@link RedisEvents}. */
  export type Cfg = {
    /** Pub/sub-capable Redis client. */
    redis: Client
    /** Channel prefix. Final channel is `${prefix}:${eventName}`. Default `auth:events`. */
    prefix?: string
  }
}

/**
 * Redis pub/sub-backed event bus. Each emit publishes the JSON-encoded
 * payload to the per-event channel; every connected `on()` subscriber
 * across the fleet receives the message.
 *
 * Local handler invocation: when an emit originates from the same
 * process, the local handlers fire synchronously off the publish call
 * so call sites do not need a round-trip latency through Redis just to
 * observe their own emit.
 */
export class RedisEvents implements Events.IBus {
  private readonly _redis: RedisEvents.Client
  private readonly _prefix: string
  private readonly _instanceId: string
  private readonly _localHandlers = new Map<Events.EventName, Set<(payload: unknown) => void | Promise<void>>>()
  private readonly _subscriptions = new Map<Events.EventName, () => Promise<void>>()

  constructor(cfg: RedisEvents.Cfg) {
    this._redis = cfg.redis
    this._prefix = cfg.prefix ?? 'auth:events'
    // Non-cryptographic loopback-dedup id; randomUUID keeps it collision-free
    // without tripping the "no Math.random in security paths" guard.
    this._instanceId = randomUUID()
  }

  private _ch(event: Events.EventName): string {
    return `${this._prefix}:${event}`
  }

  on<K extends Events.EventName>(event: K, handler: Events.Handler<K>): Events.Unsubscribe {
    let set = this._localHandlers.get(event)
    if (!set) {
      set = new Set()
      this._localHandlers.set(event, set)
    }
    const wrapped = handler as (payload: unknown) => void | Promise<void>
    set.add(wrapped)

    if (!this._subscriptions.has(event)) {
      void this._redis
        .subscribe(this._ch(event), async (_channel, message) => {
          const envelope = parseEnvelope(message)
          if (envelope === null) return
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

  async emit<K extends Events.EventName>(event: K, payload: Events.EventMap[K]): Promise<void> {
    const envelope = JSON.stringify({ from: this._instanceId, payload })
    await Promise.all([
      this._redis.publish(this._ch(event), envelope).catch(() => 0),
      this._dispatchLocal(event, payload),
    ])
  }

  private async _dispatchLocal<K extends Events.EventName>(event: K, payload: unknown): Promise<void> {
    const set = this._localHandlers.get(event)
    if (!set || set.size === 0) return
    for (const handler of set) {
      try {
        await handler(payload)
      } catch (err) {
        console.error(`[@gentleduck/auth] RedisEvents listener for "${event}" threw:`, err)
      }
    }
  }

  /** Introspection helper. Used by Engine.strict() boot-time gates. */
  listenerCount<K extends Events.EventName>(event: K): number {
    return this._localHandlers.get(event)?.size ?? 0
  }
}

/**
 * Every field the event types declare as a `Date`. `JSON.stringify` writes each
 * one as an ISO string and `JSON.parse` leaves it a string, so without this a
 * remote subscriber gets a payload that satisfies no part of its own type.
 */
const DATE_KEYS: ReadonlySet<string> = new Set([
  'absoluteExpiresAt',
  'addedAt',
  'completedAt',
  'createdAt',
  'deletedAt',
  'expiresAt',
  'invitedAt',
  'joinedAt',
  'lastUsedAt',
  'leftAt',
  'revokedAt',
  'rotatedAt',
  'startedAt',
  'updatedAt',
])

/**
 * Caller-owned blobs. `metadata` and `profile` are `Record<string, unknown>` the
 * host app fills, and the library's own metadata shapes store times as epoch
 * **numbers**, never Dates - so there is nothing here to revive, and walking in
 * would rewrite someone else's data on a key-name collision.
 */
const OPAQUE_KEYS: ReadonlySet<string> = new Set(['metadata', 'profile'])

/**
 * Turn the ISO strings a JSON round-trip leaves behind back into `Date`s.
 *
 * A local handler is handed the original object, so this divergence was
 * invisible in a single process and appeared only across the Redis fan-out that
 * is the whole point of this class: `payload.session.expiresAt.getTime()` threw
 * `is not a function`, and worse, `payload.audit.actingAs.expiresAt < Date.now()`
 * compared a string with a number and answered `false` - an impersonation window
 * that never looked expired on any instance except the one that opened it.
 *
 * Reviving by key rather than by sniffing every string for a date shape keeps a
 * free-text field that happens to hold a timestamp - `actingAs.reason`, say - a
 * string, which is what its type promises.
 */
function reviveDates(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reviveDates)
  if (typeof value !== 'object' || value === null) return value
  const out: Record<string, unknown> = {}
  for (const [key, child] of Object.entries(value)) {
    if (OPAQUE_KEYS.has(key)) {
      out[key] = child
    } else if (DATE_KEYS.has(key) && typeof child === 'string') {
      const parsed = new Date(child)
      // A key we expected to hold a date but which does not parse is left as it
      // arrived: the payload is already wrong, and an `Invalid Date` reads as a
      // real Date to every caller while comparing false against everything.
      out[key] = Number.isFinite(parsed.getTime()) ? parsed : child
    } else {
      out[key] = reviveDates(child)
    }
  }
  return out
}

/** Parse a pub/sub envelope. Returns null on any shape mismatch. */
function parseEnvelope(message: string): { from: string; payload: unknown } | null {
  let raw: unknown
  try {
    raw = JSON.parse(message)
  } catch {
    return null
  }
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return null
  if (!('from' in raw) || typeof raw.from !== 'string') return null
  if (!('payload' in raw)) return null
  return { from: raw.from, payload: reviveDates(raw.payload) }
}

/** Factory around {@link RedisEvents}, for callers who prefer functions to `new`. */
export function redisEvents(...args: ConstructorParameters<typeof RedisEvents>): RedisEvents {
  return new RedisEvents(...args)
}
