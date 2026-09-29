import { randomUUID } from 'node:crypto'
import type { RedisLike } from '~/core/drivers/redis-like'
import type { Events } from '~/core/events/events.types'

type Listener = (payload: unknown) => void | Promise<void>

export namespace RedisEvents {
  /** A `RedisLike.Client` with pub/sub in the `@upstash/redis` shape; `valkeyPubSubAdapter` fits ioredis and
   *  iovalkey to it. */
  export type Client = RedisLike.Client & {
    /** Publishes `message` on `channel`; answers how many subscribers got it. */
    publish(channel: string, message: string): Promise<number>
    /** `onMessage` runs for every payload until the returned unsubscribe is invoked. */
    subscribe(
      channel: string,
      onMessage: (channel: string, message: string) => void | Promise<void>,
    ): Promise<() => Promise<void>>
  }

  /** The Redis event bus's options. */
  export type Cfg = {
    /** Pub/sub-capable Redis client. */
    redis: Client
    /** Channel prefix. Final channel is `${prefix}:${eventName}`. Default `auth:events`. */
    prefix?: string
  }
}

/** Publishes each emit to a per-event channel. A `fleet` handler runs on every server, an `origin` one
 *  only on the server that emitted, inside its async context. Local handlers run off the publish, so a
 *  call site does not pay a Redis round trip to observe its own emit. */
export class RedisEvents implements Events.IBus {
  private readonly _redis: RedisEvents.Client
  private readonly _prefix: string
  private readonly _instanceId: string
  private readonly _origin = new Map<Events.EventName, Set<Listener>>()
  private readonly _fleet = new Map<Events.EventName, Set<Listener>>()
  private readonly _subscriptions = new Map<Events.EventName, Promise<(() => Promise<void>) | null>>()

  constructor(cfg: RedisEvents.Cfg) {
    this._redis = cfg.redis
    this._prefix = cfg.prefix ?? 'auth:events'
    // A loopback-dedup id, not a secret; randomUUID keeps it collision-free without tripping the
    // "no Math.random in security paths" guard.
    this._instanceId = randomUUID()
  }

  private _ch(event: Events.EventName): string {
    return `${this._prefix}:${event}`
  }

  /** Registers a local handler. The first `fleet` one for an event subscribes to its channel and removing
   *  the last closes it; an `origin` one never touches the channel. */
  on<K extends Events.EventName>(event: K, handler: Events.Handler<K>, opts?: Events.OnOptions): Events.Unsubscribe {
    const origin = opts?.delivery === 'origin'
    const handlers = origin ? this._origin : this._fleet
    const set = handlers.get(event) ?? new Set<Listener>()
    handlers.set(event, set)
    const wrapped = handler as Listener
    set.add(wrapped)
    if (origin) return () => set.delete(wrapped)

    if (!this._subscriptions.has(event)) {
      // The promise itself, recorded synchronously. The guard above used to read a map written inside
      // the `.then()`, so two `on()` calls for one event in the same tick - handlers registered
      // together at boot, which is the ordinary case - both passed it and both subscribed.
      this._subscriptions.set(event, this._subscribe(event))
    }

    return () => {
      set.delete(wrapped)
      if (set.size > 0) return
      const pending = this._subscriptions.get(event)
      if (!pending) return
      // The teardown stays in the map while it runs, and resubscribes if a handler arrived meanwhile: an
      // adapter unsubscribes a channel, not a callback, so it would cancel an `on()` made in the same tick.
      this._subscriptions.set(
        event,
        pending.then(async (unsubscribe) => {
          // Through the promise, so unsubscribing before the subscribe resolves still closes it.
          try {
            await unsubscribe?.()
          } catch (err) {
            // Closed all the same, since `onMessage` stops once unsubscribe is invoked. Rethrown, it rejected
            // this entry with nothing awaiting it, and the event stayed deaf here for good.
            console.error(`[@gentleduck/auth] RedisEvents could not unsubscribe from "${event}":`, err)
          }
          if (set.size > 0) return this._subscribe(event)
          this._subscriptions.delete(event)
          return null
        }),
      )
    }
  }

  /** Opens the channel for `event`, answering the unsubscribe the teardown above awaits. */
  private _subscribe(event: Events.EventName): Promise<(() => Promise<void>) | null> {
    return this._redis
      .subscribe(this._ch(event), async (_channel, message) => {
        const envelope = parseEnvelope(message)
        if (envelope === null) return
        if (envelope.from === this._instanceId) return
        await this._dispatchLocal(event, envelope.payload, this._fleet.get(event))
      })
      .catch(() => {
        // The subscriber failed to register; in-process events still work. Dropped from the map
        // so the next `on()` for this event tries again rather than assuming one is live.
        this._subscriptions.delete(event)
        return null
      })
  }

  /** Publishes the event, whether or not this server holds a `fleet` handler, and runs this server's
   *  `origin` and `fleet` handlers. */
  async emit<K extends Events.EventName>(event: K, payload: Events.EventMap[K]): Promise<void> {
    const envelope = JSON.stringify({ from: this._instanceId, payload })
    await Promise.all([
      // Reported, not thrown: local handlers have already run and a caller cannot retry a fan-out it
      // does not own. Swallowed outright, a fleet whose pub/sub was down looked exactly like one whose
      // events had simply not fired, while every other failure in this file is retried or logged.
      this._redis.publish(this._ch(event), envelope).catch((err) => {
        console.error(`[@gentleduck/auth] RedisEvents could not publish "${event}" to the fleet:`, err)
        return 0
      }),
      this._dispatchLocal(event, payload, this._origin.get(event), this._fleet.get(event)),
    ])
  }

  private async _dispatchLocal(
    event: Events.EventName,
    payload: unknown,
    ...sets: Array<Set<Listener> | undefined>
  ): Promise<void> {
    // Snapshotted, as `InMemoryEvents.emit` does and for its reason: a `for...of` over a live Set
    // visits entries added after the cursor, so a handler that called `on()` for this same event ran
    // inside the emit that triggered it - and one that re-subscribed itself never terminated. The two
    // implementations of this bus disagreed about what an emit is.
    for (const handler of sets.flatMap((set) => [...(set ?? [])])) {
      try {
        await handler(payload)
      } catch (err) {
        console.error(`[@gentleduck/auth] RedisEvents listener for "${event}" threw:`, err)
      }
    }
  }

  /** Used by Engine.strict()'s boot-time gates. Counts both deliveries. */
  listenerCount<K extends Events.EventName>(event: K): number {
    return (this._origin.get(event)?.size ?? 0) + (this._fleet.get(event)?.size ?? 0)
  }
}

/** Every field the event types declare as a `Date`. A JSON round trip leaves each one a string, so
 *  without this a remote subscriber gets a payload that satisfies no part of its own type. */
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

/** Caller-owned blobs. The library's own metadata stores times as epoch numbers, so there is nothing
 *  to revive and walking in would rewrite someone else's data on a key-name collision. */
const OPAQUE_KEYS: ReadonlySet<string> = new Set(['metadata', 'profile'])

/**
 * Turn the ISO strings a JSON round trip leaves behind back into `Date`s. A local handler is handed
 * the original object, so the divergence shows only across the fan-out: `expiresAt < Date.now()`
 * compares a string with a number and answers `false`, which is an impersonation window that never
 * looks expired anywhere but the instance that opened it.
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
      // A key that should hold a date but does not parse is left as it
      // arrived: the payload is already wrong, and an `Invalid Date` reads as a
      // real Date to every caller while comparing false against everything.
      out[key] = Number.isFinite(parsed.getTime()) ? parsed : child
    } else {
      out[key] = reviveDates(child)
    }
  }
  return out
}

/** `null` on any shape mismatch. */
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

/** Redis pub/sub event bus, for delivery across a fleet. */
export function redisEvents(...args: ConstructorParameters<typeof RedisEvents>): RedisEvents {
  return new RedisEvents(...args)
}
