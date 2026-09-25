import type { Events } from './events.types'

/** Single-process: production swaps in `RedisEvents`. Handlers run sequentially per
 *  event, and a throwing one is caught and logged so its siblings still fire. */
export class InMemoryEvents implements Events.IBus {
  /** Read by `strict()`. `withAuditStamping` wraps the bus in a fresh object literal, so the engine's
   *  `events` carries no brand and the check reads `cfg.events`, which is what the operator passed. */
  readonly __isInProcessBus = true as const
  private _handlers = new Map<Events.EventName, Set<(p: unknown) => void | Promise<void>>>()

  /** Registers a handler and answers the function that unsubscribes it. */
  on<K extends Events.EventName>(event: K, handler: Events.Handler<K>): Events.Unsubscribe {
    let set = this._handlers.get(event)
    if (!set) {
      set = new Set()
      this._handlers.set(event, set)
    }
    const wrapped = handler as (p: unknown) => void | Promise<void>
    set.add(wrapped)
    return () => set?.delete(wrapped)
  }

  /** Dispatches to the handlers registered when the emit began; a throwing one cannot stop the rest. */
  async emit<K extends Events.EventName>(event: K, payload: Events.EventMap[K]): Promise<void> {
    const set = this._handlers.get(event)
    if (!set || set.size === 0) return
    // Snapshotted, so a handler subscribing or unsubscribing mid-emit cannot reorder this dispatch or
    // loop for ever: every handler sees the set as it stood at emit time.
    const snapshot = [...set]
    for (const handler of snapshot) {
      try {
        await handler(payload)
      } catch (err) {
        console.error(`[@gentleduck/auth] events listener for "${event}" threw:`, err)
      }
    }
  }

  /** Lets `AuthEngine.strict()` assert the required listeners are wired, `lockout` among them, without
   *  reaching into private state. */
  listenerCount<K extends Events.EventName>(event: K): number {
    return this._handlers.get(event)?.size ?? 0
  }
}

/** In-process event bus. No cross-node delivery, so a fleet needs the Redis bus instead. */
export function inMemoryEvents(...args: ConstructorParameters<typeof InMemoryEvents>): InMemoryEvents {
  return new InMemoryEvents(...args)
}
