import type { Events } from './events.types'

/** Single-process: `origin` and `fleet` handlers both run on this server. Handlers run sequentially per
 *  event, and a throwing one is caught and logged so its siblings still fire. */
export class InMemoryEvents implements Events.IBus {
  /** Read by `strict()`. `withAuditStamping` wraps the bus in a fresh object literal, so the engine's
   *  `events` carries no brand and the check reads `cfg.events`, which is what the operator passed. */
  readonly __isInProcessBus = true as const
  private readonly _origin = new Map<Events.EventName, Set<(p: unknown) => void | Promise<void>>>()
  private readonly _fleet = new Map<Events.EventName, Set<(p: unknown) => void | Promise<void>>>()

  /** Registers a handler and answers the function that unsubscribes it. */
  on<K extends Events.EventName>(event: K, handler: Events.Handler<K>, opts?: Events.OnOptions): Events.Unsubscribe {
    const handlers = opts?.delivery === 'origin' ? this._origin : this._fleet
    const set = handlers.get(event) ?? new Set()
    handlers.set(event, set)
    const wrapped = handler as (p: unknown) => void | Promise<void>
    set.add(wrapped)
    return () => set.delete(wrapped)
  }

  /** Dispatches to the handlers registered when the emit began; a throwing one cannot stop the rest. */
  async emit<K extends Events.EventName>(event: K, payload: Events.EventMap[K]): Promise<void> {
    // Snapshotted, so a handler subscribing or unsubscribing mid-emit cannot reorder this dispatch or
    // loop for ever: every handler sees the set as it stood at emit time.
    const snapshot = [...(this._origin.get(event) ?? []), ...(this._fleet.get(event) ?? [])]
    for (const handler of snapshot) {
      try {
        await handler(payload)
      } catch (err) {
        console.error(`[@gentleduck/auth] events listener for "${event}" threw:`, err)
      }
    }
  }

  /** Lets `AuthEngine.strict()` assert the required listeners are wired, `lockout` among them, without
   *  reaching into private state. Counts both deliveries. */
  listenerCount<K extends Events.EventName>(event: K): number {
    return (this._origin.get(event)?.size ?? 0) + (this._fleet.get(event)?.size ?? 0)
  }

  /** The events holding a `fleet` handler, which `strict()` refuses on this bus in production. */
  fleetEvents(): Events.EventName[] {
    return [...this._fleet].filter(([, set]) => set.size > 0).map(([event]) => event)
  }
}

/** In-process event bus. A `fleet` handler here hears only this server, so more than one server needs `redisEvents`. */
export function inMemoryEvents(...args: ConstructorParameters<typeof InMemoryEvents>): InMemoryEvents {
  return new InMemoryEvents(...args)
}
