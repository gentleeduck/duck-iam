import type { AuthEvents } from './types/events'

/**
 * In-memory event bus. Single-process; production swaps in Redis pub/sub
 * (`AuthRedisEvents`) or Kafka (`KafkaEvents`). Handlers run sequentially per
 * event; a throwing handler is caught + logged so siblings still fire.
 */
export class AuthInMemoryEvents implements AuthEvents.IBus {
  private _handlers = new Map<AuthEvents.EventName, Set<(p: unknown) => void | Promise<void>>>()

  on<K extends AuthEvents.EventName>(event: K, handler: AuthEvents.Handler<K>): AuthEvents.Unsubscribe {
    let set = this._handlers.get(event)
    if (!set) {
      set = new Set()
      this._handlers.set(event, set)
    }
    const wrapped = handler as (p: unknown) => void | Promise<void>
    set.add(wrapped)
    return () => set?.delete(wrapped)
  }

  async emit<K extends AuthEvents.EventName>(event: K, payload: AuthEvents.EventMap[K]): Promise<void> {
    const set = this._handlers.get(event)
    if (!set || set.size === 0) return
    // Snapshot the listener set so a handler that subscribes / unsubscribes
    // mid-emit cannot reorder this dispatch or loop forever (each handler
    // sees the listener set as it was at emit time).
    const snapshot = [...set]
    for (const handler of snapshot) {
      try {
        await handler(payload)
      } catch (err) {
        console.error(`[@gentleduck/auth] events listener for "${event}" threw:`, err)
      }
    }
  }

  /**
   * Introspection helper. Returns the number of handlers attached to an
   * event. Used by `AuthEngine.strict()` to assert that operators have
   * wired the required event listeners (e.g. `lockout`) without reaching
   * into private state.
   */
  listenerCount<K extends AuthEvents.EventName>(event: K): number {
    return this._handlers.get(event)?.size ?? 0
  }
}
