import type { Events } from './types/events'

/**
 * In-memory event bus. Single-process; production swaps in Redis pub/sub
 * (`RedisEvents`) or Kafka (`KafkaEvents`). Handlers run sequentially per
 * event; a throwing handler is caught + logged so siblings still fire.
 */
export class InMemoryEvents implements Events.IBus {
  private _handlers = new Map<Events.EventName, Set<(p: unknown) => void | Promise<void>>>()

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

  async emit<K extends Events.EventName>(event: K, payload: Events.EventMap[K]): Promise<void> {
    const set = this._handlers.get(event)
    if (!set || set.size === 0) return
    for (const handler of set) {
      try {
        await handler(payload)
      } catch (err) {
        // Buggy listener must never escape into the caller's fail-closed path.
        // eslint-disable-next-line no-console
        console.error(`[@gentleduck/auth] events listener for "${event}" threw:`, err)
      }
    }
  }
}
