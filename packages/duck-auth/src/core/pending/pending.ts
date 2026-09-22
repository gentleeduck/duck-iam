import type { Events } from '../events/events.types'
import type { Pending } from './pending.types'

/**
 * An `Events.IBus` that records `emit` calls instead of publishing them, forwarding `on` to the real bus so
 * listener registration is unaffected.
 */
class BufferingBus implements Events.IBus {
  private _buffer: Pending.Event[] = []

  constructor(private readonly _target: Events.IBus) {}

  on<K extends Events.EventName>(event: K, handler: Events.Handler<K>): Events.Unsubscribe {
    return this._target.on(event, handler)
  }

  async emit<K extends Events.EventName>(event: K, payload: Events.EventMap[K]): Promise<void> {
    this._buffer.push({ name: event, payload } as Pending.Event)
  }

  get size(): number {
    return this._buffer.length
  }

  peek(): readonly Pending.Event[] {
    return this._buffer
  }

  /** Drop the buffer, answering with how many events went undelivered. */
  discard(): { discarded: number } {
    const discarded = this._buffer.length
    this._buffer = []
    return { discarded }
  }

  async flush(): Promise<{ published: number; failed: Error[] }> {
    // Taken before awaiting: a listener emitting during flush must not append to the batch draining, or
    // flush could never finish.
    const draining = this._buffer
    this._buffer = []
    const failed: Error[] = []
    for (const entry of draining) {
      try {
        await this._target.emit(entry.name, entry.payload)
      } catch (err) {
        // A thrown non-Error still arrives as one, since the field is what callers log; the original is
        // kept on `cause`.
        failed.push(err instanceof Error ? err : new Error(String(err), { cause: err }))
      }
    }
    // Reported, never thrown: the commit landed and the buffer is gone, so nothing a rejection could ask
    // the caller to retry. `published` counts what was announced, so a second `flush()` after a commit is
    // distinguishable from the first, which is the one that drained.
    return { failed, published: draining.length - failed.length }
  }
}

/** Facets receive `bus`; the caller receives `pending`, the {@link Pending.Effects} handle that drains it. */
export function createPending(target: Events.IBus): {
  bus: Events.IBus
  pending: Pending.Effects
} {
  const buffering = new BufferingBus(target)
  return {
    bus: buffering,
    pending: {
      get size() {
        return buffering.size
      },
      flush: () => buffering.flush(),
      discard: () => buffering.discard(),
      peek: () => buffering.peek(),
    },
  }
}
