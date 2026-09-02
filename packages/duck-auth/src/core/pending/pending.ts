import type { Events } from '../events/events.types'
import type { Pending } from './pending.types'

/**
 * An `Events.IBus` that records `emit` calls instead of publishing them, and
 * forwards `on` to the real bus so listener registration is unaffected.
 *
 * Sits INSIDE the engine's `withAuditStamping` wrapper, so a buffered payload
 * carries the audit envelope that was ambient at emit time. Stamping at flush
 * time would attribute an impersonated action to whatever envelope happened to
 * be live after the commit - which is nobody's, since the request that made the
 * write has usually finished by then.
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

  discard(): void {
    this._buffer = []
  }

  async flush(): Promise<void> {
    // Take the buffer before awaiting: a listener that emits during flush must
    // not append to the batch currently draining, or flush could never finish.
    const draining = this._buffer
    this._buffer = []
    const errors: unknown[] = []
    for (const entry of draining) {
      try {
        await this._target.emit(entry.name, entry.payload)
      } catch (err) {
        errors.push(err)
      }
    }
    if (errors.length > 0) {
      throw new AggregateError(errors, `pending.flush: ${errors.length} of ${draining.length} listeners threw`)
    }
  }
}

/**
 * Build a buffering bus over `target` plus the {@link Pending.Effects} handle
 * that drains it. Facets receive `bus`; the caller receives `pending`.
 */
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
