import type { Events } from '../events/events.types'

/** Side effects a facet would have published at once, held until the caller's transaction commits. An
 *  event announces that something happened, and inside a transaction nothing has, so publishing at emit
 *  time announces writes a rollback then erases. Produced by `createPending`, exposed as
 *  `AuthEngine.pending`. */
export namespace Pending {
  /** One buffered emit, holding the event name and the payload as it stood at emit time. */
  export type Event = {
    [K in Events.EventName]: { name: K; payload: Events.EventMap[K] }
  }[Events.EventName]

  export interface Effects {
    /** Number of buffered events awaiting publication. */
    readonly size: number
    /**
     * Publishes in emit order, then empties the buffer. Idempotent, and it never rejects: a throwing listener
     * does not stop the drain, and its error comes back in `failed`.
     *
     * WARN: deliberately so. This runs after the transaction committed and empties the buffer either way, so
     * throwing would hand a committed write back as a 500 whose one promise, that the write did not happen, is
     * false. The write happened and an announcement of it did not; a caller wanting those treated alike can
     * `if (failed.length) throw new AggregateError(failed)`, which is not available in reverse.
     */
    flush(): Promise<{ published: number; failed: Error[] }>
    /** Drop everything buffered without publishing. For an explicit rollback path. */
    discard(): { discarded: number }
    /** Inspect the buffer without draining it. For tests and custom routing. */
    peek(): readonly Event[]
  }
}
