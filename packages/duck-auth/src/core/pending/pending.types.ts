import type { Events } from '../events/events.types'

/**
 * Side effects a facet would have published immediately, held until the
 * caller's transaction commits. Produced by `createPending` and exposed as
 * `Bound.AuthEngine.pending`.
 *
 * Events are announcements: they tell the rest of the system that something
 * happened. Inside a transaction nothing has happened yet, so publishing at
 * emit time can announce a write that a later rollback erases - an audit trail
 * that records a deletion which never occurred, or a webhook that fires for a
 * signup the database does not have.
 */
export namespace Pending {
  /** One buffered emit, holding the event name and the payload as it stood at emit time. */
  export type Event = {
    [K in Events.EventName]: { name: K; payload: Events.EventMap[K] }
  }[Events.EventName]

  export interface Effects {
    /** Number of buffered events awaiting publication. */
    readonly size: number
    /**
     * Publish everything buffered, in emit order, then empty the buffer.
     * Idempotent: a second call publishes nothing.
     *
     * **Never rejects.** A throwing listener does not stop the drain - every
     * buffered event is attempted and any errors come back in `failed`.
     *
     * This is deliberate. `flush` runs AFTER the caller's transaction has
     * committed, and it empties the buffer whether or not a listener threw, so
     * there is nothing left to retry. Throwing here would hand a committed
     * write back to the caller as a failure - a 500 whose one promise, that the
     * write did not happen, would be false. The write happened; some
     * announcement of it did not. Those are different facts and the caller
     * needs to be able to tell them apart, log the second, and still answer
     * 200.
     *
     * Callers who want the old behaviour can `if (failed.length) throw new
     * AggregateError(failed)` - the reverse was not available.
     */
    flush(): Promise<{ published: number; failed: Error[] }>
    /** Drop everything buffered without publishing. For an explicit rollback path. */
    discard(): { discarded: number }
    /** Inspect the buffer without draining it. For tests and custom routing. */
    peek(): readonly Event[]
  }
}
