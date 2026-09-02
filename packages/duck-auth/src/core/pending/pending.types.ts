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
     * A throwing listener does not stop the drain - every buffered event is
     * attempted, and the call rejects with an `AggregateError` at the end if
     * any threw. The buffer is empty either way, so a partial failure never
     * leaves events to be published twice.
     */
    flush(): Promise<void>
    /** Drop everything buffered without publishing. For an explicit rollback path. */
    discard(): void
    /** Inspect the buffer without draining it. For tests and custom routing. */
    peek(): readonly Event[]
  }
}
