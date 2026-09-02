/**
 * Per-row results for the batch forms of the facets' single-row writes.
 *
 * Two failure classes, deliberately handled differently:
 *
 * - A **hard** failure - constraint violation, driver error, lost connection -
 *   throws. Inside a caller's transaction that aborts the whole transaction,
 *   which is what makes a batch atomic with the caller's work.
 * - A **soft** failure - optimistic-lock miss, row not found - is reported as
 *   `ok: false` and does NOT throw, so a bulk profile update can say which rows
 *   lost the version race instead of dying on the first one.
 */
export namespace Batch {
  export type FailureReason = 'not-found' | 'stale-write' | 'skipped'

  export type Outcome<T = void> =
    | { id: string; ok: true; value: T }
    | { id: string; ok: false; reason: FailureReason; detail?: string }

  export type Result<T = void> = {
    /** One entry per input row, in input order. */
    outcomes: Outcome<T>[]
    applied: number
    failed: number
  }
}
