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
  /**
   * Why one row of a batch did not apply.
   *
   * `not-found` means exactly that - no such row. It is NOT the catch-all for
   * "did not apply": a row that was found and then refused by a rule gets the
   * reason for that rule, so a caller can tell "this id is gone" from "this id
   * is here and you may not have it" without a second read.
   */
  export type FailureReason = 'not-found' | 'stale-write' | 'skipped' | 'grace-expired' | 'email-taken'

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
