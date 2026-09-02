/**
 * Per-row results for the batch forms of the admin's single-row writes.
 *
 * A **hard** failure - a constraint violation or driver error - throws, which
 * inside a caller's transaction aborts the whole transaction and is what makes
 * a batch atomic with the caller's work. A **soft** failure - a row that did
 * not match - is reported as `ok: false` without throwing.
 *
 * Deliberately duplicated from duck-auth's `core/batch` rather than shared:
 * the two packages do not depend on each other, and a shared shape is not worth
 * inventing a dependency edge for.
 */
export namespace Batch {
  export type FailureReason = 'not-found' | 'skipped'

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
