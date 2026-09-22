/**
 * Per-row results for admin batch writes. Failures throw, aborting the caller's transaction; there is no soft arm.
 * NOTE: mirrors duck-auth's `core/batch` without sharing it, since the two packages do not depend on each other.
 */
export namespace Batch {
  /**
   * One row's result, carrying the row itself; outcomes are in input order.
   * NOTE: the row, not a key: no string encoding of a free-form `(subject, role, scope)` triple is unambiguous.
   */
  export type Outcome<TRow, T = void> = { row: TRow; ok: true; value: T }

  /**
   * `changed` is `true` when this row accounts for a write, `false` when already applied or credited to an earlier row.
   * Absent when the driver cannot say (MySQL has no `RETURNING`; the per-row fallback returns `void`).
   */
  export type Change = {
    readonly changed?: boolean
  }

  export type Result<TRow, T = void> = {
    /** One entry per input row, in input order. */
    outcomes: Outcome<TRow, T>[]
    /** Always `outcomes.length`; kept because callers read it as the row count. */
    applied: number
  }
}
