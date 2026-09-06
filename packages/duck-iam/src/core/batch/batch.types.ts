/**
 * Per-row results for the batch forms of the admin's single-row writes.
 *
 * Every failure here is **hard**: a constraint violation or driver error
 * throws, which inside a caller's transaction aborts the whole transaction and
 * is what makes a batch atomic with the caller's work.
 *
 * There is deliberately no soft-failure channel. Both role writes are
 * idempotent, so a row the statement did not move is still applied - the
 * postcondition holds either way - and reporting it as a miss would contradict
 * the single-row method, which calls the same case success. `Outcome` once
 * carried an `ok: false` arm with a `FailureReason`, and nothing in the package
 * could produce one: both producers hard-coded `ok: true`, so the `failed`
 * counter derived from it was structurally always zero and a consumer writing
 * `if (!outcome.ok)` was writing dead code against a documented contract.
 *
 * Deliberately duplicated from duck-auth's `core/batch` rather than shared:
 * the two packages do not depend on each other, and a shared shape is not worth
 * inventing a dependency edge for. The shapes have since diverged - duck-auth
 * keys an outcome by an identity id, which is a real single-field key there,
 * while a role assignment has no such key. See {@link Batch.Outcome}.
 */
export namespace Batch {
  /**
   * One row's result, carrying the row it describes.
   *
   * The row itself, not an id derived from it: a role assignment is identified
   * by a `(subject, role, scope)` triple of free-form strings, and every
   * encoding of three of those into one key is either ambiguous or unreadable.
   * An earlier version joined them with a space, which collided whenever an id
   * contained one - `('a b', 'c')` and `('a', 'b c')` produced the same key,
   * and nothing rejects a space in a subject id.
   *
   * Holding the row keeps outcomes addressable with no key to get wrong, and
   * hands back exactly what the caller passed in. Outcomes are also in input
   * order, so matching by index stays available and exact.
   */
  export type Outcome<TRow, T = void> = { row: TRow; ok: true; value: T }

  /**
   * What a role-write outcome carries. The write itself is idempotent, so the
   * row is applied either way; `changed` says whether THIS row is what moved
   * it - `true` when it accounts for a write the statement made, `false` when
   * the row was already in the requested state, or when an earlier row of the
   * same batch already accounts for that write.
   *
   * Every write is credited to exactly one row, the first that accounts for
   * it, so two rows asking for the same thing report `true` then `false`
   * rather than both claiming a write that happened once.
   *
   * Absent when the driver could not say, which is not a failure and not a
   * guess: MySQL has no `RETURNING`, and the per-row fallback's single-row
   * methods return `void`. Asking those to answer would cost an extra read per
   * batch, so they say nothing rather than pay for it or invent an answer.
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
