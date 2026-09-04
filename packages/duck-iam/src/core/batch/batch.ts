import type { Batch } from './batch.types'

/**
 * Stable outcome id for one `(subject, role, scope)` triple. The space is a
 * separator the three parts cannot contain silently: subject and role ids are
 * validated non-empty, and a scope with a space in it still yields a distinct
 * key, because the parts are joined in a fixed order.
 */
export function tripleKey(subjectId: string, roleId: string, scope?: string): string {
  return `${subjectId} ${roleId} ${scope ?? ''}`
}

/** Build a `Batch.Result` from per-row outcomes, deriving the counts. */
export function batchResult<T>(outcomes: Batch.Outcome<T>[]): Batch.Result<T> {
  let applied = 0
  for (const o of outcomes) if (o.ok) applied++
  return { applied, failed: outcomes.length - applied, outcomes }
}

/**
 * Run a single-row write once per row and collect outcomes. Used whenever the
 * adapter offers no set-based form, so the memory, file, redis and http
 * adapters keep working with no adapter change.
 *
 * Every throw is hard here: iam has no optimistic-lock miss to soften, so an
 * error means the write genuinely failed and the caller's transaction should
 * abort rather than the batch reporting a per-row failure and carrying on.
 */
export async function loopFallback<Row, T>(
  rows: readonly Row[],
  key: (row: Row) => string,
  run: (row: Row) => Promise<T>,
): Promise<Batch.Result<T>> {
  const outcomes: Batch.Outcome<T>[] = []
  for (const row of rows) outcomes.push({ id: key(row), ok: true, value: await run(row) })
  return batchResult(outcomes)
}

/**
 * Per-row outcomes for an idempotent batch write, in input order.
 *
 * Every row is `ok` - both role writes are idempotent, so the postcondition
 * ("the subject does / does not hold this role here") is true whether or not
 * this statement is what made it true. Reporting an already-granted row as a
 * miss would contradict the single-row method, which treats it as success.
 *
 * `changed` carries the finer answer when the adapter supplied one: pass the
 * rows the statement actually moved, or `null` when the driver could not say,
 * in which case `changed` is left off entirely rather than guessed.
 */
export function appliedRows<Row>(
  requested: readonly Row[],
  changed: readonly Row[] | null,
  key: (row: Row) => string,
): Batch.Result<Batch.Change> {
  const moved = changed === null ? null : new Set(changed.map(key))
  return batchResult(
    requested.map((row) => ({
      id: key(row),
      ok: true as const,
      value: moved === null ? {} : { changed: moved.has(key(row)) },
    })),
  )
}
