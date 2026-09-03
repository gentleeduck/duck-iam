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
 * Turn "rows I asked for" plus "rows the statement actually touched" into
 * per-row outcomes in input order. A row the statement did not touch is
 * `not-found`.
 */
export function outcomesFromAffected<Row>(
  requested: readonly Row[],
  affected: readonly Row[],
  key: (row: Row) => string,
): Batch.Result {
  const hit = new Set(affected.map(key))
  return batchResult(
    requested.map((row) => {
      const id = key(row)
      return hit.has(id)
        ? { id, ok: true as const, value: undefined }
        : { id, ok: false as const, reason: 'not-found' as const }
    }),
  )
}
