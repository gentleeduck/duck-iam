import type { Batch } from './batch.types'

/** Builds a `Batch.Result`; `applied` is the row count, since every outcome is `ok` (failures throw). */
export function batchResult<TRow, T>(outcomes: Batch.Outcome<TRow, T>[]): Batch.Result<TRow, T> {
  return { applied: outcomes.length, outcomes }
}

/**
 * Runs a single-row write once per row, serially, for adapters with no set-based form.
 * A throw rejects the whole batch so the caller's transaction aborts; there is no per-row failure.
 */
export async function loopFallback<TRow, T>(
  rows: readonly TRow[],
  run: (row: TRow) => Promise<T>,
): Promise<Batch.Result<TRow, T>> {
  const outcomes: Batch.Outcome<TRow, T>[] = []
  for (const row of rows) outcomes.push({ ok: true, row, value: await run(row) })
  return batchResult(outcomes)
}

/**
 * Walks `requested` in order; each row claims the first unclaimed write it accounts for.
 * A row claims at most one write and a write at most one row, so duplicates never report extra changes.
 *
 * @returns Indices into `requested` of the rows that claimed a write.
 */
export function creditWrites<TRow, TWrite>(
  requested: readonly TRow[],
  written: readonly TWrite[],
  accountsFor: (row: TRow, write: TWrite) => boolean,
): number[] {
  const claimed = new Array<boolean>(written.length).fill(false)
  const credited: number[] = []
  requested.forEach((row, i) => {
    const hit = written.findIndex((write, w) => !claimed[w] && accountsFor(row, write))
    if (hit === -1) return
    claimed[hit] = true
    credited.push(i)
  })
  return credited
}

/**
 * Per-row outcomes for an idempotent batch write, in input order; every row is `ok`.
 * `moved` holds the indices the statement wrote, or `null` to leave `changed` off rather than guess.
 */
export function appliedRows<TRow>(
  requested: readonly TRow[],
  moved: readonly number[] | null,
): Batch.Result<TRow, Batch.Change> {
  const credited = moved === null ? null : new Set(moved)
  return batchResult(
    requested.map((row, i) => ({
      ok: true as const,
      row,
      value: credited === null ? {} : { changed: credited.has(i) },
    })),
  )
}
