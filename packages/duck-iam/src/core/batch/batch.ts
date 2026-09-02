import type { Batch } from './batch.types'

/** Build a `Batch.Result` from per-row outcomes, deriving the counts. */
export function batchResult<TRow, T>(outcomes: Batch.Outcome<TRow, T>[]): Batch.Result<TRow, T> {
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
export async function loopFallback<TRow, T>(
  rows: readonly TRow[],
  run: (row: TRow) => Promise<T>,
): Promise<Batch.Result<TRow, T>> {
  const outcomes: Batch.Outcome<TRow, T>[] = []
  for (const row of rows) outcomes.push({ ok: true, row, value: await run(row) })
  return batchResult(outcomes)
}

/**
 * Credit each written row to the first requested row that accounts for it.
 *
 * A batch can name the same write twice - the identical triple listed twice,
 * or an unscoped revoke alongside a scoped one it already covers. The write
 * happens once, so crediting both rows would report two changes where the
 * database made one. Requested rows are walked in order and each claims one
 * write not already claimed, so no write is ever credited twice and the answer
 * does not depend on which order the driver returned its rows in.
 *
 * A row claims one write, not every write it matches: a wildcard revoke that
 * removed three rows is still one request that changed something, and claiming
 * all three would starve two later rows that each genuinely accounted for one.
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
 * Per-row outcomes for an idempotent batch write, in input order.
 *
 * Every row is `ok` - both role writes are idempotent, so the postcondition
 * ("the subject does / does not hold this role here") is true whether or not
 * this statement is what made it true. Reporting an already-granted row as a
 * miss would contradict the single-row method, which treats it as success.
 *
 * `changed` carries the finer answer when the adapter supplied one: pass the
 * indices of the rows the statement moved, or `null` when the driver could not
 * say, in which case `changed` is left off entirely rather than guessed.
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
