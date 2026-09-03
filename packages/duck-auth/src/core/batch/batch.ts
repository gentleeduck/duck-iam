import { AuthError } from '../errors'
import type { Batch } from './batch.types'

/**
 * Returned by a batch runner for a row that had nothing to act on.
 *
 * "No such row" is an ordinary per-row outcome, not an exception, so signalling
 * it by return keeps it out of the thrown-error path entirely - the alternative
 * would be throwing an authentication error to mean "absent", which reads wrong
 * at the throw site and wrong again in any log that catches it.
 */
export const BATCH_NOT_FOUND: unique symbol = Symbol('batch.not-found')

/** Builds a `Batch.Result` from per-row outcomes, deriving the counts. */
export function batchResult<T>(outcomes: Batch.Outcome<T>[]): Batch.Result<T> {
  let applied = 0
  for (const o of outcomes) if (o.ok) applied++
  return { applied, failed: outcomes.length - applied, outcomes }
}

/**
 * Runs a single-row operation once per id and collects outcomes. Used by every
 * facet batch method when the underlying store offers no set-based form, so the
 * memory and redis adapters keep working with no adapter change.
 *
 * A runner reports an absent row by returning {@link BATCH_NOT_FOUND}. Thrown
 * soft failures are caught and reported; anything else rethrows, preserving the
 * hard/soft distinction described on {@link Batch}.
 */
export async function loopFallback<T>(
  ids: readonly string[],
  run: (id: string) => Promise<T | typeof BATCH_NOT_FOUND>,
): Promise<Batch.Result<T>> {
  const outcomes: Batch.Outcome<T>[] = []
  for (const id of ids) {
    try {
      const value = await run(id)
      if (value === BATCH_NOT_FOUND) outcomes.push({ id, ok: false, reason: 'not-found' })
      else outcomes.push({ id, ok: true, value })
    } catch (err) {
      const soft = toSoftReason(err)
      if (!soft) throw err
      outcomes.push({ id, ok: false, reason: soft, ...(err instanceof Error && { detail: err.message }) })
    }
  }
  return batchResult(outcomes)
}

/** Maps a thrown error to a soft outcome reason, or `null` when it is hard. */
export function toSoftReason(err: unknown): Batch.FailureReason | null {
  if (!(err instanceof AuthError)) return null
  if (err.code === 'AUTH_STALE_WRITE') return 'stale-write'
  if (err.code === 'AUTH_UNAUTHENTICATED') return 'not-found'
  return null
}
