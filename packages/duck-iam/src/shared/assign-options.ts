import type { IamAdapter } from '../core/types'

/**
 * The fields of {@link IamAdapter.IAssignOptions} an adapter has to store to honour.
 * NOTE: not `actor`: dropping it changes no decision, and the engine still emits it on the mutation event.
 */
const ASSIGN_OPTION_FIELDS = ['startsAt', 'expiresAt', 'attributes'] as const

/**
 * Adapter-boundary guard for `assignRole`'s `opts` on adapters without the columns (all but Drizzle).
 * SECURITY: refuses rather than drops them, or a grant given an `expiresAt` would be permanent.
 */
export function iamAssertNoAssignOptions(adapter: string, opts?: IamAdapter.IAssignOptions): void {
  if (opts === undefined) return
  const unsupported = ASSIGN_OPTION_FIELDS.filter((field) => opts[field] !== undefined)
  if (unsupported.length === 0) return
  throw new Error(
    `[@gentleduck/iam:${adapter}] assignRole options (${unsupported.join(', ')}) are not supported by this adapter, ` +
      'and were previously discarded silently. Use the drizzle adapter for time-boxed or attributed grants, ' +
      'or revoke the role explicitly when it should end.',
  )
}

/**
 * Adapter-boundary guard for a `[startsAt, expiresAt)` window: refuses an unusable Date or an empty window.
 * NOTE: the shipped schemas CHECK this too, but the table is caller-configurable. Messages name fields, never values.
 */
export function iamAssertValidAssignWindow(adapter: string, opts?: IamAdapter.IAssignOptions): void {
  if (opts === undefined) return
  const startsAt = readInstant(adapter, 'startsAt', opts.startsAt)
  const expiresAt = readInstant(adapter, 'expiresAt', opts.expiresAt)
  if (startsAt === null || expiresAt === null) return
  if (startsAt < expiresAt) return
  throw new Error(
    `[@gentleduck/iam:${adapter}] assignRole was given startsAt >= expiresAt, which is an empty window: ` +
      'the grant would be stored and never be active. Pass an expiresAt after the startsAt, ' +
      'or omit one of them for an open-ended grant.',
  )
}

/**
 * One bound as epoch ms, or `null` when it was not given.
 * Throws on anything but a valid `Date`, such as a JSON date that was never revived.
 */
function readInstant(adapter: string, field: 'startsAt' | 'expiresAt', value: unknown): number | null {
  if (value === undefined || value === null) return null
  const time = value instanceof Date ? value.getTime() : Number.NaN
  if (Number.isFinite(time)) return time
  throw new Error(
    `[@gentleduck/iam:${adapter}] assignRole's ${field} is not a usable Date. ` +
      'Pass a Date carrying a real instant - an Invalid Date, or a value parsed from JSON without reviving it, ' +
      'would be stored as a bound nothing can compare against.',
  )
}
