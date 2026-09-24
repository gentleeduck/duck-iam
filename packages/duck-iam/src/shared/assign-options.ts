import type { IamAdapter } from '../core/types'
import { throwIamError } from '../core/errors'

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
  throwIamError('IAM_ASSIGN_OPTIONS_UNSUPPORTED', { adapter, fields: unsupported })
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
  throwIamError('IAM_ASSIGN_WINDOW_EMPTY', { adapter })
}

/**
 * One bound as epoch ms, or `null` when it was not given.
 * Throws on anything but a valid `Date`, such as a JSON date that was never revived.
 */
function readInstant(adapter: string, field: 'startsAt' | 'expiresAt', value: unknown): number | null {
  if (value === undefined || value === null) return null
  const time = value instanceof Date ? value.getTime() : Number.NaN
  if (Number.isFinite(time)) return time
  throwIamError('IAM_ASSIGN_WINDOW_INVALID_DATE', { adapter, field })
}
