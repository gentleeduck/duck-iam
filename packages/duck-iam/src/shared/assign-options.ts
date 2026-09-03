import type { IamAdapter } from '../core/types'

/** The fields of {@link IamAdapter.IAssignOptions} an adapter has to store to honour. */
const ASSIGN_OPTION_FIELDS = ['startsAt', 'expiresAt', 'attributes'] as const

/**
 * Adapter-boundary guard for `assignRole`'s `opts`. Only Drizzle has the columns
 * for temporal bounds and per-grant attributes; the other five used to take the
 * argument and drop it on the floor, so a break-glass grant issued with
 * `expiresAt` was **permanent** and `engine.admin.assignRoles` still reported
 * `ok: true, applied: 1`.
 *
 * Refusing is the fix rather than a no-op: the caller asked for a bound the
 * store cannot keep, and the failure has to be visible at the write. An adapter
 * that gains the columns drops the call.
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
