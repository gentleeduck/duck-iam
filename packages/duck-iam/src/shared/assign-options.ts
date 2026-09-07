import type { IamAdapter } from '../core/types'

/**
 * The fields of {@link IamAdapter.IAssignOptions} an adapter has to store to honour.
 *
 * `actor` is deliberately NOT in this list, and the difference is not an
 * oversight. Dropping `expiresAt` changes what the store will *answer*: the
 * grant outlives the bound the caller asked for, so the write has to fail.
 * Dropping `actor` changes nothing about any future authorization decision -
 * the engine emits it on the `role.assigned` / `role.revoked` mutation event
 * whether or not a column exists, so the audit trail the caller wanted is
 * intact. Five of the six adapters have no provenance column at all; refusing
 * their writes would make `actor` unusable everywhere except drizzle for no
 * safety gain.
 */
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

/**
 * Adapter-boundary guard for the one adapter that *can* store a window.
 *
 * `[startsAt, expiresAt)` is half-open, so `startsAt >= expiresAt` describes an
 * empty interval: no instant is ever inside it and the grant is dead the moment
 * it is written - while the write resolves and the batch API reports
 * `ok: true, applied: 1`. That is the same silent-success shape
 * {@link iamAssertNoAssignOptions} exists to stop, arriving by a different
 * route. An `Invalid Date` is the same again: it reaches the driver as garbage
 * instead of reaching the caller as a refusal.
 *
 * The shipped pg, mysql and sqlite schemas all carry
 * `ch_iam_assignments_starts_before_expires`, but this adapter is table-config
 * driven - a caller can point it at a table of their own - so the database
 * check is a second line, not the only one.
 *
 * The message names the fields and never their values: an authorization error
 * that echoes its input is a log-injection surface, and the caller already
 * holds what it passed.
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
 * One bound as milliseconds, or `null` when it was not given.
 *
 * Refuses anything that is not a usable `Date`. The declared type says `Date`,
 * so this only fires for a caller who got past the compiler - a JSON body
 * deserialised without reviving its dates, most often - and for them a refusal
 * is the whole point: a bound the store cannot read is a bound it cannot keep.
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
