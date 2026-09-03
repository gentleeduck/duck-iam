/**
 * Adapter-boundary guard for the role argument of `assignRole`.
 *
 * The drizzle schemas carry `fk_iam_assignments_role`, so granting a role that
 * does not exist is a database error there and a silently accepted no-op on the
 * other five adapters: the row lands, `getSubjectRoles` returns the id, and
 * `resolveSubject` drops it again because no role definition resolves. An
 * operator who typed `edtior` for `editor` got "granted" back and a subject who
 * could do nothing, with no record anywhere saying why - and the same call
 * threw on pg. One of those two answers has to be the contract, and it is the
 * one that refuses: an IAM library exists to be exact about who holds what, and
 * a grant naming nothing is not a grant.
 *
 * The FK also does work no application check can: it stops `deleteRole` from
 * leaving orphan grants behind, which a later role recreated under the same id
 * would otherwise resurrect.
 *
 * Adapters that own their role storage call this after a local existence check.
 * The HTTP adapter cannot - the operator's server is the authority on which
 * roles exist - so it delegates, exactly as it does for the read contract.
 *
 * The message does not quote the role id. Every other adapter-boundary guard
 * in this package reports the shape of the offending argument and never its
 * value, because these strings reach operator logs and error responses, and the
 * id is caller-controlled.
 *
 * @param adapter - Adapter name for the error message, e.g. `'memory'`.
 * @param exists  - Whether the adapter found a role definition under that id.
 * @throws When no role is stored under the requested id.
 */
export function iamAssertRoleExists(adapter: string, exists: boolean): void {
  if (exists) return
  throw iamUnknownRoleError(adapter)
}

/**
 * The error {@link iamAssertRoleExists} throws, for the adapters that learn of
 * the missing role from a driver rather than from their own lookup.
 *
 * @param adapter - Adapter name for the error message, e.g. `'drizzle'`.
 * @param cause - The driver error being translated, when there is one.
 * @returns The refusal, worded identically on every adapter.
 */
export function iamUnknownRoleError(adapter: string, cause?: unknown): Error {
  const message = `[@gentleduck/iam:${adapter}] cannot assign a role that is not stored; save the role before granting it`
  return cause === undefined ? new Error(message) : new Error(message, { cause })
}

/**
 * Recognises the driver error a missing role produces on a schema that carries
 * `fk_iam_assignments_role`.
 *
 * The SQL adapters cannot check first and stay correct - a role deleted between
 * the check and the insert would slip through - so they let the database
 * decide and translate what comes back. Drizzle wraps the driver error in
 * `Failed query: <sql>`, and the constraint that actually rejected the write is
 * only on `.cause`, so an operator reading `err.message` learns nothing about
 * why the grant failed. This walks the cause chain instead of reading the
 * outermost message alone.
 *
 * All three name the constraint in the message - Postgres "violates foreign key
 * constraint", MySQL "a foreign key constraint fails", SQLite "FOREIGN KEY
 * constraint failed" - so the text is the portable signal. Postgres's SQLSTATE
 * is checked as well because `lc_messages` can translate that text; MySQL's
 * `errno` and SQLite's `code` are not, because matching them would add two more
 * lists for cases the text already covers.
 *
 * @param err - The error the driver threw.
 * @returns Whether it is a foreign-key violation.
 */
export function iamIsForeignKeyViolation(err: unknown): boolean {
  let cursor: unknown = err
  for (let depth = 0; depth < 8 && cursor !== null && cursor !== undefined; depth++) {
    if (typeof cursor !== 'object') return false
    if (Reflect.get(cursor, 'code') === PG_FOREIGN_KEY_VIOLATION) return true
    const message = Reflect.get(cursor, 'message')
    if (typeof message === 'string' && /foreign key constraint/i.test(message)) return true
    cursor = Reflect.get(cursor, 'cause')
  }
  return false
}

/** Postgres SQLSTATE for `foreign_key_violation`. */
const PG_FOREIGN_KEY_VIOLATION = '23503'
