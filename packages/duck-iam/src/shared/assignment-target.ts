import { fail, IamError } from '../core/errors'

/**
 * Adapter-boundary guard for `assignRole`: a role with no stored definition throws, as drizzle's FK does.
 * SECURITY: the message never quotes the caller-controlled role id, since it reaches logs and error responses.
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
 * The error {@link iamAssertRoleExists} throws, for adapters that learn of the missing role from a driver error.
 *
 * @param adapter - Adapter name for the error message, e.g. `'drizzle'`.
 * @param cause - The driver error being translated, when there is one.
 */
export function iamUnknownRoleError(adapter: string, cause?: unknown): IamError {
  const err = fail('IAM_ROLE_NOT_FOUND', { adapter })
  if (cause !== undefined) err.cause = cause
  return err
}

/**
 * True when a driver error, or anything in its `cause` chain (where drizzle puts it), is a foreign-key violation.
 * INFO: Postgres, MySQL and SQLite all say "foreign key constraint"; SQLSTATE 23503 covers translated Postgres text.
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
