import { describe, expect, it } from 'vitest'
import { AuthError } from '../errors'
import { type SqlFault, STORE_RAISES, sqlError } from '../errors.drivers'

/** What node-postgres throws, nested under `cause` the way drizzle re-wraps it. */
function driverError(fields: { code?: string; constraint?: string; errno?: number; message?: string }): Error {
  const { message = 'pg', ...rest } = fields

  return new Error('Failed query: insert into "auth_identities"', {
    cause: Object.assign(new Error(message), rest),
  })
}

describe('sqlError', () => {
  // `has` refuses a code outside the set's own type, so each line checks the range the types read and the one the
  // set holds at once. One code per way in: named in words, named exactly, and named only by a prefix.
  it('draws its range from the whole table, so nothing it answers is re-labelled by wrap', () => {
    expect(sqlError.codes.has('AUTH_EMAIL_TAKEN')).toBe(true)
    expect(sqlError.codes.has('AUTH_STALE_WRITE')).toBe(true)
    expect(sqlError.codes.has('AUTH_INVALID_PARAMETERS')).toBe(true)
  })

  // Every SQL store throws these three itself and no driver ever names them, so only the map can put them in range.
  // Wired to `sqlError` instead, a store answers a revoked session with AUTH_ADAPTER_FAILED and a 500.
  it.each(['AUTH_CREDENTIAL_NOT_FOUND', 'AUTH_GRACE_EXPIRED', 'AUTH_SESSION_REVOKED'] as const)(
    'keeps %s in range, which a store raises itself',
    (code) => {
      expect(STORE_RAISES.codes.has(code)).toBe(true)
      const _inRange: SqlFault = code
      expect(_inRange).toBe(code)
    },
  )

  // INFO: SQLSTATE codes, https://www.postgresql.org/docs/current/errcodes-appendix.html
  it.each([
    ['23502', 'AUTH_NOT_ENOUGH_PARAMETERS'],
    ['23503', 'AUTH_IDENTITY_NOT_FOUND'],
    ['23505', 'AUTH_ALREADY_EXISTS'],
    ['23514', 'AUTH_INVALID_PARAMETERS'],
    ['22P02', 'AUTH_INVALID_PARAMETERS'],
    ['22021', 'AUTH_INVALID_PARAMETERS'],
    ['40001', 'AUTH_STALE_WRITE'],
    ['40P01', 'AUTH_STALE_WRITE'],
    ['08006', 'AUTH_ADAPTER_UNAVAILABLE'],
    ['53300', 'AUTH_ADAPTER_UNAVAILABLE'],
    ['57014', 'AUTH_ADAPTER_UNAVAILABLE'],
    ['57P01', 'AUTH_ADAPTER_UNAVAILABLE'],
    ['ECONNREFUSED', 'AUTH_ADAPTER_UNAVAILABLE'],
    ['42P01', 'AUTH_MISCONFIGURED'],
    ['42703', 'AUTH_MISCONFIGURED'],
    ['XX000', 'AUTH_ADAPTER_FAILED'],
  ])('reads %s as %s, keeping the driver error on cause', (code, expected) => {
    const err = driverError({ code })
    expect(sqlError(err)).toMatchObject({ cause: err, code: expected })
  })

  // INFO: mysql errnos, which mysql2 sets even for a code it has no name for.
  it.each([
    [1044, 'AUTH_MISCONFIGURED'],
    [1048, 'AUTH_NOT_ENOUGH_PARAMETERS'],
    [1062, 'AUTH_ALREADY_EXISTS'],
    [1146, 'AUTH_MISCONFIGURED'],
    [1205, 'AUTH_STALE_WRITE'],
    [1213, 'AUTH_STALE_WRITE'],
    [1452, 'AUTH_IDENTITY_NOT_FOUND'],
    [3819, 'AUTH_INVALID_PARAMETERS'],
    [9999, 'AUTH_ADAPTER_FAILED'],
  ])('reads errno %i as %s', (errno, expected) => {
    expect(sqlError(driverError({ errno })).code).toBe(expected)
  })

  // An errno is a whole token. Read as a prefix, 1062 would claim 10620 and answer a stranger's error as a duplicate.
  it('never reads one errno as a family of another', () => {
    expect(sqlError(driverError({ code: '10620' })).code).toBe('AUTH_ADAPTER_FAILED')
    expect(sqlError(driverError({ errno: 10624 })).code).toBe('AUTH_ADAPTER_FAILED')
  })

  // The token and the words have to agree: a driver that reports the code and no message still answers 409, not 400.
  it.each([
    ['SQLITE_CONSTRAINT_UNIQUE', 'AUTH_ALREADY_EXISTS'],
    ['SQLITE_CONSTRAINT_FOREIGNKEY', 'AUTH_IDENTITY_NOT_FOUND'],
    ['SQLITE_CONSTRAINT_NOTNULL', 'AUTH_NOT_ENOUGH_PARAMETERS'],
    ['SQLITE_CONSTRAINT_CHECK', 'AUTH_INVALID_PARAMETERS'],
    ['SQLITE_BUSY_SNAPSHOT', 'AUTH_STALE_WRITE'],
    ['SQLITE_READONLY_ROLLBACK', 'AUTH_MISCONFIGURED'],
    ['SQLITE_CANTOPEN', 'AUTH_MISCONFIGURED'],
  ])('reads the sqlite code %s as %s with no message to read', (code, expected) => {
    expect(sqlError(driverError({ code })).code).toBe(expected)
  })

  it.each([
    ['UNIQUE constraint failed: uq_auth_identities_email', 'AUTH_EMAIL_TAKEN'],
    ['UNIQUE constraint failed: auth_identity_providers.provider_sub', 'AUTH_PROVIDER_TAKEN'],
    ['FOREIGN KEY constraint failed', 'AUTH_IDENTITY_NOT_FOUND'],
    ['NOT NULL constraint failed: auth_identities.email', 'AUTH_NOT_ENOUGH_PARAMETERS'],
    ['no such table: auth_sessions', 'AUTH_MISCONFIGURED'],
  ])('reads what sqlite says in words, %s, as %s', (message, expected) => {
    expect(sqlError(driverError({ code: 'SQLITE_CONSTRAINT_UNIQUE', message })).code).toBe(expected)
  })

  // `MEANS['constructor']` is a function off the prototype, and a code read out of one is undefined: an AuthError
  // carrying no code serialises to an empty envelope with no status.
  it.each(['constructor', 'toString', 'hasOwnProperty', '__proto__'])('answers a %s code as a failure', (code) => {
    expect(sqlError(driverError({ code })).code).toBe('AUTH_ADAPTER_FAILED')
  })

  // A driver that refuses a write for a conflict read no versions, so it claims none rather than a pair of -1s.
  it('carries no versions on a race the driver refused', () => {
    expect(sqlError(driverError({ code: '40001' })).meta).toEqual({})
    expect(JSON.stringify(sqlError(driverError({ code: '40001' })))).not.toContain('-1')
  })

  it('names an email or username clash after its index rather than as a generic clash', () => {
    expect(sqlError(driverError({ code: '23505', constraint: 'uq_auth_identities_email' })).code).toBe(
      'AUTH_EMAIL_TAKEN',
    )
    expect(sqlError(driverError({ code: '23505', constraint: 'uq_auth_identities_username' })).code).toBe(
      'AUTH_USERNAME_TAKEN',
    )
  })

  it('reads an error pg threw directly, with no drizzle wrapper around it', () => {
    expect(sqlError(Object.assign(new Error('pg'), { code: '23503' })).code).toBe('AUTH_IDENTITY_NOT_FOUND')
  })

  it('passes an AuthError through as the same instance', () => {
    const typed = new AuthError('AUTH_PROVIDER_TAKEN')
    expect(sqlError(typed)).toBe(typed)
  })

  it('reports a value with no code at all as AUTH_ADAPTER_FAILED', () => {
    expect(sqlError('Connection terminated unexpectedly').code).toBe('AUTH_ADAPTER_FAILED')
    expect(sqlError(null).code).toBe('AUTH_ADAPTER_FAILED')
  })

  it('never puts the driver text on the wire', () => {
    const typed = sqlError(driverError({ code: '42P01' }))
    expect(JSON.stringify(typed)).not.toContain('auth_identities')
  })
})
