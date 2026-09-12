import { AuthError, asAuthError } from './errors'
import { declares, errorMap, type RangeOf } from './errors.map'

/** A code, or a code and the meta it cannot be raised without. */
type Means = AuthError.Bare | readonly [code: AuthError.Code, meta: object]

const DENIED = ['AUTH_MISCONFIGURED', { detail: 'the database refused the configured role' }] as const
const SCHEMA = ['AUTH_MISCONFIGURED', { detail: 'the database is missing the auth schema' }] as const
const UNOPENABLE = ['AUTH_MISCONFIGURED', { detail: 'the database file could not be opened' }] as const
// The store raises the real one with the versions it read; a driver that refused the write first knows neither.
const RACED = 'AUTH_STALE_WRITE'

/**
 * What a driver names when it refuses, and what that means. One table for all three dialects, because none of
 * their tokens collide: postgres names a SQLSTATE, mysql an errno, sqlite a SQLITE_ code, and the socket names
 * an errno of its own. A key shorter than a whole token matches as a prefix, which is how a SQLSTATE family and
 * a libsql code with its sub-code left off both read.
 */
const MEANS = {
  ECONNREFUSED: 'AUTH_ADAPTER_UNAVAILABLE',
  ECONNRESET: 'AUTH_ADAPTER_UNAVAILABLE',
  EPIPE: 'AUTH_ADAPTER_UNAVAILABLE',
  ETIMEDOUT: 'AUTH_ADAPTER_UNAVAILABLE',
  ENOTFOUND: 'AUTH_ADAPTER_UNAVAILABLE',
  EAI_AGAIN: 'AUTH_ADAPTER_UNAVAILABLE',
  EHOSTUNREACH: 'AUTH_ADAPTER_UNAVAILABLE',
  ENETUNREACH: 'AUTH_ADAPTER_UNAVAILABLE',
  PROTOCOL_CONNECTION_LOST: 'AUTH_ADAPTER_UNAVAILABLE',

  // INFO: SQLSTATE, https://www.postgresql.org/docs/current/errcodes-appendix.html
  '23502': 'AUTH_NOT_ENOUGH_PARAMETERS',
  '23503': 'AUTH_IDENTITY_NOT_FOUND', // every foreign key in the schema points at auth_identities.id
  '23505': 'AUTH_ALREADY_EXISTS',
  '28000': DENIED,
  '28P01': DENIED,
  '3D000': DENIED,
  '3F000': SCHEMA,
  '40001': RACED,
  '40P01': RACED,
  '42501': DENIED,
  '42703': SCHEMA,
  '42P01': SCHEMA,
  // By family, for the rest: 22/23/54 refuse the value itself; 08/53/57 mean the server cannot answer right now.
  '08': 'AUTH_ADAPTER_UNAVAILABLE',
  '22': 'AUTH_INVALID_PARAMETERS',
  '23': 'AUTH_INVALID_PARAMETERS',
  '53': 'AUTH_ADAPTER_UNAVAILABLE',
  '54': 'AUTH_INVALID_PARAMETERS',
  '57': 'AUTH_ADAPTER_UNAVAILABLE',

  // INFO: mysql errnos, which mysql2 sets even for a code it has no name for.
  // https://dev.mysql.com/doc/mysql-errors/8.4/en/server-error-reference.html
  1044: DENIED, // ER_DBACCESS_DENIED_ERROR
  1045: DENIED, // ER_ACCESS_DENIED_ERROR
  1048: 'AUTH_NOT_ENOUGH_PARAMETERS', // ER_BAD_NULL_ERROR
  1049: SCHEMA, // ER_BAD_DB_ERROR
  1054: SCHEMA, // ER_BAD_FIELD_ERROR
  1062: 'AUTH_ALREADY_EXISTS', // ER_DUP_ENTRY
  1146: SCHEMA, // ER_NO_SUCH_TABLE
  1205: RACED, // ER_LOCK_WAIT_TIMEOUT
  1213: RACED, // ER_LOCK_DEADLOCK
  1451: 'AUTH_IDENTITY_NOT_FOUND', // ER_ROW_IS_REFERENCED_2
  1452: 'AUTH_IDENTITY_NOT_FOUND', // ER_NO_REFERENCED_ROW_2
  3819: 'AUTH_INVALID_PARAMETERS', // ER_CHECK_CONSTRAINT_VIOLATED
  4025: 'AUTH_INVALID_PARAMETERS', // MariaDB's own errno for the same refused CHECK

  // INFO: sqlite extended result codes, https://www.sqlite.org/rescode.html
  SQLITE_AUTH: DENIED,
  SQLITE_BUSY: RACED,
  SQLITE_CANTOPEN: UNOPENABLE,
  SQLITE_CONSTRAINT: 'AUTH_INVALID_PARAMETERS',
  // Named before the family they belong to, or a driver that reports the code and no message reads a duplicate as a
  // bad value: 409 becomes 400 and the caller is told to fix input it got right.
  SQLITE_CONSTRAINT_FOREIGNKEY: 'AUTH_IDENTITY_NOT_FOUND',
  SQLITE_CONSTRAINT_NOTNULL: 'AUTH_NOT_ENOUGH_PARAMETERS',
  SQLITE_CONSTRAINT_UNIQUE: 'AUTH_ALREADY_EXISTS',
  SQLITE_LOCKED: RACED,
  SQLITE_PERM: DENIED,
  SQLITE_READONLY: DENIED,
} as const satisfies Readonly<Record<string, Means>>

/**
 * What a driver says in words, read before the token it named. Sqlite says everything here and names no token of
 * its own for a constraint, and an index name is the only thing that tells one clash from another.
 *
 * WARN: the wording comes before the index names, because a NOT NULL also names the column its index is on.
 */
const WORDS = [
  [/not null constraint failed/i, 'AUTH_NOT_ENOUGH_PARAMETERS'],
  [/foreign key constraint failed/i, 'AUTH_IDENTITY_NOT_FOUND'],
  [/check constraint failed/i, 'AUTH_INVALID_PARAMETERS'],
  [/no such (table|column)/i, SCHEMA],
  ['uq_auth_identities_email', 'AUTH_EMAIL_TAKEN'],
  ['uq_auth_identities_username', 'AUTH_USERNAME_TAKEN'],
  // All three refuse a login: another identity holds the sub, or this one already has that provider under a
  // different one. Sqlite names the column rather than the index.
  ['uq_auth_identity_providers_sub', 'AUTH_PROVIDER_TAKEN'],
  ['uq_auth_identity_providers_owned', 'AUTH_PROVIDER_TAKEN'],
  ['auth_identity_providers.provider_sub', 'AUTH_PROVIDER_TAKEN'],
  [/unique constraint failed/i, 'AUTH_ALREADY_EXISTS'],
] as const satisfies readonly (readonly [named: string | RegExp, is: Means])[]

/** The code an entry names, which is the entry itself unless it carries meta. */
type CodeOf<M> = M extends readonly [infer C extends AuthError.Code, object] ? C : M

/** What a SQL store answers with: what its driver refused, and what it raised itself. Read off the map, so a store
 *  cannot declare a range its own mapper does not draw from. */
export type SqlFault = RangeOf<typeof STORE_RAISES>

function codeOf<M extends Means>(means: M): CodeOf<M> {
  return (typeof means === 'string' ? means : means[0]) as CodeOf<M>
}

/** Own keys only: `MEANS['constructor']` is a function off the prototype, and reading a code out of one is undefined. */
function meansOf(key: string | number): (typeof MEANS)[keyof typeof MEANS] | undefined {
  return Object.hasOwn(MEANS, key) ? MEANS[key as keyof typeof MEANS] : undefined
}

// Longest first, so the most specific token wins however the table happens to be ordered. An errno never prefixes:
// it is a whole token, and `1062` would otherwise claim every longer number starting with it.
const PREFIXES = Object.entries(MEANS)
  .filter(([key]) => key.length <= 2 || Number.isNaN(Number(key)))
  .sort(([one], [other]) => other.length - one.length)

/** Turns what any of the three drivers threw, bare or under drizzle's `cause`, into the error that names it. */
export const sqlError = errorMap(
  (err: unknown): AuthError => {
    const said = signalOf(err)
    const means =
      WORDS.find(([named]) => (typeof named === 'string' ? said.text.includes(named) : named.test(said.text)))?.[1] ??
      meansOf(said.code) ??
      meansOf(said.errno) ??
      PREFIXES.find(([prefix]) => said.code.startsWith(prefix))?.[1]

    if (means === undefined) return asAuthError(err, 'AUTH_ADAPTER_FAILED')

    const code = codeOf(means)
    // Read this way and not as `means[1]`: a bare entry is a string, and `'AUTH_X'[1]` is a character.
    const carried = typeof means === 'string' ? undefined : means[1]
    // Postgres is the only one that says which provider was taken, and it says it in `detail`.
    const provider = code === 'AUTH_PROVIDER_TAKEN' ? keyValue(said.detail) : undefined
    const typed = new AuthError(code, provider ? { providerId: provider } : carried)
    typed.cause = err

    return typed
  },
  [...Object.values(MEANS).map(codeOf), ...WORDS.map(([, is]) => codeOf(is)), 'AUTH_ADAPTER_FAILED'],
)

/** The codes every SQL store throws itself, which no driver signal produces and the tables therefore never name.
 *  WARN: a `throw new AuthError(...)` in a store whose code is in neither is re-labelled AUTH_ADAPTER_FAILED by
 *  `wrap()` - add it here in the same change. */
export const STORE_RAISES = declares(sqlError, [
  'AUTH_CREDENTIAL_NOT_FOUND',
  'AUTH_GRACE_EXPIRED',
  'AUTH_SESSION_REVOKED',
])

/** Down the cause chain drizzle wrapped the driver error in, which is the only place anything above reads from. */
function* frames(err: unknown): Generator<object> {
  for (let frame: unknown = err, depth = 0; depth < 4 && typeof frame === 'object' && frame !== null; depth++) {
    yield frame
    frame = Reflect.get(frame, 'cause')
  }
}

function words(frame: object, key: string): string {
  const value: unknown = Reflect.get(frame, key)

  return typeof value === 'string' ? value : ''
}

/** The first frame that names a code, with everything it said alongside it. */
function signalOf(err: unknown): { code: string; detail: string; errno: number; text: string } {
  for (const frame of frames(err)) {
    const code = words(frame, 'code')
    const errno: unknown = Reflect.get(frame, 'errno')

    // NOTE: pg's own `constraint` field and the index the others name in words read the same here.
    if (code !== '' || typeof errno === 'number')
      return {
        code,
        detail: words(frame, 'detail'),
        errno: typeof errno === 'number' ? errno : 0,
        text: `${words(frame, 'message')} ${words(frame, 'sqlMessage')} ${words(frame, 'constraint')}`,
      }
  }

  return { code: '', detail: '', errno: 0, text: '' }
}

/** Which provider pg named in the key it refused on. A driver that named none leaves it off rather than guessing. */
function keyValue(detail: string): string | undefined {
  const key = /^Key \(([^)]*)\)=\((.*)\) already exists/.exec(detail)
  const at = key?.[1]?.split(', ').indexOf('provider_id') ?? -1

  return at >= 0 ? key?.[2]?.split(', ')[at] : undefined
}
