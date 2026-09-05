import { expect } from 'vitest'

/**
 * What a row field is allowed to be when it comes back out of a store.
 *
 * The row types promise `Date`, `number`, `boolean` and `string`. A backend that
 * hands back the serialised form instead - `"2026-09-04T…"` for a `Date`, `"3"`
 * for a `version`, `1` for a boolean - still satisfies `tsc`, because nothing
 * re-checks a value that crossed a driver boundary. It surfaces later and
 * somewhere else, as `expiresAt.getTime is not a function` in a caller's code,
 * or worse as a comparison that silently does the wrong thing: `'2' > '10'` is
 * `true`, and `new Date(x) < now` against a string that failed to parse is
 * `false`, which reads as "not expired".
 */
type FieldKind = 'date' | 'date|null' | 'number' | 'number|null' | 'boolean' | 'string' | 'string|null'

/** A dotted path into a row, with `[]` marking "every element of this array". */
export type FieldSpec = Record<string, FieldKind>

function reach(row: unknown, path: string[]): unknown[] {
  if (path.length === 0) return [row]
  const [head, ...rest] = path
  if (row === null || row === undefined) return []
  if (head === '[]') {
    if (!Array.isArray(row)) return []
    return row.flatMap((item) => reach(item, rest))
  }
  if (typeof row !== 'object') return []
  return reach(Reflect.get(row, head as string), rest)
}

function check(value: unknown, kind: FieldKind, where: string): void {
  switch (kind) {
    case 'date':
    case 'date|null': {
      if (kind === 'date|null' && value === null) return
      expect(value, `${where} must be a Date, got ${describe(value)}`).toBeInstanceOf(Date)
      // A `Date` built from an unparseable string is still a `Date`. Every
      // comparison against it is `false`, so an expired row reads as live.
      expect(Number.isFinite((value as Date).getTime()), `${where} is an Invalid Date`).toBe(true)
      return
    }
    case 'number':
    case 'number|null': {
      if (kind === 'number|null' && value === null) return
      expect(typeof value, `${where} must be a number, got ${describe(value)}`).toBe('number')
      expect(Number.isFinite(value), `${where} is not finite`).toBe(true)
      return
    }
    case 'boolean':
      expect(typeof value, `${where} must be a boolean, got ${describe(value)}`).toBe('boolean')
      return
    case 'string':
      expect(typeof value, `${where} must be a string, got ${describe(value)}`).toBe('string')
      return
    case 'string|null':
      if (value === null) return
      expect(typeof value, `${where} must be a string or null, got ${describe(value)}`).toBe('string')
      return
  }
}

function describe(value: unknown): string {
  if (value === null) return 'null'
  if (value === undefined) return 'undefined'
  if (value instanceof Date) return `Date(${value.toISOString()})`
  return `${typeof value} ${JSON.stringify(value)}`
}

/**
 * Assert every field in `spec` came back as the type the row type declares.
 *
 * A field whose path resolves to nothing is skipped, not failed: `providers[]`
 * on an identity with no links, or `actingAs` on an ordinary session, are
 * legitimately absent. What this catches is a field that *is* there and is the
 * wrong shape.
 */
export function expectFieldTypes(row: unknown, spec: FieldSpec, label: string): void {
  for (const [path, kind] of Object.entries(spec)) {
    const segments = path.split('.')
    const optional = kind.endsWith('|null')
    for (const value of reach(row, segments)) {
      if (value === undefined && optional) continue
      check(value, kind, `${label}.${path}`)
    }
  }
}

/** `Identities.Me` - every field the type declares with a concrete shape. */
export const IDENTITY_FIELDS: FieldSpec = {
  createdAt: 'date',
  createdBy: 'string|null',
  deletedAt: 'date|null',
  deletedBy: 'string|null',
  emailVerified: 'boolean',
  id: 'string',
  'providers.[].addedAt': 'date',
  'providers.[].providerId': 'string',
  'providers.[].providerSub': 'string|null',
  updatedAt: 'date',
  updatedBy: 'string|null',
  version: 'number',
}

/** `Sessions.Me`. It carries no `version`; the row is replaced, not patched. */
export const SESSION_FIELDS: FieldSpec = {
  aal: 'number',
  absoluteExpiresAt: 'date',
  'actingAs.expiresAt': 'date',
  'actingAs.realIdentityId': 'string',
  'actingAs.startedAt': 'date',
  createdAt: 'date',
  csrfHash: 'string|null',
  expiresAt: 'date',
  'factors.[].completedAt': 'date',
  'factors.[].method': 'string',
  fingerprint: 'string|null',
  fresh: 'boolean',
  id: 'string',
  identityId: 'string|null',
  ip: 'string|null',
  kind: 'string',
  rotatedAt: 'date',
  tenantId: 'string|null',
  userAgent: 'string|null',
}

/**
 * The OIDC OP rows. Every instant here is an epoch `number`, not a `Date` - and
 * on Postgres they are `bigint` columns, which node-postgres hands back as
 * strings so that an id past 2^53 is not silently rounded. Whether drizzle's
 * `mode: 'number'` converts them is the whole question these answer.
 */
export const OIDC_CLIENT_FIELDS: FieldSpec = {
  client_id: 'string',
  createdAt: 'number',
  'grant_types.[]': 'string',
  'redirect_uris.[]': 'string',
  'response_types.[]': 'string',
  'scope.[]': 'string',
  token_endpoint_auth_method: 'string',
}

export const OIDC_CODE_FIELDS: FieldSpec = {
  client_id: 'string',
  code: 'string',
  exp: 'number',
  identity_id: 'string',
  redirect_uri: 'string',
  'scope.[]': 'string',
  sid: 'string',
  tenant_id: 'string|null',
}

export const OIDC_ACCESS_TOKEN_FIELDS: FieldSpec = {
  client_id: 'string',
  exp: 'number',
  identity_id: 'string',
  'scope.[]': 'string',
  tenant_id: 'string|null',
  token_hash: 'string',
}

export const OIDC_REFRESH_TOKEN_FIELDS: FieldSpec = {
  client_id: 'string',
  consumedAt: 'number|null',
  exp: 'number',
  family_id: 'string',
  identity_id: 'string',
  'scope.[]': 'string',
  tenant_id: 'string|null',
  token_hash: 'string',
}

export const OIDC_CONSENT_FIELDS: FieldSpec = {
  client_id: 'string',
  grantedAt: 'number',
  identity_id: 'string',
  'scope.[]': 'string',
}

/** `Credential.Me`. */
export const CREDENTIAL_FIELDS: FieldSpec = {
  createdAt: 'date',
  createdBy: 'string|null',
  expiresAt: 'date|null',
  id: 'string',
  identityId: 'string',
  kind: 'string',
  lastUsedAt: 'date|null',
  revokedAt: 'date|null',
  secret: 'string',
  tenantId: 'string|null',
  updatedBy: 'string|null',
  version: 'number',
}

/** `Org.Me`. */
export const ORG_FIELDS: FieldSpec = {
  createdAt: 'date',
  domain: 'string|null',
  id: 'string',
  name: 'string',
}

/** `Org.Membership`. */
export const MEMBERSHIP_FIELDS: FieldSpec = {
  identityId: 'string',
  invitedAt: 'date|null',
  joinedAt: 'date',
  leftAt: 'date|null',
  orgId: 'string',
  'roles.[]': 'string',
}
