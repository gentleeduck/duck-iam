/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

/**
 * Minimal SQL bridge. Consumers implement this against any ORM
 * (Drizzle, Kysely, Prisma, raw pg, mysql2, better-sqlite3, ...) to
 * back the Identity + Credential + Session stores without forcing the
 * auth lib to take a hard ORM dependency.
 *
 * The interface intentionally stays at the row level - one method per
 * store operation - so the adapter does not invent its own query DSL.
 * Consumers translate each method to their ORM of choice. A reference
 * Drizzle / pg implementation lives in the examples directory.
 *
 * Tenant scoping: every method receives `tenantId` (or undefined).
 * Bridge implementations MUST scope every query by tenantId so a
 * tenant cannot read another tenant's rows.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface SqlBridge {
  identities: SqlIdentityBridge
  credentials: SqlCredentialBridge
  sessions: SqlSessionBridge
}

/**
 * Bridge for the `identities` table. Bridges return raw rows; the
 * adapter wraps them in the typed `Identity.IIdentity` shape.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface SqlIdentityBridge {
  findById(id: string, tenantId: string | undefined): Promise<SqlIdentityRow | null>
  findByEmail(email: string, tenantId: string | undefined): Promise<SqlIdentityRow | null>
  findByProviderSub(
    providerId: string,
    sub: string,
    tenantId: string | undefined,
  ): Promise<SqlIdentityRow | null>
  insert(row: SqlIdentityRow): Promise<void>
  /** Optimistic update. Returns the new row when version matched; null when stale. */
  updateConditional(
    id: string,
    patch: Partial<Omit<SqlIdentityRow, 'id'>>,
    expectedVersion: number,
    tenantId: string | undefined,
  ): Promise<SqlIdentityRow | null>
  softDelete(id: string, deletedAt: number, tenantId: string | undefined): Promise<void>
  restore(id: string, tenantId: string | undefined): Promise<SqlIdentityRow | null>
  /** Hard delete the row + cascade rows in credentials / sessions. */
  erase(id: string, tenantId: string | undefined): Promise<void>
  insertProviderLink(
    identityId: string,
    providerId: string,
    providerSub: string | undefined,
    addedAt: number,
    tenantId: string | undefined,
  ): Promise<void>
  deleteProviderLink(
    identityId: string,
    providerId: string,
    tenantId: string | undefined,
  ): Promise<void>
  /** Re-point credentials + sessions at the survivor, then erase the dup. */
  merge(survivorId: string, dupId: string, tenantId: string | undefined): Promise<void>
}

/**
 * Bridge for the `credentials` table. Indexed on `(kind, secret)` so
 * `findByHashedSecret` is O(1).
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface SqlCredentialBridge {
  findById(id: string, tenantId: string | undefined): Promise<SqlCredentialRow | null>
  listByIdentity(
    identityId: string,
    kind: string | undefined,
    tenantId: string | undefined,
  ): Promise<SqlCredentialRow[]>
  findByProviderSub(
    provider: string,
    sub: string,
    tenantId: string | undefined,
  ): Promise<SqlCredentialRow | null>
  findByHashedSecret(
    secretHash: string,
    kind: string,
    tenantId: string | undefined,
  ): Promise<SqlCredentialRow | null>
  insert(row: SqlCredentialRow): Promise<void>
  updateConditional(
    id: string,
    patch: Partial<Omit<SqlCredentialRow, 'id'>>,
    expectedVersion: number,
    tenantId: string | undefined,
  ): Promise<SqlCredentialRow | null>
  revoke(id: string, revokedAt: number, tenantId: string | undefined): Promise<void>
  delete(id: string, tenantId: string | undefined): Promise<void>
  deleteByKind(
    identityId: string,
    kind: string,
    tenantId: string | undefined,
  ): Promise<void>
}

/**
 * Bridge for the `sessions` table. Primary lookup is by sha256(sid).
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface SqlSessionBridge {
  insert(row: SqlSessionRow): Promise<void>
  findByHash(sidHash: string): Promise<SqlSessionRow | null>
  update(id: string, patch: Partial<Omit<SqlSessionRow, 'id'>>): Promise<SqlSessionRow | null>
  delete(id: string): Promise<void>
  listByIdentity(identityId: string): Promise<SqlSessionRow[]>
  deleteAllForIdentity(identityId: string): Promise<void>
  deleteExpired(now: number): Promise<number>
}

/** Row shapes the bridge accepts + returns. */
export interface SqlIdentityRow {
  id: string
  tenantId: string | null
  /** JSON-encoded profile blob. */
  profile: string | null
  /** JSON-encoded provider-link array. */
  providers: string
  version: number
  createdAt: number
  updatedAt: number
  deletedAt: number | null
}

export interface SqlCredentialRow {
  id: string
  identityId: string
  tenantId: string | null
  kind: string
  secret: string
  metadata: string | null
  version: number
  createdAt: number
  lastUsedAt: number | null
  expiresAt: number | null
  revokedAt: number | null
}

export interface SqlSessionRow {
  id: string
  identityId: string | null
  tenantId: string | null
  kind: string
  aal: number
  factors: string
  csrfHash: string | null
  ip: string | null
  userAgent: string | null
  fingerprint: string | null
  createdAt: number
  rotatedAt: number
  expiresAt: number
  absoluteExpiresAt: number
  fresh: number
  actingAs: string | null
}

/**
 * Namespace merge for the SqlBridge surface. Co-locates the bridge
 * sub-interfaces + row shapes under one importable symbol.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace SqlBridge {
  /** Alias for `SqlIdentityBridge`. */
  export type IIdentity = SqlIdentityBridge
  /** Alias for `SqlCredentialBridge`. */
  export type ICredential = SqlCredentialBridge
  /** Alias for `SqlSessionBridge`. */
  export type ISession = SqlSessionBridge
  /** Alias for `SqlIdentityRow`. */
  export type IIdentityRow = SqlIdentityRow
  /** Alias for `SqlCredentialRow`. */
  export type ICredentialRow = SqlCredentialRow
  /** Alias for `SqlSessionRow`. */
  export type ISessionRow = SqlSessionRow
}
