/**
 * Public surface for the SQL bridge contract. Consumers implement
 * `SqlBridge.IBridge` against any ORM (Drizzle, Kysely, Prisma, raw
 * pg, mysql2, better-sqlite3, ...) to back the Identity + Credential +
 * Session stores without forcing the auth lib to take a hard ORM
 * dependency.
 *
 * The interface intentionally stays at the row level - one method per
 * store operation - so the adapter does not invent its own query DSL.
 * Consumers translate each method to their ORM of choice.
 *
 * Tenant scoping: every method receives `tenantId` (or undefined).
 * Bridge implementations MUST scope every query by tenantId so a
 * tenant cannot read another tenant's rows.
 */
export namespace SqlBridge {
  /** Aggregate bridge consumers wire into `createSqlAuthStores`. */
  export interface IBridge {
    identities: IIdentity
    credentials: ICredential
    sessions: ISession
  }

  /**
   * Bridge for the `identities` table. Bridges return raw rows; the
   * adapter wraps them in the typed `Identity.IIdentity` shape.
   */
  export interface IIdentity {
    findById(id: string, tenantId: string | undefined): Promise<IIdentityRow | null>
    findByEmail(email: string, tenantId: string | undefined): Promise<IIdentityRow | null>
    findByProviderSub(providerId: string, sub: string, tenantId: string | undefined): Promise<IIdentityRow | null>
    insert(row: IIdentityRow): Promise<void>
    /** Optimistic update. Returns the new row when version matched; null when stale. */
    updateConditional(
      id: string,
      patch: Partial<Omit<IIdentityRow, 'id'>>,
      expectedVersion: number,
      tenantId: string | undefined,
    ): Promise<IIdentityRow | null>
    softDelete(id: string, deletedAt: number, tenantId: string | undefined): Promise<void>
    restore(id: string, tenantId: string | undefined): Promise<IIdentityRow | null>
    /** Hard delete + cascade rows in credentials / sessions. */
    erase(id: string, tenantId: string | undefined): Promise<void>
    insertProviderLink(
      identityId: string,
      providerId: string,
      providerSub: string | undefined,
      addedAt: number,
      tenantId: string | undefined,
    ): Promise<void>
    deleteProviderLink(identityId: string, providerId: string, tenantId: string | undefined): Promise<void>
    /** Re-point credentials + sessions at the survivor, then erase the dup. */
    merge(survivorId: string, dupId: string, tenantId: string | undefined): Promise<void>
  }

  /**
   * Bridge for the `credentials` table. Indexed on `(kind, secret)` so
   * `findByHashedSecret` is O(1).
   */
  export interface ICredential {
    findById(id: string, tenantId: string | undefined): Promise<ICredentialRow | null>
    listByIdentity(
      identityId: string,
      kind: string | undefined,
      tenantId: string | undefined,
    ): Promise<ICredentialRow[]>
    findByProviderSub(provider: string, sub: string, tenantId: string | undefined): Promise<ICredentialRow | null>
    findByHashedSecret(secretHash: string, kind: string, tenantId: string | undefined): Promise<ICredentialRow | null>
    insert(row: ICredentialRow): Promise<void>
    updateConditional(
      id: string,
      patch: Partial<Omit<ICredentialRow, 'id'>>,
      expectedVersion: number,
      tenantId: string | undefined,
    ): Promise<ICredentialRow | null>
    revoke(id: string, revokedAt: number, tenantId: string | undefined): Promise<void>
    delete(id: string, tenantId: string | undefined): Promise<void>
    deleteByKind(identityId: string, kind: string, tenantId: string | undefined): Promise<void>
  }

  /**
   * Bridge for the `sessions` table. Primary lookup is by sha256(sid).
   */
  export interface ISession {
    insert(row: ISessionRow): Promise<void>
    findByHash(sidHash: string): Promise<ISessionRow | null>
    update(id: string, patch: Partial<Omit<ISessionRow, 'id'>>): Promise<ISessionRow | null>
    delete(id: string): Promise<void>
    listByIdentity(identityId: string): Promise<ISessionRow[]>
    deleteAllForIdentity(identityId: string): Promise<void>
    deleteExpired(now: number): Promise<number>
  }

  /** Row shape the bridge stores under the identities table. */
  export interface IIdentityRow {
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

  /** Row shape the bridge stores under the credentials table. */
  export interface ICredentialRow {
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

  /** Row shape the bridge stores under the sessions table. */
  export interface ISessionRow {
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
}
