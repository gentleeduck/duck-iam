import type { Session } from '../../core'
import type { Credential, Identity } from '../../core/types/identity'

export namespace SqlBridge {
  /** Aggregate bridge consumers wire into `createSqlStores`. */

  /** Re-export of the canonical base profile shape so bridge adapters can constrain on `SqlBridge.ProfileMetadataBase`. */
  export type ProfileMetadataBase = Identity.ProfileMetadataBase

  /** TODO: this is missing the event emitter to the db */
  export type Me<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase> = {
    identities: Identity<Identity.Me<Profile>>
    credentials: Credential<Credential.Me>
    sessions: Session<Session.Me>
    // TODO: add events emitter here
  }

  /**
   * Bridge for the `identities` table. Bridges return raw rows; the
   * adapter wraps them in the typed `Identity.IIdentity` shape.
   */
  export type Identity<Row> = {
    findById(id: string, tenantId: string | undefined): Promise<Row | null>
    findByEmail(email: string, tenantId: string | undefined): Promise<Row | null>
    findByProviderSub(providerId: string, sub: string, tenantId: string | undefined): Promise<Row | null>
    insert(row: Row): Promise<void>
    /** Optimistic update. Returns the new row when version matched; null when stale. */
    updateConditional(
      id: string,
      patch: Partial<Omit<Row, 'id'>>,
      expectedVersion: number,
      tenantId: string | undefined,
    ): Promise<Row | null>
    softDelete(id: string, deletedAt: Date, tenantId: string | undefined): Promise<void>
    restore(id: string, tenantId: string | undefined): Promise<Row | null>
    /** Hard delete + cascade rows in credentials / sessions. */
    erase(id: string, tenantId: string | undefined): Promise<void>
    insertProviderLink(
      identityId: string,
      providerId: string,
      providerSub: string | null,
      addedAt: Date,
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
  export type Credential<Row> = {
    findById(id: string, tenantId: string | undefined): Promise<Row | null>
    listByIdentity(identityId: string, kind: Credential.Kind | null, tenantId: string | undefined): Promise<Row[]>
    findByProviderSub(provider: string, sub: string, tenantId: string | undefined): Promise<Row | null>
    findByHashedSecret(secretHash: string, kind: Credential.Kind, tenantId: string | undefined): Promise<Row | null>
    insert(row: Row): Promise<void>
    updateConditional(
      id: string,
      patch: Partial<Omit<Row, 'id'>>,
      expectedVersion: number,
      tenantId: string | undefined,
    ): Promise<Row | null>
    revoke(id: string, revokedAt: Date, tenantId: string | undefined): Promise<void>
    delete(id: string, tenantId: string | undefined): Promise<void>
    deleteByKind(identityId: string, kind: Credential.Kind, tenantId: string | undefined): Promise<void>
  }

  /** Bridge for the `sessions` table. Primary lookup is by authSha256(sid). */
  export type Session<Row> = {
    insert(row: Row): Promise<void>
    findByHash(sidHash: string): Promise<Row | null>
    update(id: string, patch: Partial<Omit<Row, 'id'>>): Promise<Row | null>
    delete(id: string): Promise<void>
    listByIdentity(identityId: string): Promise<Row[]>
    deleteAllForIdentity(identityId: string): Promise<void>
    deleteExpired(now: Date): Promise<number>
  }
}
