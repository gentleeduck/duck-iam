import type { Credential } from '~/core/credentials/credentials.types'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions'

export namespace SqlBridge {
  export type ProfileMetadataBase = Identities.ProfileMetadataBase

  export type Me<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> = {
    identities: Identity<Identities.Me<Profile>>
    credentials: Credential<Credential.Me>
    sessions: Session<Sessions.Me>
    // TODO: add events emitter here
    /**
     * Re-make this bridge against a different driver client - a transaction
     * handle. Implemented by adapters whose driver has transactions;
     * `createSqlStores` propagates it to every store it builds, so one
     * implementation per adapter covers all three stores.
     */
    withClient?(client: unknown): Me<Profile>
  }

  export type Identity<Row> = {
    findById(id: string): Promise<Row | null>
    findByEmail(email: string): Promise<Row | null>
    findByProviderSub(providerId: string, sub: string): Promise<Row | null>
    insert(row: Row): Promise<void>
    updateConditional(id: string, patch: Partial<Omit<Row, 'id'>>, expectedVersion: number): Promise<Row | null>
    softDelete(id: string, deletedAt: Date): Promise<void>
    restore(id: string): Promise<Row | null>
    erase(id: string): Promise<void>
    insertProviderLink(identityId: string, providerId: string, providerSub: string | null, addedAt: Date): Promise<void>
    deleteProviderLink(identityId: string, providerId: string): Promise<void>
    merge(survivorId: string, dupId: string): Promise<void>

    /**
     * Set-based forms of the writes above. Each returns the ids it actually
     * affected, which is what lets `createSqlStores` build honest per-row
     * outcomes: an id in the request but not in the response did not match.
     *
     * All optional. An adapter that omits one falls back to the facet's loop,
     * which is correct - just one statement per row instead of one per batch.
     */
    softDeleteManyReturningIds?(ids: readonly string[], deletedAt: Date): Promise<string[]>
    restoreManyReturning?(ids: readonly string[]): Promise<Row[]>
    eraseManyReturningIds?(ids: readonly string[]): Promise<string[]>
    updateProfileManyReturning?(
      rows: readonly { id: string; patch: Partial<Omit<Row, 'id'>>; expectedVersion: number }[],
    ): Promise<Row[]>
    insertProviderLinks?(
      links: readonly { identityId: string; providerId: string; providerSub: string | null; addedAt: Date }[],
    ): Promise<string[]>
    deleteProviderLinks?(links: readonly { identityId: string; providerId: string }[]): Promise<string[]>
  }

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

    /** Set-based delete by identity, returning the identity ids actually hit. Optional. */
    deleteByIdentitiesReturningIds?(identityIds: readonly string[], tenantId: string | undefined): Promise<string[]>
  }

  export type Session<Row> = {
    insert(row: Row): Promise<void>
    findByHash(sidHash: string): Promise<Row | null>
    update(id: string, patch: Partial<Omit<Row, 'id'>>): Promise<Row | null>
    delete(id: string): Promise<void>
    listByIdentity(identityId: string): Promise<Row[]>
    deleteAllForIdentity(identityId: string): Promise<void>
    deleteExpired(now: Date): Promise<number>

    /**
     * Set-based forms of the deletes above, plus the read the facet needs to
     * name the sessions it revoked. All optional; the facet loops when absent.
     */
    deleteAllForIdentitiesReturningIds?(identityIds: readonly string[]): Promise<string[]>
    deleteManyReturningIds?(ids: readonly string[]): Promise<string[]>
    listByIdentities?(identityIds: readonly string[]): Promise<Row[]>
  }

  export type Event<Row> = {
    insert(row: Row): Promise<void>
  }
}
