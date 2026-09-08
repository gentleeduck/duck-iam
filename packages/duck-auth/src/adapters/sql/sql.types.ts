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
    /**
     * The mutating writes all hand back the row they touched, `null` when no row
     * matched, so a caller never has to re-read to see what a write did. Where
     * the dialect has `RETURNING` this is the same round trip; `erase` returns
     * the row as it was immediately before deletion.
     */
    /**
     * `deletedBy` is passed rather than read from the ambient actor inside each
     * dialect: the bridge is a data-layer contract, and three dialects each
     * reaching for context is three places for it to be forgotten.
     */
    softDelete(id: string, deletedAt: Date, deletedBy: string | null): Promise<Row | null>
    /** Clears `deletedAt` *and* `deletedBy`: a live row names no deleter. */
    restore(id: string): Promise<Row | null>
    erase(id: string): Promise<Row | null>
    insertProviderLink(
      identityId: string,
      providerId: string,
      providerSub: string | null,
      addedAt: Date,
    ): Promise<Row | null>
    deleteProviderLink(identityId: string, providerId: string): Promise<Row | null>
    merge(survivorId: string, dupId: string): Promise<Row | null>

    /**
     * Set-based forms of the writes above. Each returns the ids it actually
     * affected, which is what lets `createSqlStores` build honest per-row
     * outcomes: an id in the request but not in the response did not match.
     *
     * All optional. An adapter that omits one falls back to the facet's loop,
     * which is correct - just one statement per row instead of one per batch.
     */
    softDeleteManyReturningIds?(ids: readonly string[], deletedAt: Date, deletedBy: string | null): Promise<string[]>
    /**
     * Restore is the one set-based write with more than one way to refuse a
     * row, so it hands back what it READ as well as what it wrote. Without the
     * candidates `createSqlStores` can only see that an id did not come back,
     * and every refusal - closed grace window, address since taken - would have
     * to be reported as `not-found`, which is the one thing they are not.
     *
     * `candidates` is every row the ids matched, hidden or not; `restored` is
     * the subset actually brought back.
     */
    restoreManyReturning?(ids: readonly string[]): Promise<{
      candidates: Row[]
      restored: Row[]
      /**
       * Which rule refused each row that was restorable but not restored. The
       * dialect is the only place that knows - it ran both clash queries - and
       * without it `restoreMany` has to guess, which is how a provider clash
       * would arrive labelled `email-taken`. Optional so an older custom bridge
       * still compiles; omitting it falls back to that guess.
       */
      refused?: readonly { id: string; reason: 'email-taken' | 'provider-taken' }[]
    }>
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
    /**
     * As on the identity side, the removals hand back what they removed -
     * `null` / `[]` when nothing matched. `delete` and `deleteByKind` return
     * the rows as they were immediately before deletion.
     */
    revoke(id: string, revokedAt: Date, tenantId: string | undefined): Promise<Row | null>
    delete(id: string, tenantId: string | undefined): Promise<Row | null>
    deleteByKind(identityId: string, kind: Credential.Kind, tenantId: string | undefined): Promise<Row[]>

    /** Set-based delete by identity, returning the identity ids actually hit. Optional. */
    deleteByIdentitiesReturningIds?(identityIds: readonly string[], tenantId: string | undefined): Promise<string[]>
  }

  export type Session<Row> = {
    insert(row: Row): Promise<void>
    findByHash(sidHash: string): Promise<Row | null>
    update(id: string, patch: Partial<Omit<Row, 'id'>>): Promise<Row | null>
    delete(id: string): Promise<void>
    /**
     * `tenantId` undefined means every tenant, matching the credential bridge
     * above and `Sessions.Store.listByIdentity`. A named tenant matches exactly,
     * so a global (`tenant_id IS NULL`) session is not in its scope.
     */
    listByIdentity(identityId: string, tenantId: string | undefined): Promise<Row[]>
    deleteAllForIdentity(identityId: string, tenantId: string | undefined): Promise<void>
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
