import type { Batch } from '~/core/batch'
import type { Credential } from '~/core/credentials/credentials.types'
import type { Sessions } from '~/core/sessions/sessions.types'

/**
 * Stable identity record + the IdentitiesFacet's own config/export types —
 * the single `Identity` namespace for the identities subject. Opaque to the
 * auth core; application-specific shape carried in `profile`.
 */
export namespace Identities {
  export type ProviderLink = {
    providerId: string
    providerSub: string | null
    addedAt: Date
  }

  export type ProfileMetadataBase = {
    username: string
    email: string
    [key: string]: unknown
  }

  export type Me<Profile extends ProfileMetadataBase = ProfileMetadataBase> = {
    id: string
    profile: Profile
    providers: ProviderLink[]
    /** Optimistic-locking version. Incremented on every successful write. */
    version: number
    emailVerified: boolean
    createdAt: Date
    updatedAt: Date
    /** Soft-delete grace; identity hidden from queries when set, hard-purged after window. */
    deletedAt: Date | null
  }

  /**
   * Input to `Store.create`. The store stamps `id`/`version`/`createdAt`/`updatedAt`;
   * `deletedAt` starts `null`. Every field is explicit — the facet coalesces
   * optional public inputs to defaults before passing this type.
   */
  export type CreateInput<Profile> = {
    profile: Profile
    providers: ProviderLink[]
    emailVerified: boolean
  }

  export type Store<Profile extends ProfileMetadataBase> = {
    findById(id: string): Promise<Me<Profile> | null>
    findByEmail(email: string): Promise<Me<Profile> | null>
    findByProviderSub(providerId: string, sub: string): Promise<Me<Profile> | null>
    create(input: CreateInput<Profile>): Promise<Me<Profile>>
    update(id: string, patch: Partial<Me<Profile>>, expectedVersion: number): Promise<Me<Profile>>
    softDelete(id: string, gracePeriodMs: number): Promise<void>
    restore(id: string): Promise<Me<Profile>>
    erase(id: string): Promise<void>
    link(identityId: string, link: ProviderLink): Promise<void>
    unlink(identityId: string, providerId: string): Promise<void>
    /** Merges a duplicate global identity into the survivor, repointing ALL of the dup's tenant-scoped rows (credentials/sessions) before erasing it. */
    merge(survivorId: string, dupId: string): Promise<void>
    /**
     * Re-bind this store to a caller-supplied driver client - a transaction
     * handle. The client is opaque to duck-auth and is handed straight back to
     * the adapter that produced this store, so the library never learns what
     * driver is in use.
     *
     * Absent means the store cannot join a transaction; `AuthEngine.withTransaction`
     * throws `AUTH_MISCONFIGURED` naming the store rather than silently leaving
     * it outside the caller's transaction.
     */
    withClient?(client: unknown): Store<Profile>

    /**
     * Set-based forms of the single-row writes above. Each is optional: the
     * facet loops over the single-row method when the store omits it, so the
     * memory and redis adapters need no change. A store that implements one
     * must apply it as ONE statement, atomic with any transaction the store is
     * bound to, and return one outcome per input row in input order.
     */
    softDeleteMany?(ids: readonly string[], gracePeriodMs: number): Promise<Batch.Result>
    restoreMany?(ids: readonly string[]): Promise<Batch.Result<Me<Profile>>>
    eraseMany?(ids: readonly string[]): Promise<Batch.Result>
    updateProfileMany?(
      rows: readonly { id: string; profile: Profile; expectedVersion: number }[],
    ): Promise<Batch.Result<Me<Profile>>>
    linkMany?(links: readonly { identityId: string; link: ProviderLink }[]): Promise<Batch.Result>
    unlinkMany?(links: readonly { identityId: string; providerId: string }[]): Promise<Batch.Result>
  }

  /** IdentitiesFacet tuning. */
  export interface Cfg {
    /** Grace before hard-purge after softDelete. Default 7 days. */
    softDeleteGracePeriodMs: number
    /**
     * maximum serialized (JSON / UTF-8 bytes) size of a profile.
     * Defaults to 16 KiB. Set to `0` to disable (not recommended -
     * unbounded profiles are a storage / read-amplification DoS).
     */
    profileMaxBytes?: number
  }

  /** GDPR Article 20 export envelope produced by {@link IdentitiesFacet.exportForIdentity}. */
  export interface ExportBlob<Profile extends ProfileMetadataBase> {
    identity: Me<Profile>
    credentials: Array<Omit<Credential.Me, 'secret'>>
    /** Live + recently-revoked sessions. Empty when caller skips sessions store. */
    sessions: Array<Omit<Sessions.Me, 'csrfHash'>>
    /** GDPR Article 20 envelope: schema version + export timestamp. */
    schemaVersion: '1'
    exportedAt: number
  }
}
