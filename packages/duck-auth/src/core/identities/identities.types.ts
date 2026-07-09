import type { Session } from '~/core/sessions/sessions.types'
import type { Credential } from '~/core/types/identity'

/**
 * Stable identity record + the IdentitiesFacet's own config/export types —
 * the single `Identity` namespace for the identities subject. Opaque to the
 * auth core; application-specific shape carried in `profile`.
 */
export namespace Identity {
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
  }

  /** IdentitiesFacet tuning. */
  export interface Config {
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
    sessions: Array<Omit<Session.Me, 'csrfHash'>>
    /** GDPR Article 20 envelope: schema version + export timestamp. */
    schemaVersion: '1'
    exportedAt: number
  }
}
