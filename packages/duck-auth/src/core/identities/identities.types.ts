import type { Session } from '~/core/sessions/sessions.types'
import type { Credential } from '~/core/types/identity'
import type { TenantContext } from '~/core/types/infra'

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
    tenantId: string | null
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
   * optional public inputs to `null` / defaults before passing this type.
   */
  export type CreateInput<Profile> = {
    profile: Profile
    providers: ProviderLink[]
    tenantId: string | null
    emailVerified: boolean
  }

  export type Store<Profile extends ProfileMetadataBase> = {
    findById(id: string, ctx: TenantContext): Promise<Me<Profile> | null>
    findByEmail(email: string, ctx: TenantContext): Promise<Me<Profile> | null>
    findByProviderSub(providerId: string, sub: string, ctx: TenantContext): Promise<Me<Profile> | null>
    create(input: CreateInput<Profile>, ctx: TenantContext): Promise<Me<Profile>>
    update(id: string, patch: Partial<Me<Profile>>, expectedVersion: number, ctx: TenantContext): Promise<Me<Profile>>
    softDelete(id: string, gracePeriodMs: number, ctx: TenantContext): Promise<void>
    restore(id: string, ctx: TenantContext): Promise<Me<Profile>>
    erase(id: string, ctx: TenantContext): Promise<void>
    link(identityId: string, link: ProviderLink, ctx: TenantContext): Promise<void>
    unlink(identityId: string, providerId: string, ctx: TenantContext): Promise<void>
    merge(survivorId: string, dupId: string, ctx: TenantContext): Promise<void>
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
