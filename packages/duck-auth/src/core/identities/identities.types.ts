import type { Credential } from '~/core/credentials/credentials.types'
import type { Sessions } from '~/core/sessions/sessions.types'

/**
 * Stable identity record + the IdentitiesFacet's own config/export types —
 * the single `Identity` namespace for the identities subject. Opaque to the
 * auth core; application-specific shape carried in `profile`.
 */
export namespace Identities {
  /**
   * One external login this identity answers to. A credential kept here - a password, a magic link, a
   * passkey - is not one of these: it is a row in `credentials`, and nothing ever looks it up by subject.
   */
  export type ProviderLink = {
    /** Which party issued the login, namespaced: 'oauth:authGoogle', 'saml:acme', 'okta'. Ours, not theirs. */
    providerId: string
    /** That party's own stable subject id for the account, such as a Google `sub`. Theirs, not ours. */
    providerSub: string
    addedAt: Date
  }

  /** `addedAt` is the table's default; only a caller restoring a link it removed brings its own. */
  export type ProviderLinkInput = Omit<ProviderLink, 'addedAt'> & { addedAt?: Date }

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
    deletedAt: Date | null
    deletedBy: string | null
    createdBy: string | null
    updatedBy: string | null
  }

  /**
   * Input to `Store.create`. The store stamps `id`/`version`/`createdAt`/`updatedAt`;
   * `deletedAt` starts `null`. Every field is explicit — the facet coalesces
   * optional public inputs to defaults before passing this type.
   */
  export type CreateInput<Profile> = {
    profile: Profile
    providers: ProviderLinkInput[]
    emailVerified: boolean
  }

  /** What an update may change; the row owns its id, version, timestamps and audit columns. */
  export type UpdateInput<Profile extends ProfileMetadataBase> = Partial<Pick<Me<Profile>, 'emailVerified' | 'profile'>>

  /**
   * How a caller names the row it wants: by id, by address, or by the login it holds.
   *
   * Several addresses match any of them, which is how a row stored before addresses were
   * normalised is still found under the canonical spelling of the same address.
   */
  export type By = { id: string } | { email: string | readonly string[] } | { providerId: string; providerSub: string }

  export type Store<Profile extends ProfileMetadataBase> = {
    /** The one read: a live identity, by whichever of {@link By} the caller named it with. */
    find(by: By): Promise<Me<Profile> | null>
    create(input: CreateInput<Profile>): Promise<Me<Profile>>
    update(id: string, patch: UpdateInput<Profile>, expectedVersion: number): Promise<Me<Profile>>
    /**
     * Every mutating write answers with the row it touched, `null` when no row
     * matched, rather than `void`. A caller that needs to know what a write did
     * - the new `deletedAt`, the providers array after a link - should not have
     * to issue a second read to find out.
     */
    softDelete(id: string, gracePeriodMs: number): Promise<Me<Profile> | null>
    /**
     * Clears a soft delete. `null` means the id matched nothing, the same as
     * {@link softDelete} and {@link erase}. A row that WAS matched and then
     * refused throws `AUTH_GRACE_EXPIRED` instead. There is no freeness check:
     * the unique indexes are unconditional, so a hidden row held its address,
     * its handle and its logins the whole time and nothing can have taken them.
     */
    restore(id: string): Promise<Me<Profile> | null>
    /** Returns the row as it was immediately before deletion. */
    erase(id: string): Promise<Me<Profile> | null>
    link(identityId: string, link: ProviderLinkInput): Promise<Me<Profile> | null>
    unlink(identityId: string, providerId: string): Promise<Me<Profile> | null>
    /** Merges a duplicate global identity into the survivor, repointing ALL of the dup's tenant-scoped rows (credentials/sessions) before erasing it. */
    merge(survivorId: string, dupId: string): Promise<Me<Profile> | null>
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

  /** GDPR Article 20 export envelope produced by {@link IdentitiesImpl.exportAll}. */
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
