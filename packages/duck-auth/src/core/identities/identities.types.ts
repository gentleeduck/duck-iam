import type { Credential } from '~/core/credentials/credentials.types'
import type { Sessions } from '~/core/sessions/sessions.types'

/** The identity row, its provider links, and the store contract over them. */
export namespace Identities {
  export type ProviderLink = {
    /** Which party issued the login, namespaced: 'oauth:authGoogle', 'saml:acme', 'okta'. Ours, not theirs. */
    providerId: string
    /** That party's own stable subject id for the account, such as a Google `sub`. Theirs, not ours. */
    providerSub: string
    addedAt: Date
    addedBy: string | null
  }

  /** `addedAt` is the table's default; only a caller restoring a link it removed brings its own. */
  export type ProviderLinkInput = Omit<ProviderLink, 'addedAt' | 'addedBy'> & { addedAt?: Date }

  export type ProfileMetadataBase = {
    username: string
    email: string
    [key: string]: unknown
  }

  export type Me<Profile extends ProfileMetadataBase = ProfileMetadataBase> = {
    id: string
    /** The host's own user fields; `username` and `email` are the only two this package reads. */
    profile: Profile
    /** Every linked provider; unlinking the last one that can sign in is refused. */
    providers: ProviderLink[]
    /** Optimistic-concurrency counter; a write passes it as `expectedVersion` to refuse a stale edit. */
    version: number
    /** Whether an address was proven, not merely asserted by a federated IdP. */
    emailVerified: boolean
    createdAt: Date
    updatedAt: Date
    /** Set by a soft delete; the row is hidden but recoverable until the grace period elapses. */
    deletedAt: Date | null
    /** The actor the soft delete was attributed to, or `null` where none was bound. */
    deletedBy: string | null
    /** The actor the create was attributed to, or `null` where none was bound. */
    createdBy: string | null
    /** The actor the last write was attributed to, or `null` where none was bound. */
    updatedBy: string | null
  }

  export type CreateInput<Profile> = {
    profile: Profile
    providers: ProviderLinkInput[]
    emailVerified: boolean
  }

  export type Store<Profile extends ProfileMetadataBase> = {
    find(by: { id: string } | { email: string } | { providerId: string; providerSub: string }): Promise<Me<Profile>>
    create(input: CreateInput<Profile>): Promise<Me<Profile>>
    update(
      id: string,
      patch: Partial<Pick<Me<Profile>, 'emailVerified' | 'profile'>>,
      expectedVersion: number,
    ): Promise<Me<Profile>>
    /** Hides the row for `gracePeriodMs`. Already hidden counts as no row, so a second call cannot push
     *  the window forward. */
    softDelete(id: string, gracePeriodMs: number): Promise<Me<Profile>>
    /** Clears a soft delete. A window already closed raises `AUTH_GRACE_EXPIRED`, not `NOT_FOUND`. */
    restore(id: string): Promise<Me<Profile>>
    /** Hard-deletes the row and its children, answering it as it stood just before it went. */
    erase(id: string): Promise<Me<Profile>>
    /** Attaches a login. A subject another identity holds is refused; a provider this one already holds is
     *  a no-op, which is what a retried OAuth callback does. */
    link(identityId: string, link: ProviderLinkInput): Promise<Me<Profile>>
    /** Detaches the login at `providerId`; there is at most one, and an absent one is not an error. */
    unlink(identityId: string, providerId: string): Promise<Me<Profile>>

    /** {@link Identities.Store.softDelete} and {@link Identities.Store.erase} for the admin and compliance paths. */
    softDeleteMany(ids: string[], gracePeriodMs: number): Promise<Me<Profile>[]>
    eraseMany(ids: string[]): Promise<Me<Profile>[]>

    /** Hard-deletes every row whose grace window closed before `now`, which is what makes a soft delete a
     *  delete rather than a row hidden forever. The children go with it, by the cascade
     *  {@link Identities.Store.erase} relies on. */
    gc(now: number): Promise<{ deleted: number }>
  }

  export interface Cfg {
    /** Default 7 days. */
    softDeleteGracePeriodMs: number
    /** Maximum serialised profile size in UTF-8 bytes, 16 KiB by default.
     *  WARN: `0` disables the cap, and an unbounded profile is a storage and read-amplification DoS. */
    profileMaxBytes?: number
  }

  /** GDPR Article 20 export envelope. */
  export interface ExportBlob<Profile extends ProfileMetadataBase> {
    identity: Me<Profile>
    credentials: Credential.Public[]
    /** Empty when the caller skips the sessions store. */
    sessions: Sessions.Public[]
    schemaVersion: '1'
    exportedAt: number
  }
}
