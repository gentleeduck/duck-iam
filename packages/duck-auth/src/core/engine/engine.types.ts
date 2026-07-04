import type { HijackFacet } from '../facets/hijack'
import type { Credential, Identity, Org } from '../types/identity'
import type { Hasher, Limiter } from '../types/infra'
import type { AuthProvider, Events } from '../types/provider'
import type { Session, Transport } from '../types/session'

export namespace Engine {
  /**
   * Configuration for creating an {@link Engine} instance.
   *
   * @template Profile  - Shape of the user profile stored on identities.
   * @template Tenant   - Tenant discriminator type.
   * @template OrgMeta  - Shape of organization metadata.
   */
  export type Config<
    Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
    Tenant = string,
    OrgMeta = unknown,
  > = {
    baseUrl: string
    transport: Transport.ITransport
    stores: {
      identities: Identity.Store<Profile>
      sessions: Session.Store
      credentials: Credential.Store
      orgs?: Org.Store<OrgMeta>
    }
    limiter?: Limiter.ILimiter
    providers?: AuthProvider.IProvider<unknown, unknown, Profile>[]
    events?: Events.IBus
    session?: {
      ttlMs?: number
      absoluteTtlMs?: number
      freshnessMs?: number
    }
    identities?: {
      softDeleteGracePeriodMs?: number
      /** SEC: max serialized (JSON UTF-8) profile size, in bytes. Default 16 KiB. Set to `0` to disable. */
      profileMaxBytes?: number
    }
    passwords?: {
      /** Min length, default 8. AuthCompliance presets bump to 12+. */
      minLength?: number
      /** Max length, default 1024. SEC: caps argon2/scrypt DoS surface. */
      maxLength?: number
      rejectCommon?: boolean
      /** Pluggable hasher. Defaults to scrypt (Node built-in, zero deps). */
      hasher?: Hasher.IHasher
    }
    mfa?: {
      /** Brand shown in TOTP authenticator app entries. Default 'duck-auth'. */
      issuer?: string
      backupCodeCount?: number
      backupCodeLen?: number
    }
    apiKeys?: {
      prefix?: string
      randomBytes?: number
    }
    hijack?: HijackFacet.IPolicyConfig
    __tenantBrand?: Tenant
  }
}
