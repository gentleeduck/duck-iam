import type { HijackFacet } from '../facets/hijack'
import type { AuthCredential } from '../types/credential'
import type { AuthEvents } from '../types/events'
import type { AuthHasher } from '../types/hasher'
import type { AuthIdentity } from '../types/identity'
import type { AuthLimiter } from '../types/limiter'
import type { AuthOrg } from '../types/org'
import type { AuthProvider } from '../types/provider'
import type { AuthSession } from '../types/session'
import type { AuthTransport } from '../types/transport'

export namespace AuthEngineTypes {
  /**
   * Configuration for creating an {@link AuthEngine} instance.
   *
   * @template Profile  - Shape of the user profile stored on identities.
   * @template Tenant   - Tenant discriminator type.
   * @template OrgMeta  - Shape of organization metadata.
   */
  export interface IConfig<Profile = unknown, Tenant = string, OrgMeta = unknown> {
    baseUrl: string
    transport: AuthTransport.ITransport
    stores: {
      identities: AuthIdentity.IStore<Profile>
      sessions: AuthSession.IStore
      credentials: AuthCredential.IStore
      orgs?: AuthOrg.IStore<OrgMeta>
    }
    limiter?: AuthLimiter.ILimiter
    providers?: AuthProvider.IProvider<unknown, unknown, Profile>[]
    events?: AuthEvents.IBus
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
      hasher?: AuthHasher.IHasher
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
