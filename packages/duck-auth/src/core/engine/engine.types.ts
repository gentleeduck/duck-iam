import type { Events } from '~/core/events/events.types'
import type { Limiter } from '~/limiters'
import type { AuthDefine } from '../config/config.types'
import type { Credential } from '../credentials/credentials.types'
import type { Hijack } from '../hijack/hijack.types'
import type { IdempotencyImpl } from '../idempotency'
import type { Identities } from '../identities/identities.types'
import type { Org } from '../orgs/orgs.types'
import type { Sessions } from '../sessions/sessions.types'
import type { Transport } from '../transport/transport.types'

export namespace Engine {
  /**
   * Cfguration for creating an {@link Engine} instance.
   *
   * @template Profile  - Shape of the user profile stored on identities.
   * @template Tenant   - Tenant discriminator type.
   * @template OrgMeta  - Shape of organization metadata.
   */
  export type Cfg<
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
    Tenant = string,
    OrgMeta = unknown,
  > = {
    baseUrl: string
    transport: Transport.ITransport
    stores: {
      identities: Identities.Store<Profile>
      sessions: Sessions.Store
      credentials: Credential.Store
      orgs?: Org.Store<OrgMeta>
    }
    limiter?: Limiter.Me
    /**
     * Capabilities (sign-in providers + attach-only facets), or thunks that
     * build one from the constructed engine + channels. Resolved and registered
     * by the engine constructor, so `new AuthEngine` and `createAuth` behave
     * identically.
     */
    providers?: AuthDefine.IProviderEntry<Profile, Tenant, OrgMeta>[]
    idempotency?: IdempotencyImpl
    /** Channel bundle forwarded to provider thunks (magic-link / OTP). */
    channels?: AuthDefine.IChannels
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
    hijack?: Hijack.Cfg
    __tenantBrand?: Tenant
  }
}
