import type { HijackFacet } from '../facets/hijack'
import type { Credential, Identity, Org } from '../types/identity'
import type { Limiter } from '../types/infra'
import type { Events, Provider } from '../types/provider'
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
    limiter?: Limiter.Limiter
    providers?: (Provider.Me<unknown, unknown, Profile> | Provider.ProviderModule<Profile, Tenant, OrgMeta>)[]
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
    apiKeys?: {
      prefix?: string
      randomBytes?: number
    }
    hijack?: HijackFacet.Config
    __tenantBrand?: Tenant
  }
}
