import type { Deliver } from '~/core/flows/flows.delivery'
import type { AuthEngine, Engine } from '../engine'
import type { Identities } from '../identities/identities.types'
import type { PluginRegistry } from '../plugin'
import type { Provider } from '../provider/provider.types'
import type { Transport } from '../transport/transport.types'

/** The declarative config `createAuth` accepts, before it is resolved into an engine. */
export namespace AuthDefine {
  /**
   * Skipped-or-included provider entry. Falsy values silently dropped.
   * Thunks receive the constructed `AuthEngine` and the host's `deliver`, so magic-link and OTP can bind
   * both without repeating config.
   */
  export type IProviderEntry<
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
    Tenant = string,
    OrgMeta = unknown,
  > =
    | Provider.Capability
    | false
    | null
    | undefined
    | ''
    | ((
        auth: AuthEngine<Profile, Tenant, OrgMeta>,
        deliver: Deliver | undefined,
      ) => Provider.Capability | false | null | undefined | '')

  /** Skipped-or-included plugin entry — same falsy-drop rules as providers. */
  export type IPluginEntry<
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
    Tenant = string,
    OrgMeta = unknown,
  > = PluginRegistry.Plugin<Profile, Tenant, OrgMeta> | false | null | undefined | ''

  /**
   * Input shape for `createAuth`. Flat, ergonomic alternative to constructing
   * {@link AuthEngine} directly.
   *
   * @template Profile  - Shape of the user profile stored on identities.
   * @template Tenant   - Tenant discriminator type (phantom; drives type-safety only).
   * @template OrgMeta  - Shape of organization metadata.
   */
  export interface Cfg<
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
    Tenant = string,
    OrgMeta = unknown,
  > extends Omit<Engine.Cfg<Profile, Tenant, OrgMeta>, 'providers' | 'transport'> {
    transport?: Transport.ITransport
    /** oauth-wide defaults. `stateSigningSecret` used for state HMAC across all oauth providers. */
    oauth?: { stateSigningSecret?: string }
    /** Provider array — falsy entries silently skipped. */
    providers?: IProviderEntry<Profile, Tenant, OrgMeta>[]
    /** Plugins applied via `auth.plugins.install(p)`. Falsy entries skipped. */
    plugins?: IPluginEntry<Profile, Tenant, OrgMeta>[]
    /** Which environment's checks `auth.strict({ env })` runs at the end of construction. */
    strict?: 'development' | 'production' | 'test' | false
  }
}
