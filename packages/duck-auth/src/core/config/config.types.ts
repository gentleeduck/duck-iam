import type { Channel } from '~/channels/channels.types'
import type { AuthEngine, Engine } from '../engine'
import type { Identity } from '../identities/identities.types'
import type { Org } from '../orgs/orgs.types'
import type { PluginRegistry } from '../plugin'
import type { Provider } from '../provider/provider.types'
import type { Session } from '../sessions/sessions.types'
import type { Credential } from '../types/identity'
import type { Transport } from '../types/session'

export namespace AuthDefine {
  /**
   * Skipped-or-included provider entry. Falsy values silently dropped.
   * Thunks receive the constructed `AuthEngine` and the resolved channel bundle
   * so magic-link / OTP providers can bind both without repeating config.
   */
  export type IProviderEntry<
    Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
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
        channels: IChannels | undefined,
      ) => Provider.Capability | false | null | undefined | '')

  /** Skipped-or-included plugin entry — same falsy-drop rules as providers. */
  export type IPluginEntry<
    Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
    Tenant = string,
    OrgMeta = unknown,
  > = PluginRegistry.Plugin<Profile, Tenant, OrgMeta> | false | null | undefined | ''

  /** Storage triple returned by `authMemoryStorage()` / `authDrizzlePgStorage()` / etc. */
  export interface IStorage<
    Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
    OrgMeta = unknown,
  > {
    identities: Identity.Store<Profile>
    sessions: Session.Store
    credentials: Credential.Store
    /**
     * Optional org store. Not provided by `authDrizzlePgStorage` — implement
     * `Org.Store<OrgMeta>` against your own org table and pass it here.
     * Omit if you are not using org-scoped sessions or duck-iam org scopes.
     */
    orgs?: Org.Store<OrgMeta>
  }

  /** Channel bundle keyed by channel kind. Passed to provider thunks as second arg. */
  export interface IChannels {
    email?: Channel.Channel
    sms?: Channel.Channel
    webpush?: Channel.Channel
  }

  /**
   * Input shape for {@link createAuth}. Flat, ergonomic alternative to constructing
   * {@link AuthEngine} directly.
   *
   * @template Profile  - Shape of the user profile stored on identities.
   * @template Tenant   - Tenant discriminator type (phantom; drives type-safety only).
   * @template OrgMeta  - Shape of organization metadata.
   */
  export interface IConfig<
    Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
    Tenant = string,
    OrgMeta = unknown,
  > extends Omit<Engine.Config<Profile, Tenant, OrgMeta>, 'providers' | 'transport'> {
    transport?: Transport.ITransport
    /** Channel bundle forwarded to provider thunks as second argument. */
    channels?: IChannels
    /** oauth-wide defaults. `stateSigningSecret` used for state HMAC across all oauth providers. */
    oauth?: { stateSigningSecret?: string }
    /** Provider array — falsy entries silently skipped. */
    providers?: IProviderEntry<Profile, Tenant, OrgMeta>[]
    /** Plugins applied via `auth.plugins.install(p)`. Falsy entries skipped. */
    plugins?: IPluginEntry<Profile, Tenant, OrgMeta>[]
    /** When set, runs `auth.strict({ env })` at end of construction. */
    strict?: 'development' | 'production' | 'test'
  }
}
