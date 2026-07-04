import type { AuthEngine, AuthEngineTypes } from '../engine'
import type { AuthPluginRegistry } from '../plugin'
import type { Channel } from '../types/infra'
import type { Credential } from '../types/identity'
import type { Identity } from '../types/identity'
import type { Org } from '../types/identity'
import type { AuthProvider } from '../types/provider'
import type { Session } from '../types/session'
import type { Transport } from '../types/session'

export namespace AuthDefine {
  /**
   * Skipped-or-included provider entry. Falsy values silently dropped.
   * Thunks receive the constructed `AuthEngine` and the resolved channel bundle
   * so magic-link / OTP providers can bind both without repeating config.
   */
  export type IProviderEntry<Profile, Tenant = string, OrgMeta = unknown> =
    | AuthProvider.IProvider<unknown, unknown, Profile>
    | false
    | null
    | undefined
    | ''
    | ((
        auth: AuthEngine<Profile, Tenant, OrgMeta>,
        channels: IChannels | undefined,
      ) => AuthProvider.IProvider<unknown, unknown, Profile> | false | null | undefined | '')

  /** Skipped-or-included plugin entry — same falsy-drop rules as providers. */
  export type IPluginEntry<Profile = unknown, Tenant = string, OrgMeta = unknown> =
    | AuthPluginRegistry.IAuthPlugin<Profile, Tenant, OrgMeta>
    | false
    | null
    | undefined
    | ''

  /** Storage triple returned by `authMemoryStorage()` / `authDrizzlePgStorage()` / etc. */
  export interface IStorage<Profile = unknown, OrgMeta = unknown> {
    identities: Identity.Store<Profile>
    sessions: Session.Store
    credentials: Credential.Store
    /**
     * Optional org store. Not provided by `authDrizzlePgStorage` — implement
     * `Org.IStore<OrgMeta>` against your own org table and pass it here.
     * Omit if you are not using org-scoped sessions or duck-iam org scopes.
     */
    orgs?: Org.IStore<OrgMeta>
  }

  /** Channel bundle keyed by channel kind. Passed to provider thunks as second arg. */
  export interface IChannels {
    email?: Channel.IChannel
    sms?: Channel.IChannel
    webpush?: Channel.IChannel
  }

  /**
   * Input shape for {@link createAuth}. Flat, ergonomic alternative to constructing
   * {@link AuthEngine} directly.
   *
   * @template Profile  - Shape of the user profile stored on identities.
   * @template Tenant   - Tenant discriminator type (phantom; drives type-safety only).
   * @template OrgMeta  - Shape of organization metadata.
   */
  export interface IConfig<Profile = unknown, Tenant = string, OrgMeta = unknown>
    extends Omit<AuthEngineTypes.IConfig<Profile, Tenant, OrgMeta>, 'providers' | 'transport'> {
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
