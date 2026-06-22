import type { AuthEngine, AuthEngineTypes } from '../engine'
import type { AuthPluginRegistry } from '../plugin'
import type { AuthChannel } from '../types/channel'
import type { AuthCredential } from '../types/credential'
import type { AuthEvents } from '../types/events'
import type { AuthHasher } from '../types/hasher'
import type { AuthIdentity } from '../types/identity'
import type { AuthLimiter } from '../types/limiter'
import type { AuthOrg } from '../types/org'
import type { AuthProvider } from '../types/provider'
import type { AuthSession } from '../types/session'
import type { AuthTransport } from '../types/transport'

export namespace AuthDefine {
  /** Skipped-or-included provider entry; falsy values dropped, thunks receive the constructed AuthEngine. */
  export type IProviderEntry<Profile> =
    | AuthProvider.IProvider<unknown, unknown, Profile>
    | false
    | null
    | undefined
    | ''
    | ((
        auth: AuthEngine<Profile, any, any>,
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
    identities: AuthIdentity.IStore<Profile>
    sessions: AuthSession.IStore
    credentials: AuthCredential.IStore
    orgs?: AuthOrg.IStore<OrgMeta>
  }

  /** Channel bundle keyed by channel kind. */
  export interface IChannels {
    email?: AuthChannel.IChannel
    sms?: AuthChannel.IChannel
    webpush?: AuthChannel.IChannel
  }

  /**
   * Input shape for {@link createAuth}. Flat, ergonomic alternative to constructing
   * {@link AuthEngine} directly.
   *
   * @template Profile  - Shape of the user profile stored on identities.
   * @template _Tenant  - Tenant discriminator type (phantom; drives type-safety only).
   * @template OrgMeta  - Shape of organization metadata.
   */
  export interface IConfig<Profile = unknown, _Tenant = string, OrgMeta = unknown> {
    /** Public-facing URL of the app. Used for OAuth redirect-URI derivation, magic-link URLs, etc. */
    baseUrl: string
    /** Storage triple — output of `authMemoryStorage()` / `authDrizzlePgStorage(...)` etc. */
    storage: IStorage<Profile, OrgMeta>
    /** Defaults to `new AuthCookieTransport({ name: 'duck-sid' })`. */
    transport?: AuthTransport.ITransport
    /** Token-bucket limiter. Omit for `AuthNoopLimiter` (rejected by `strict('production')`). */
    limiter?: AuthLimiter.ILimiter
    /** Password hasher. Defaults to `AuthScryptHasher`; pass `new AuthArgon2idHasher()` for production. */
    hasher?: AuthHasher.IHasher
    /** Optional channel bundle for magic-link / OTP delivery. */
    channels?: IChannels
    /** OAuth-wide defaults. `stateSigningSecret` reserved for future per-provider auto-fill. */
    oauth?: { stateSigningSecret?: string }
    /** Provider array — falsy entries silently skipped. */
    providers?: IProviderEntry<Profile>[]
    /** Plugins applied via `auth.plugins.install(p)`. Falsy entries skipped. */
    plugins?: IPluginEntry<Profile, _Tenant, OrgMeta>[]
    /** Custom event bus (defaults to `AuthInMemoryEvents` inside `AuthEngine`). */
    events?: AuthEvents.IBus
    /** Session-config knobs passed straight to `AuthEngineTypes.IConfig.session`. */
    session?: AuthEngineTypes.IConfig<Profile>['session']
    mfa?: AuthEngineTypes.IConfig<Profile>['mfa']
    apiKeys?: AuthEngineTypes.IConfig<Profile>['apiKeys']
    hijack?: AuthEngineTypes.IConfig<Profile>['hijack']
    /** When set, runs `auth.strict({ env })` at end of construction. */
    strict?: 'development' | 'production' | 'test'
  }
}
