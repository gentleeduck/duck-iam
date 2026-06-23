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
    identities: AuthIdentity.IStore<Profile>
    sessions: AuthSession.IStore
    credentials: AuthCredential.IStore
    /**
     * Optional org store. Not provided by `authDrizzlePgStorage` — implement
     * `AuthOrg.IStore<OrgMeta>` against your own org table and pass it here.
     * Omit if you are not using org-scoped sessions or duck-iam org scopes.
     */
    orgs?: AuthOrg.IStore<OrgMeta>
  }

  /** Channel bundle keyed by channel kind. Passed to provider thunks as second arg. */
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
   * @template Tenant   - Tenant discriminator type (phantom; drives type-safety only).
   * @template OrgMeta  - Shape of organization metadata.
   */
  export interface IConfig<Profile = unknown, Tenant = string, OrgMeta = unknown> {
    /** Public-facing URL of the app. Used for OAuth redirect-URI derivation, magic-link URLs, etc. */
    baseUrl: string
    /** Storage triple — output of `authMemoryStorage()` / `authDrizzlePgStorage(...)` etc. */
    storage: IStorage<Profile, OrgMeta>
    /** Defaults to `new AuthCookieTransport({ name: 'duck-sid' })`. */
    transport?: AuthTransport.ITransport
    /** Token-bucket limiter. Omit for `AuthNoopLimiter` (rejected by `strict('production')`). */
    limiter?: AuthLimiter.ILimiter
    /**
     * Password hasher. Defaults to `AuthScryptHasher`.
     * Pass `new AuthArgon2idHasher()` for production / HIPAA / FIPS.
     * Superseded by `passwords.hasher` when both are set.
     */
    hasher?: AuthHasher.IHasher
    /** Channel bundle forwarded to provider thunks as second argument. */
    channels?: IChannels
    /** OAuth-wide defaults. `stateSigningSecret` used for state HMAC across all OAuth providers. */
    oauth?: { stateSigningSecret?: string }
    /** Provider array — falsy entries silently skipped. */
    providers?: IProviderEntry<Profile, Tenant, OrgMeta>[]
    /** Plugins applied via `auth.plugins.install(p)`. Falsy entries skipped. */
    plugins?: IPluginEntry<Profile, Tenant, OrgMeta>[]
    /** Custom event bus (defaults to `AuthInMemoryEvents` inside `AuthEngine`). */
    events?: AuthEvents.IBus
    /** Session TTL knobs forwarded straight to `AuthEngineTypes.IConfig`. */
    session?: AuthEngineTypes.IConfig<Profile, Tenant, OrgMeta>['session']
    /** Identity-store knobs: soft-delete grace period, max profile size. */
    identities?: AuthEngineTypes.IConfig<Profile, Tenant, OrgMeta>['identities']
    /**
     * Password policy overrides. `hasher` here takes precedence over the
     * top-level `hasher` shorthand when both are provided.
     */
    passwords?: AuthEngineTypes.IConfig<Profile, Tenant, OrgMeta>['passwords']
    mfa?: AuthEngineTypes.IConfig<Profile, Tenant, OrgMeta>['mfa']
    apiKeys?: AuthEngineTypes.IConfig<Profile, Tenant, OrgMeta>['apiKeys']
    hijack?: AuthEngineTypes.IConfig<Profile, Tenant, OrgMeta>['hijack']
    /** When set, runs `auth.strict({ env })` at end of construction. */
    strict?: 'development' | 'production' | 'test'
  }
}
