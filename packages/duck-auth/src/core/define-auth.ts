import { AuthEngine } from './auth'
import { ScryptHasher } from './password/scrypt'
import type { AuthPluginRegistry } from './plugin'
import { AuthCookieTransport } from './transport/cookie'
import type { AuthChannel } from './types/channel'
import type { AuthCredential } from './types/credential'
import type { AuthEvents } from './types/events'
import type { AuthHasher } from './types/hasher'
import type { AuthIdentity } from './types/identity'
import type { AuthLimiter } from './types/limiter'
import type { AuthOrg } from './types/org'
import type { AuthProvider } from './types/provider'
import type { AuthSession } from './types/session'
import type { AuthTransport } from './types/transport'

/**
 * Friendly {@link AuthEngine} constructor from a flat config. Falsy entries in
 * `providers` are skipped; `strict: 'production'` runs `auth.strict()` at boot.
 *
 * @example
 * ```ts
 * export const auth = defineAuth({
 *   baseUrl: 'http://localhost:8787',
 *   storage: drizzlePgStorage(process.env.DATABASE_URL!),
 *   transport: cookieTransport({ name: 'duck-sid' }),
 *   limiter: memoryLimiter({ max: 30, windowMs: 60_000 }),
 *   hasher: argon2id(),
 *   channels: { email: consoleChannel() },
 *   providers: [password(), magicLink({ autoCreateIdentity: true })],
 *   strict: process.env.NODE_ENV === 'production' ? 'production' : 'development',
 * })
 * ```
 */
export function defineAuth<Profile = unknown, Tenant = string, OrgMeta = unknown>(
  config: AuthDefine.IConfig<Profile, Tenant, OrgMeta>,
): AuthEngine<Profile, Tenant, OrgMeta> {
  const transport = config.transport ?? new AuthCookieTransport({ name: 'duck-sid' })
  const passwords = config.hasher ? { hasher: config.hasher } : { hasher: new ScryptHasher() }

  const rootConfig: AuthEngine.IConfig<Profile, Tenant, OrgMeta> = {
    baseUrl: config.baseUrl,
    stores: {
      credentials: config.storage.credentials,
      identities: config.storage.identities,
      sessions: config.storage.sessions,
      ...(config.storage.orgs !== undefined && { orgs: config.storage.orgs }),
    },
    transport,
    passwords,
    ...(config.limiter !== undefined && { limiter: config.limiter }),
    ...(config.events !== undefined && { events: config.events }),
    ...(config.session !== undefined && { session: config.session }),
    ...(config.mfa !== undefined && { mfa: config.mfa }),
    ...(config.apiKeys !== undefined && { apiKeys: config.apiKeys }),
    ...(config.hijack !== undefined && { hijack: config.hijack }),
  }

  const auth = new AuthEngine<Profile, Tenant, OrgMeta>(rootConfig)

  for (const entry of config.providers ?? []) {
    if (!entry) continue
    const p = typeof entry === 'function' ? entry(auth) : entry
    if (!p) continue
    auth.providers.register(p)
  }

  if (config.plugins) {
    // Fire-and-forget install; callers needing completion should use
    // `Promise.all(plugins.map(p => auth.plugins.install(p)))` directly.
    for (const plugin of config.plugins) {
      if (!plugin) continue
      void auth.plugins.install(auth, plugin)
    }
  }

  if (config.strict) auth.strict({ env: config.strict })

  return auth
}

export namespace AuthDefine {
  /** A skipped-or-included provider entry; falsy values dropped, thunks receive the constructed AuthEngine. */
  export type IProviderEntry<Profile> =
    | AuthProvider.IProvider<unknown, unknown, Profile>
    | false
    | null
    | undefined
    | ''
    | ((
        // biome-ignore lint/suspicious/noExplicitAny: thunk accepts any Tenant/OrgMeta variance; caller resolves the concrete types
        auth: AuthEngine<Profile, any, any>,
      ) => AuthProvider.IProvider<unknown, unknown, Profile> | false | null | undefined | '')

  /** A skipped-or-included plugin entry - same rules as providers. */
  export type IPluginEntry<Profile = unknown, Tenant = string, OrgMeta = unknown> =
    | AuthPluginRegistry.IAuthPlugin<Profile, Tenant, OrgMeta>
    | false
    | null
    | undefined
    | ''

  /** Storage triple returned by `memoryStorage()` / `drizzlePgStorage()` / etc. */
  export interface IStorage<Profile = unknown, OrgMeta = unknown> {
    identities: AuthIdentity.IStore<Profile>
    sessions: AuthSession.IStore
    credentials: AuthCredential.IStore
    orgs?: AuthOrg.IStore<OrgMeta>
  }

  /** AuthChannel bundle keyed by channel kind. */
  export interface IChannels {
    email?: AuthChannel.IChannel
    sms?: AuthChannel.IChannel
    webpush?: AuthChannel.IChannel
  }

  export interface IConfig<Profile = unknown, _Tenant = string, OrgMeta = unknown> {
    /** Public-facing URL of the app. Used for OAuth redirect-URI derivation, magic-link URLs, etc. */
    baseUrl: string
    /** Storage triple - output of `memoryStorage()` / `drizzlePgStorage(...)` etc. */
    storage: IStorage<Profile, OrgMeta>
    /** Defaults to `new AuthCookieTransport({ name: 'duck-sid' })`. */
    transport?: AuthTransport.ITransport
    /** Token-bucket limiter. Omit for `AuthNoopLimiter` (rejected by `strict('production')`). */
    limiter?: AuthLimiter.ILimiter
    /** Password hasher. Defaults to `ScryptHasher`; pass `argon2id()` for production. */
    hasher?: AuthHasher.IHasher
    /** Optional channel bundle for magic-link / OTP delivery. */
    channels?: IChannels
    /** OAuth-wide defaults. `stateSigningSecret` is informational today; reserved for future per-provider auto-fill. */
    oauth?: { stateSigningSecret?: string }
    /** AuthProvider array - falsy entries are silently skipped. */
    providers?: IProviderEntry<Profile>[]
    /** Plugins applied via `auth.plugins.use(p)`. Falsy entries skipped. */
    plugins?: IPluginEntry<Profile, _Tenant, OrgMeta>[]
    /** Custom event bus (defaults to `InMemoryEvents` inside `AuthEngine`). */
    events?: AuthEvents.IBus
    /** AuthSession-config knobs passed straight to `AuthEngine.IConfig.session`. */
    session?: AuthEngine.IConfig<Profile>['session']
    mfa?: AuthEngine.IConfig<Profile>['mfa']
    apiKeys?: AuthEngine.IConfig<Profile>['apiKeys']
    hijack?: AuthEngine.IConfig<Profile>['hijack']
    /** When set, runs `auth.strict({ env })` at the end of construction. */
    strict?: 'development' | 'production' | 'test'
  }
}
