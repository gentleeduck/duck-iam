import { AuthRoot } from './auth'
import { ScryptHasher } from './password/scrypt'
import type { PluginRegistry } from './plugin'
import { CookieTransport } from './transport/cookie'
import type { Channel } from './types/channel'
import type { Credential } from './types/credential'
import type { Events } from './types/events'
import type { Hasher } from './types/hasher'
import type { Identity } from './types/identity'
import type { Limiter } from './types/limiter'
import type { Org } from './types/org'
import type { Provider } from './types/provider'
import type { Session } from './types/session'
import type { Transport } from './types/transport'

/**
 * Friendly constructor that builds an {@link AuthRoot} from a flat
 * config: storage destructured, providers as an array of called
 * factories, channels grouped under one field, OAuth `stateSigningSecret`
 * hoisted to the root. Mirrors the duck-iam `defineRole(...).build()`
 * convention and the better-auth `betterAuth({ plugins: [...] })`
 * shape.
 *
 * Behavior:
 *
 * 1. **`storage`** - accepts the three-store triple produced by any
 *    storage helper (`memoryStorage()`, `drizzlePgStorage(...)`, etc.).
 *    Plugged into `AuthRoot.stores` verbatim.
 *
 * 2. **`providers`** - array of `Provider.IProvider | false | null |
 *    undefined`. Falsy entries are skipped so consumers can write
 *    `process.env.GOOGLE_CLIENT_ID && google({ ... })` without an
 *    extra `.filter(Boolean)`.
 *
 * 3. **`oauth.stateSigningSecret`** - currently informational; the
 *    OAuth provider factories still receive their own `stateSigningSecret`
 *    explicitly per-call. Recording it on the config lets future
 *    helper layers fill missing per-provider secrets without breaking
 *    today's call sites.
 *
 * 4. **`transport`** defaults to `new CookieTransport({ name:
 *    'duck-sid' })` when omitted.
 *
 * 5. **`hasher`** defaults to `new ScryptHasher()` (Node built-in,
 *    zero peerDep). Pass `argon2id()` for production.
 *
 * 6. **`limiter`** has no default - if omitted, `AuthRoot` uses its
 *    own internal `NoopLimiter` which `strict({ env: 'production' })`
 *    rejects. Wire `memoryLimiter()` for dev or a Redis-backed
 *    limiter for production.
 *
 * 7. **`plugins`** - array of `Plugin` objects; `auth.plugins.use(p)`
 *    is called for each.
 *
 * 8. **`strict`** - optional. When set to `'production'` etc., runs
 *    `auth.strict({ env })` at the end of construction so misconfig
 *    fails fast at boot rather than at first request.
 *
 * @example
 * ```ts
 * import { defineAuth } from '@gentleduck/auth/core'
 * import { drizzlePgStorage } from '@gentleduck/auth/adapters/drizzle/pg'
 * import { cookieTransport, memoryLimiter, argon2id, consoleChannel } from '@gentleduck/auth/core'
 * import { password, magicLink, google, github, passkey } from '@gentleduck/auth/providers'
 *
 * export const auth = defineAuth({
 *   baseUrl: 'http://localhost:8787',
 *   storage: drizzlePgStorage(process.env.DATABASE_URL!),
 *   transport: cookieTransport({ name: 'duck-sid' }),
 *   limiter: memoryLimiter({ max: 30, windowMs: 60_000 }),
 *   hasher: argon2id(),
 *   channels: { email: consoleChannel() },
 *   providers: [
 *     password(),
 *     magicLink({ autoCreateIdentity: true }),
 *     process.env.GOOGLE_CLIENT_ID && google({ clientId, clientSecret, redirectUri, stateSigningSecret }),
 *     passkey({ rpID: 'localhost', rpName: 'demo' }),
 *   ],
 *   strict: process.env.NODE_ENV === 'production' ? 'production' : 'development',
 * })
 * ```
 */
export function defineAuth<Profile = unknown, Tenant = string, OrgMeta = unknown>(
  config: DefineAuth.IConfig<Profile, Tenant, OrgMeta>,
): AuthRoot<Profile, Tenant, OrgMeta> {
  const transport = config.transport ?? new CookieTransport({ name: 'duck-sid' })
  const passwords = config.hasher ? { hasher: config.hasher } : { hasher: new ScryptHasher() }

  const rootConfig: AuthRoot.IConfig<Profile, Tenant, OrgMeta> = {
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

  const auth = new AuthRoot<Profile, Tenant, OrgMeta>(rootConfig)

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

/**
 * Namespace merge for {@link defineAuth}. Holds the config shape.
 */
export namespace DefineAuth {
  /**
   * A skipped-or-included provider entry. Any falsy value
   * (`false | null | undefined | ''`) is silently dropped so
   * consumers can write `process.env.X && google(...)` directly.
   *
   * Functions (thunks) receive the constructed `AuthRoot` so they
   * can resolve `auth.passwords` / `auth.identities` etc. without
   * the chicken-and-egg of needing the root before the array is
   * defined. The thunk's return value may itself be falsy.
   */
  export type IProviderEntry<Profile> =
    | Provider.IProvider<unknown, unknown, Profile>
    | false
    | null
    | undefined
    | ''
    | ((
        // biome-ignore lint/suspicious/noExplicitAny: thunk accepts any Tenant/OrgMeta variance; caller resolves the concrete types
        auth: AuthRoot<Profile, any, any>,
      ) => Provider.IProvider<unknown, unknown, Profile> | false | null | undefined | '')

  /** A skipped-or-included plugin entry - same rules as providers. */
  export type IPluginEntry<Profile = unknown, Tenant = string, OrgMeta = unknown> =
    | PluginRegistry.IAuthPlugin<Profile, Tenant, OrgMeta>
    | false
    | null
    | undefined
    | ''

  /** Storage triple returned by `memoryStorage()` / `drizzlePgStorage()` / etc. */
  export interface IStorage<Profile = unknown, OrgMeta = unknown> {
    identities: Identity.IStore<Profile>
    sessions: Session.IStore
    credentials: Credential.IStore
    orgs?: Org.IStore<OrgMeta>
  }

  /** Channel bundle keyed by channel kind. */
  export interface IChannels {
    email?: Channel.IChannel
    sms?: Channel.IChannel
    webpush?: Channel.IChannel
  }

  export interface IConfig<Profile = unknown, _Tenant = string, OrgMeta = unknown> {
    /** Public-facing URL of the app. Used for OAuth redirect-URI derivation, magic-link URLs, etc. */
    baseUrl: string
    /** Storage triple - output of `memoryStorage()` / `drizzlePgStorage(...)` etc. */
    storage: IStorage<Profile, OrgMeta>
    /** Defaults to `new CookieTransport({ name: 'duck-sid' })`. */
    transport?: Transport.ITransport
    /** Token-bucket limiter. Omit for `NoopLimiter` (rejected by `strict('production')`). */
    limiter?: Limiter.ILimiter
    /** Password hasher. Defaults to `ScryptHasher`; pass `argon2id()` for production. */
    hasher?: Hasher.IHasher
    /** Optional channel bundle for magic-link / OTP delivery. */
    channels?: IChannels
    /** OAuth-wide defaults. `stateSigningSecret` is informational today; reserved for future per-provider auto-fill. */
    oauth?: { stateSigningSecret?: string }
    /** Provider array - falsy entries are silently skipped. */
    providers?: IProviderEntry<Profile>[]
    /** Plugins applied via `auth.plugins.use(p)`. Falsy entries skipped. */
    plugins?: IPluginEntry<Profile, _Tenant, OrgMeta>[]
    /** Custom event bus (defaults to `InMemoryEvents` inside `AuthRoot`). */
    events?: Events.IBus
    /** Session-config knobs passed straight to `AuthRoot.IConfig.session`. */
    session?: AuthRoot.IConfig<Profile>['session']
    mfa?: AuthRoot.IConfig<Profile>['mfa']
    apiKeys?: AuthRoot.IConfig<Profile>['apiKeys']
    hijack?: AuthRoot.IConfig<Profile>['hijack']
    /** When set, runs `auth.strict({ env })` at the end of construction. */
    strict?: 'development' | 'production' | 'test'
  }
}
