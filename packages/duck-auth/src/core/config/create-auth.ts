import type { AuthEngineTypes } from '../engine'
import { AuthEngine } from '../engine'
import { AuthScryptHasher } from '../password/scrypt'
import { AuthCookieTransport } from '../transport/cookie'
import type { AuthDefine } from './create-auth.types'

export type { AuthDefine } from './create-auth.types'

/**
 * Creates a fully-wired {@link AuthEngine} from a flat config. Primary entry
 * point for duck-auth — the ergonomic alternative to `new AuthEngine(config)`.
 *
 * Falsy entries in `providers` are silently skipped; `strict: 'production'`
 * runs `auth.strict()` at boot to enforce production-grade settings.
 *
 * @example
 * ```ts
 * export const auth = createAuth({
 *   baseUrl: 'http://localhost:8787',
 *   storage: authMemoryStorage(),
 *   transport: new AuthCookieTransport({ name: 'duck-sid' }),
 *   limiter: new AuthMemoryLimiter({ max: 30, windowMs: 60_000 }),
 *   hasher: new AuthArgon2idHasher(),
 *   channels: { email: new AuthConsoleChannel() },
 *   providers: [authPassword(), authMagicLink({ autoCreateIdentity: true })],
 *   strict: process.env.NODE_ENV === 'production' ? 'production' : 'development',
 * })
 * ```
 */
export function createAuth<Profile = unknown, Tenant = string, OrgMeta = unknown>(
  config: AuthDefine.IConfig<Profile, Tenant, OrgMeta>,
): AuthEngine<Profile, Tenant, OrgMeta> {
  const transport = config.transport ?? new AuthCookieTransport({ name: 'duck-sid' })

  // `passwords` field wins over shorthand `hasher` when both are set.
  const passwords: AuthEngineTypes.IConfig['passwords'] = config.passwords
    ? { hasher: new AuthScryptHasher(), ...config.passwords }
    : { hasher: config.hasher ?? new AuthScryptHasher() }

  const rootConfig: AuthEngineTypes.IConfig<Profile, Tenant, OrgMeta> = {
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
    ...(config.identities !== undefined && { identities: config.identities }),
    ...(config.mfa !== undefined && { mfa: config.mfa }),
    ...(config.apiKeys !== undefined && { apiKeys: config.apiKeys }),
    ...(config.hijack !== undefined && { hijack: config.hijack }),
  }

  const auth = new AuthEngine<Profile, Tenant, OrgMeta>(rootConfig)

  for (const entry of config.providers ?? []) {
    if (!entry) continue
    // Pass channels as second arg so magic-link / OTP thunks can bind without repeating config.
    const p = typeof entry === 'function' ? entry(auth, config.channels) : entry
    if (!p) continue
    auth.providers.register(p)
  }

  if (config.plugins) {
    for (const plugin of config.plugins) {
      if (!plugin) continue
      void auth.plugins.install(auth, plugin)
    }
  }

  if (config.strict) auth.strict({ env: config.strict })

  return auth
}
