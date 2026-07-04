import type { AuthEngineTypes } from '../engine'
import { AuthEngine } from '../engine'
import { AuthCookieTransport } from '../transport/cookie'
import type { AuthDefine } from './config.types'

/**
 * Creates a fully-wired {@link AuthEngine} from a flat config. Primary entry
 * point for duck-auth — the ergonomic alternative to `new AuthEngine(config)`.
 *
 * Falsy entries in `providers` are silently skipped; `strict: 'production'`
 * runs `auth.strict()` at boot to enforce production-grade settings.
 *
 * @example
 * ```ts
 * NOTE:
 * ```
 */
export function createAuth<const Profile = unknown, const Tenant = string, const OrgMeta = unknown>(
  config: AuthDefine.IConfig<Profile, Tenant, OrgMeta>,
): AuthEngine<Profile, Tenant, OrgMeta> {
  const transport = config.transport ?? new AuthCookieTransport({ name: 'duck-sid' })

  const rootConfig: AuthEngineTypes.IConfig<Profile, Tenant, OrgMeta> = {
    baseUrl: config.baseUrl,
    stores: {
      credentials: config.stores.credentials,
      identities: config.stores.identities,
      sessions: config.stores.sessions,
      ...(config.stores.orgs !== undefined && { orgs: config.stores.orgs }),
    },
    transport,
    ...(config.passwords !== undefined && { passwords: config.passwords }),
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
      void auth.use(plugin)
    }
  }

  if (config.strict) auth.strict({ env: config.strict })

  return auth
}
