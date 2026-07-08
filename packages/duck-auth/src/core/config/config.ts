import type { AuthEngineTypes } from '../engine'
import { AuthEngine } from '../engine'
import { CookieTransport } from '../transport/cookie'
import type { Identity } from '../types/identity'
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
export function createAuth<
  const Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
  const Tenant = string,
  const OrgMeta = unknown,
>(config: AuthDefine.IConfig<Profile, Tenant, OrgMeta>): AuthEngine<Profile, Tenant, OrgMeta> {
  const transport = config.transport ?? new CookieTransport({ name: 'duck-sid' })

  // Engine-config knobs are genuinely optional tuning (not stored data), so they
  // stay optional and pass straight through — the `...(x !== undefined && {x})`
  // spread guard was noise, not safety (`exactOptionalPropertyTypes: false`).
  const rootConfig: AuthEngineTypes.Config<Profile, Tenant, OrgMeta> = {
    baseUrl: config.baseUrl,
    stores: {
      credentials: config.stores.credentials,
      identities: config.stores.identities,
      sessions: config.stores.sessions,
      orgs: config.stores.orgs,
    },
    transport,
    limiter: config.limiter,
    events: config.events,
    session: config.session,
    identities: config.identities,
    hijack: config.hijack,
  }

  const auth = new AuthEngine<Profile, Tenant, OrgMeta>(rootConfig)

  for (const entry of config.providers ?? []) {
    if (!entry) continue
    // Pass channels as second arg so magic-link / OTP thunks can bind without repeating config.
    const p = typeof entry === 'function' ? entry(auth, config.channels) : entry
    if (!p) continue
    // A capability module (mechanism A) mounts its own facet; a bare provider registers directly.
    if ('name' in p) {
      if (p.provider) auth.providers.register(p.provider)
      p.attach?.(auth)
    } else {
      auth.providers.register(p)
    }
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
