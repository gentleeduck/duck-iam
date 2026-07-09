import { AuthEngine, type Engine } from '../engine'
import type { Identity } from '../identities/identities.types'
import { CookieTransport } from '../transport/cookie.transport'
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
  const rootConfig: Engine.Config<Profile, Tenant, OrgMeta> = {
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
    // Provider registration (incl. thunk resolution) happens in the engine
    // constructor, so `new AuthEngine` and `createAuth` behave identically.
    providers: config.providers,
    channels: config.channels,
  }

  const auth = new AuthEngine<Profile, Tenant, OrgMeta>(rootConfig)

  if (config.strict) auth.strict({ env: config.strict })

  return auth
}
