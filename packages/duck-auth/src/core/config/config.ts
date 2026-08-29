import { AuthEngine, type Engine } from '../engine'
import { AuthError } from '../errors'
import type { Identities } from '../identities/identities.types'
import { CookieTransport } from '../transport/cookie.transport'
import type { AuthDefine } from './config.types'

/**
 * Creates a fully-wired {@link AuthEngine} from a flat config. Primary entry
 * point for duck-auth: the ergonomic alternative to `new AuthEngine(config)`.
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
  const Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  const Tenant = string,
  const OrgMeta = unknown,
>(config: AuthDefine.Cfg<Profile, Tenant, OrgMeta>): AuthEngine<Profile, Tenant, OrgMeta> {
  // A key this factory cannot honour must not be accepted in silence. Installing
  // a plugin is async and `createAuth` is not, and an oauth state secret has to
  // reach each provider at construction, so both are refused with the call that
  // does work.
  if (config.plugins?.length) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail:
        'createAuth cannot install plugins: installation is async. Build the engine first, then `await auth.use(plugin)` for each one.',
    })
  }
  if (config.oauth?.stateSigningSecret) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail:
        'createAuth has no oauth-wide defaults to apply: pass `stateSigningSecret` to each oauth provider, e.g. `github({ stateSigningSecret })`.',
    })
  }

  const transport = config.transport ?? new CookieTransport({ name: 'duck-sid' })

  // Engine-config knobs are genuinely optional tuning (not stored data), so they
  // stay optional and pass straight through; the `...(x !== undefined && {x})`
  // spread guard was noise, not safety (`exactOptionalPropertyTypes: false`).
  const rootCfg: Engine.Cfg<Profile, Tenant, OrgMeta> = {
    baseUrl: config.baseUrl,
    stores: {
      credentials: config.stores.credentials,
      identities: config.stores.identities,
      sessions: config.stores.sessions,
      orgs: config.stores.orgs,
    },
    transport,
    limiter: config.limiter,
    // Inherited from Engine.Cfg, so a caller can always pass it and it type-checks.
    // Forgetting it here dropped it silently: the engine fell back to
    // MemoryIdempotency and strict() then refused to boot production.
    idempotency: config.idempotency,
    events: config.events,
    session: config.session,
    identities: config.identities,
    hijack: config.hijack,
    anomaly: config.anomaly,
    // Provider registration (incl. thunk resolution) happens in the engine
    // constructor, so `new AuthEngine` and `createAuth` behave identically.
    providers: config.providers,
    channels: config.channels,
  }

  const auth = new AuthEngine<Profile, Tenant, OrgMeta>(rootCfg)

  if (config.strict) auth.strict({ env: config.strict })

  return auth
}
