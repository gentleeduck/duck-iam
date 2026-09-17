import { AuthEngine, type Engine } from '../engine'
import { AuthError } from '../errors'
import type { Identities } from '../identities/identities.types'
import { CookieTransport } from '../transport/cookie.transport'
import { assertKnownKeys, normaliseBaseUrl, resolveStrictEnv } from './config.constants'
import type { AuthDefine } from './config.types'

/**
 * Creates a fully-wired {@link AuthEngine} from a flat config. Primary entry
 * point for duck-auth: the ergonomic alternative to `new AuthEngine(config)`.
 *
 * Falsy entries in `providers` are silently skipped. `strict` runs `auth.strict()` at boot and
 * follows `NODE_ENV` unless it is named, so a production deploy is checked without being asked;
 * `strict: false` opts out.
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
  assertKnownKeys(config)
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

  const absent = (['identities', 'sessions', 'credentials'] as const).filter((name) => !config.stores?.[name])
  if (absent.length > 0) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `createAuth needs a store for identities, sessions and credentials; missing: ${absent.join(', ')}`,
    })
  }

  // Both are read before the engine exists, so a bad value is named here rather than surfacing as a
  // redirect to nowhere or a production deploy that skipped every check.
  const baseUrl = normaliseBaseUrl(config.baseUrl)
  const strictEnv = resolveStrictEnv(config.strict)
  const transport = config.transport ?? new CookieTransport({ name: 'duck-sid' })

  // Spread rather than key by key, or a key added later is silently dropped: it type-checks on the
  // way in, because `AuthDefine.Cfg` inherits it, and then goes nowhere.
  //
  // `plugins`, `oauth` and `strict` ride along and the engine never reads them: the first two are
  // refused above, and `strict` is applied below.
  const rootCfg: Engine.Cfg<Profile, Tenant, OrgMeta> = {
    ...config,
    baseUrl,
    transport,
  }

  const auth = new AuthEngine<Profile, Tenant, OrgMeta>(rootCfg)

  if (strictEnv) auth.strict({ env: strictEnv })

  return auth
}
