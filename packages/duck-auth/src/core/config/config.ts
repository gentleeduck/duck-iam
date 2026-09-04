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

  // Every `Engine.Cfg` key, by construction. Copying them across by hand is
  // what this used to do, and it dropped three: `idempotency` (the engine fell
  // back to MemoryIdempotency and `strict()` then refused to boot production),
  // `captcha`, and `resolveActor` - so a host that wired an actor resolver the
  // documented way wrote audit rows with no actor on them. Each one type-checks
  // on the way in, because `AuthDefine.Cfg` inherits the key, and then goes
  // nowhere. A spread cannot forget a key that is added later.
  //
  // `plugins`, `oauth` and `strict` ride along and the engine never reads them:
  // the first two are refused above, and `strict` is applied below.
  const rootCfg: Engine.Cfg<Profile, Tenant, OrgMeta> = {
    ...config,
    transport,
  }

  const auth = new AuthEngine<Profile, Tenant, OrgMeta>(rootCfg)

  if (config.strict) auth.strict({ env: config.strict })

  return auth
}
