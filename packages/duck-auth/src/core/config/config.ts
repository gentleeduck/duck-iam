import { applyCompliancePreset } from '../compliance'
import { AuthEngine, type Engine } from '../engine'
import { AuthError } from '../errors'
import type { Identities } from '../identities/identities.types'
import { CookieTransport } from '../transport/cookie.transport'
import { assertKnownKeys, normaliseBaseUrl, resolveStrictEnv } from './config.constants'
import type { AuthDefine } from './config.types'

/** The ergonomic entry point: a fully-wired {@link AuthEngine} from one flat config. */
export function createAuth<
  const Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  const Tenant = string,
  const OrgMeta = unknown,
>(config: AuthDefine.Cfg<Profile, Tenant, OrgMeta>): AuthEngine<Profile, Tenant, OrgMeta> {
  assertKnownKeys(config)

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

  // Spread rather than key by key, or a key added later type-checks on the way in, because
  // `AuthDefine.Cfg` inherits it, and then goes nowhere. `strict` rides along unread and is applied below.
  const { compliance, ...rest } = config
  const rootCfg: Engine.Cfg<Profile, Tenant, OrgMeta> = {
    ...rest,
    baseUrl,
    transport,
  }

  const auth = new AuthEngine<Profile, Tenant, OrgMeta>(
    compliance ? applyCompliancePreset(rootCfg, compliance) : rootCfg,
  )

  if (strictEnv) auth.strict({ env: strictEnv })

  return auth
}
