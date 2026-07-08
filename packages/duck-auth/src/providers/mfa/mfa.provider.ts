import type { Identity } from '~/core'
import type { Provider } from '~/core/types/provider'
import { toMfaConfig } from './mfa.config'
import { MfaFacet } from './mfa.facet'
import type { Mfa } from './mfa.types'

/**
 * MFA capability module (mechanism A). Owns the MfaFacet + its config and
 * mounts it onto the engine at construction, exposing `auth.mfa`.
 * Add it to `providers: [mfaProvider()]`.
 *
 * MFA is a second factor, not a sign-in method, so the module is attach-only —
 * it carries no `Provider.Me`.
 */
export function mfaProvider<
  Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(cfg?: Mfa.ConfigInput): Provider.ProviderModule<Profile, Tenant, OrgMeta> {
  return {
    name: 'mfa',
    attach(engine) {
      engine.setMfa(new MfaFacet(engine.config.stores.credentials, engine.events, toMfaConfig(cfg)))
    },
  }
}
