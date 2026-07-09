import type { Identity } from '~/core'
import type { AuthEngine } from '~/core/engine'
import { toMfaConfig } from './mfa.config'
import { MfaFacet } from './mfa.facet'
import type { Mfa } from './mfa.types'

/**
 * MFA capability. MFA is a second factor, not a sign-in method, so this
 * carries no `begin`/`complete` — it is a facet the engine resolves via
 * `auth.mfa`. Add it to `providers: [mfaProvider()]`; `createAuth` calls
 * the thunk with the constructed engine and registers the returned facet.
 */
export function mfaProvider<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  cfg?: Mfa.ConfigInput,
): (auth: AuthEngine<Profile>) => MfaFacet {
  return (auth) => new MfaFacet(auth.config.stores.credentials, auth.events, toMfaConfig(cfg))
}
