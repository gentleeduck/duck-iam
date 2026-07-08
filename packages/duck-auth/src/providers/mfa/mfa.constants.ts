import type { Mfa } from './mfa.types'

/** Default MFA facet config; overridden per-provider via `mfaProvider(cfg)`. */
export const DEFAULT_MFA_CONFIG: Mfa.Config = {
  issuer: 'duck-auth',
  backupCodeCount: 10,
  backupCodeLen: 10,
}
