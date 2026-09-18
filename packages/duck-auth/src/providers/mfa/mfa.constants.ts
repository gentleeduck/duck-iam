import type { Mfa } from './mfa.types'

/** Overridden per provider through `mfaProvider(cfg)`. */
export const DEFAULT_MFA_CONFIG: Mfa.Cfg = {
  issuer: 'duck-auth',
  backupCodeCount: 10,
  backupCodeLen: 10,
  compliance: 'gdpr',
}
