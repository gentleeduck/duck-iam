import type { Mfa } from './mfa.types'

/** Overridden per provider through `mfaProvider(cfg)`. `dataAtRest` has no default. */
export const DEFAULT_MFA_CONFIG: Omit<Mfa.Cfg, 'dataAtRest'> = {
  issuer: 'duck-auth',
  backupCodeCount: 10,
  backupCodeLen: 10,
  compliance: 'gdpr',
}
