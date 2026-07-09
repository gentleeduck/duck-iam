/**
 * MFA provider — self-contained capability folder (mechanism A).
 * Everything MFA-related lives here: the facet, its config, the TOTP helpers,
 * and all types under the `Mfa` namespace.
 */

export { toMfaConfig } from './mfa.config'
export { DEFAULT_MFA_CONFIG } from './mfa.constants'
export { MfaFacet } from './mfa.facet'
export { mfaProvider } from './mfa.provider'
export type { Totp } from './mfa.totp'
export {
  base32Decode,
  base32Encode,
  buildOtpAuthUri,
  generateSecret,
  TOTP_DEFAULTS,
  totpAt,
  verifyTotp,
} from './mfa.totp'
export type { Mfa } from './mfa.types'
export { BackupCodesFacet, DEFAULT_BACKUP_CODES_CONFIG } from './mfa.backup-codes'
export { RememberMeFacet, DEFAULT_REMEMBER_ME_CONFIG } from './mfa.remember-me'
