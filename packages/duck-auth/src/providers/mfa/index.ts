/**
 * MFA provider — self-contained capability folder (mechanism A).
 * Everything MFA-related lives here: the facet, its config, the TOTP helpers,
 * and all types under the `Mfa` namespace.
 */

export { BackupCodesFacet, DEFAULT_BACKUP_CODES_CONFIG } from './internal/backup-codes'
export { DEFAULT_REMEMBER_ME_CONFIG, RememberMeFacet } from './internal/remember-me'
export type { Totp } from './internal/totp'
export {
  base32Decode,
  base32Encode,
  buildOtpAuthUri,
  generateSecret,
  TOTP_DEFAULTS,
  totpAt,
  verifyTotp,
} from './internal/totp'
export { MfaFacet, mfaProvider } from './mfa'
export { DEFAULT_MFA_CONFIG, toMfaConfig } from './mfa.constants'
export type { Mfa } from './mfa.types'
