/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

export { AuthRoot, type AuthRootConfig } from './auth'
export { randomToken, sha256, timingSafeEqual } from './crypto'
export { type AuthError, type AuthErrorCode, AuthErrorObject } from './errors'
export { InMemoryEvents } from './events'
export {
  BackupCodesFacet,
  type BackupCodesFacetConfig,
  DEFAULT_BACKUP_CODES_CONFIG,
} from './mfa/backup-codes'
export {
  ARGON2ID_COMPLIANCE,
  ARGON2ID_DEFAULTS,
  Argon2idHasher,
  type Argon2idParams,
} from './password/argon2'
export { SCRYPT_DEFAULTS, ScryptHasher, type ScryptParams } from './password/scrypt'
export * from './transport'
export * from './types'
