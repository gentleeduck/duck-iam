/**
 * Password provider — self-contained capability folder (mechanism A).
 * Everything password-related lives here: the sign-in provider, the facet,
 * its config, the hashers, and all types under the `Password` namespace.
 */

export { ARGON2ID_COMPLIANCE, ARGON2ID_DEFAULTS, Argon2idHasher } from './hashers/argon2'
export type { Hasher } from './hashers/hashers.types'
export { SCRYPT_DEFAULTS, ScryptHasher } from './hashers/scrypt'
export {
  PasswordsImpl,
  passwords,
} from './passwords'
export {
  COMMON_PASSWORDS,
  DEFAULT_PASSWORDS_CONFIG,
  NO_CREDENTIAL_REFRENCE,
  NO_IDENTITY_SENTINEL,
} from './passwords.constants'
export type { Passwords } from './passwords.types'
