/**
 * Password provider — self-contained capability folder (mechanism A).
 * Everything password-related lives here: the sign-in provider, the facet,
 * its config, the hashers, and all types under the `Password` namespace.
 */

export { ARGON2ID_COMPLIANCE, ARGON2ID_DEFAULTS, Argon2idHasher } from './hashers/argon2.hasher'
export { SCRYPT_DEFAULTS, ScryptHasher } from './hashers/scrypt.hasher'
export { toPasswordsConfig } from './password.config'
export { COMMON_PASSWORDS, DEFAULT_PASSWORDS_CONFIG, NO_IDENTITY_SENTINEL } from './password.constants'
export { PasswordsFacet } from './password.facet'
export { password, passwordProvider } from './password.provider'
export type { Password } from './password.types'
