/**
 * Passkey provider — self-contained capability folder.
 * Everything passkey-related lives here: the sign-in provider, registration
 * ceremony helpers, the challenge store, and all types under the `Passkey`
 * namespace.
 */

export { MemoryPasskeyChallengeStore as AuthMemoryPasskeyChallengeStore } from './internal/challenge-store'
export { beginPasskeyRegistration, completePasskeyRegistration, passkey } from './passkey'
export { DEFAULT_PASSKEY_CONFIG } from './passkey.constants'
export type { Passkey, Passkey as AuthPasskeyTypes } from './passkey.types'
