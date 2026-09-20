export {
  MemoryPasskeyChallengeStore as AuthMemoryPasskeyChallengeStore,
  memoryPasskeyChallengeStore,
} from './internal/challenge-store'
export { beginPasskeyRegistration, completePasskeyRegistration, PasskeyImpl, passkey, passkeyImpl } from './passkey'
export { DEFAULT_PASSKEY_CONFIG } from './passkey.constants'
export type { Passkey, Passkey as AuthPasskeyTypes } from './passkey.types'
