import { Argon2idHasher } from './hashers/argon2'
import type { Passwords } from './passwords.types'

/** Total: every field explicit. */
export const DEFAULT_PASSWORDS_CONFIG: Passwords.Cfg = {
  minLength: 8,
  maxLength: 1024,
  rejectCommon: true,
  autoRehash: true,
  limiterKeyPrefix: 'signin:password:',
  hasher: new Argon2idHasher(),
  compliance: 'gdpr',
}

/** Obvious junk rejected when `rejectCommon` is on. */
export const COMMON_PASSWORDS: ReadonlySet<string> = new Set([
  'password',
  'password1',
  '12345678',
  '123456789',
  'qwerty12',
  'iloveyou',
  'admin123',
  'welcome1',
  'letmein1',
])

/** Fed to `verify` on the no-such-user branch, so the timing matches and the account cannot be enumerated. */
export const NO_IDENTITY_SENTINEL = '00000000-0000-0000-0000-000000000000'

/** The marker a lookup returns in place of a credential, so an absent row costs the same as a present one. */
export const NO_CREDENTIAL_REFRENCE = 'duck-auth:no-credential-reference'
