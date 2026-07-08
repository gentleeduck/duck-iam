import type { Password } from './password.types'

/** Default resolved facet config (null-discipline: every field explicit). */
export const DEFAULT_PASSWORDS_CONFIG: Password.Config = {
  minLength: 8,
  maxLength: 1024,
  rejectCommon: true,
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

/**
 * Sentinel identity id fed to `verify` on the no-such-user branch to keep
 * timing constant (defeats account enumeration). MUST be a syntactically
 * valid UUID: the SQL adapters store `identity_id` as a `uuid` column, so a
 * non-UUID sentinel (e.g. `'__never__'`) makes Postgres throw
 * `invalid input syntax for type uuid` instead of returning zero rows. The
 * all-zero UUID is well-formed and matches no real identity.
 */
export const NO_IDENTITY_SENTINEL = '00000000-0000-0000-0000-000000000000'
