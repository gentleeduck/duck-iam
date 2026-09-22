/** Extractors for per-IdP userinfo and id_token claim shapes, which are whatever the IdP sent. */

import { isFiniteNumber } from '~/core/predicates/predicates'

/** `undefined` when the field is missing, null or not a string, rather than a coerced value. */
export function getUserinfoString(info: unknown, key: string): string | undefined {
  if (typeof info !== 'object' || info === null || Array.isArray(info)) return undefined
  const v = Reflect.get(info, key)
  if (typeof v !== 'string' || v.length === 0) return undefined
  return v
}

/**
 * Coerces a numeric id field to a string, for GitHub, whose `info.id` is a numeric snowflake.
 *
 * SECURITY: anything that is not a finite number answers `undefined`. Coercing blindly would make
 * `String(null)` the id `'null'`, collapsing every such account onto one identity.
 */
export function getUserinfoNumericIdAsString(info: unknown, key: string): string | undefined {
  if (typeof info !== 'object' || info === null || Array.isArray(info)) return undefined
  const v = Reflect.get(info, key)
  if (!isFiniteNumber(v)) return undefined
  return String(v)
}

/** True only for a literal `true`, so an `email_verified` of `"true"`, `1` or `[]` does not read as verified. */
export function getUserinfoBooleanTrue(info: unknown, key: string): boolean {
  if (typeof info !== 'object' || info === null || Array.isArray(info)) return false
  return Reflect.get(info, key) === true
}
