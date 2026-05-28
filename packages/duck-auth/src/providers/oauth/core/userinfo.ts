/** Safe-extractor helpers for per-IdP userinfo / id_token claim shapes. */

import { isFiniteNumber } from '../../../core/credential-utils'

/**
 * Extract a non-empty string field from a userinfo object. Returns
 * `undefined` when the field is missing, null, or non-string - never
 * lies about the shape.
 */
export function getUserinfoString(info: unknown, key: string): string | undefined {
  if (typeof info !== 'object' || info === null || Array.isArray(info)) return undefined
  const v = Reflect.get(info, key)
  if (typeof v !== 'string' || v.length === 0) return undefined
  return v
}

/**
 * Extract a numeric id field and coerce to a non-empty string. Used
 * by GitHub (`info.id` is a numeric snowflake). Returns `undefined`
 * if the field isn't a finite number - defending against the
 * `String(null) === 'null'` multi-account-collapse bug.
 */
export function getUserinfoNumericIdAsString(info: unknown, key: string): string | undefined {
  if (typeof info !== 'object' || info === null || Array.isArray(info)) return undefined
  const v = Reflect.get(info, key)
  if (!isFiniteNumber(v)) return undefined
  return String(v)
}

/**
 * Extract a strict boolean field. Returns `true` only when the field
 * is `=== true`; returns `false` for everything else. Used for
 * `email_verified` claims - `=== true` defends against truthy-but-
 * non-boolean confusion (`"true"`, `1`, `[]`).
 */
export function getUserinfoBooleanTrue(info: unknown, key: string): boolean {
  if (typeof info !== 'object' || info === null || Array.isArray(info)) return false
  return Reflect.get(info, key) === true
}
