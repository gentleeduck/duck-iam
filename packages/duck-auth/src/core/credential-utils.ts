/** Runtime helpers for {@link AuthCredential.ICredential} shared by multiple facets. */

import type { AuthCredential } from './types/credential'

/** True when the credential row carries any `revokedAt` marker. */
export function isRevoked(row: Pick<AuthCredential.ICredential, 'revokedAt'>): boolean {
  return row.revokedAt !== undefined
}

/** True when an identity row carries any `deletedAt` marker (soft delete). */
export function isSoftDeleted(row: { deletedAt?: number }): boolean {
  return row.deletedAt !== undefined
}

/** Read the `purpose` field off a credential row's `metadata` object. */
export function getCredentialPurpose(row: Pick<AuthCredential.ICredential, 'metadata'>): string | undefined {
  const meta = row.metadata
  if (meta === undefined) return undefined
  const purpose = meta.purpose
  return typeof purpose === 'string' ? purpose : undefined
}

/** True when the row has an `expiresAt` that is malformed or in the past. */
export function isCredentialExpired(row: Pick<AuthCredential.ICredential, 'expiresAt'>, now: number = Date.now()): boolean {
  return isExpiredAt(row.expiresAt, now)
}

/**
 * `undefined` -> false (no expiry configured).
 * Non-numeric / NaN / Infinity -> true (fail closed).
 * Past -> true (expired). Future -> false (still valid).
 */
export function isExpiredAt(timestampMs: unknown, now: number = Date.now()): boolean {
  if (timestampMs === undefined) return false
  if (!isFiniteNumber(timestampMs)) return true
  return timestampMs < now
}

/** Type predicate: number AND not NaN / Infinity. */
export function isFiniteNumber(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v)
}

/** Read a non-empty string field off an unknown profile object. */
export function getProfileString(profile: unknown, key: string): string | undefined {
  if (!isPlainObject(profile)) return undefined
  const value = profile[key]
  if (typeof value !== 'string' || value.length === 0) return undefined
  return value
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** Returns `true` only when `profile[key]` is strictly the boolean `true`. */
export function isProfileBooleanTrue(profile: unknown, key: string): boolean {
  if (!isPlainObject(profile)) return false
  return profile[key] === true
}
