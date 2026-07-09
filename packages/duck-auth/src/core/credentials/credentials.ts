/** Runtime helpers for {@link Credential.Me} shared by multiple facets. */

import type { Credential } from '../credentials/credentials.types'

/** True when the credential row carries any `revokedAt` marker. */
export function isRevoked(row: Pick<Credential.Me, 'revokedAt'>): boolean {
  return row.revokedAt != null
}

/** True when an identity row carries any `deletedAt` marker (soft delete). */
export function isSoftDeleted(row: { deletedAt?: Date | number | null }): boolean {
  return row.deletedAt != null
}

/** Read the `purpose` field off a credential row's `metadata` object. */
export function getCredentialPurpose(row: Pick<Credential.Me, 'metadata'>): string | undefined {
  const meta = row.metadata
  if (meta == null) return undefined
  const purpose = meta.purpose
  return typeof purpose === 'string' ? purpose : undefined
}

/**
 * Coalesce a partial credential input into a total {@link Credential.UpsertInput}.
 * The facet boundary: callers supply the fields they care about; the nullable
 * columns default to `null` so `undefined` never reaches the store contract.
 */
export function toCredentialUpsert(
  input: Pick<Credential.UpsertInput, 'identityId' | 'kind' | 'secret'> & Partial<Credential.UpsertInput>,
): Credential.UpsertInput {
  return {
    tenantId: null,
    metadata: null,
    lastUsedAt: null,
    expiresAt: null,
    revokedAt: null,
    ...input,
  }
}

/** True when the row has an `expiresAt` that is malformed or in the past. */
export function isCredentialExpired(row: Pick<Credential.Me, 'expiresAt'>, now: number = Date.now()): boolean {
  return isExpiredAt(row.expiresAt, now)
}

/**
 * `null` / `undefined` -> false (no expiry configured — the live sentinel).
 * Date instance -> compare `.getTime()` against now (fail closed on invalid Date).
 * Non-numeric / NaN / Infinity -> true (fail closed).
 * Past -> true (expired). Future -> false (still valid).
 */
export function isExpiredAt(timestampMs: unknown, now: number = Date.now()): boolean {
  if (timestampMs == null) return false
  if (timestampMs instanceof Date) {
    const t = timestampMs.getTime()
    return !Number.isFinite(t) || t < now
  }
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
