/** Runtime helpers for {@link Credential.Me} shared by multiple facets. */

import type { Credential } from '../credentials/credentials.types'
import type { TenantContext } from '../tenant/tenant.types'

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
 * Every meaning `kind: 'recovery'` carries. There are seven, and `kind` tells
 * them apart from none of each other - a password-reset token, a verification
 * mail, a pending account deletion and its undo link, an in-flight signup, an
 * MFA backup code and a remembered device are all one column value.
 * `metadata.purpose` is the real discriminator, and this is what it can say.
 *
 * The consequence of ignoring it is not cosmetic. `deleteByKind(id, 'recovery')`
 * reads as "clear the thing I just wrote" and means "clear all six", so
 * regenerating backup codes used to void the user's pending reset token, their
 * verification mail, their deletion request, their half-finished signup and
 * every device they had asked the site to remember. Read paths overreach the
 * same way: a `listByIdentity(id, 'recovery')` that hashes candidates against a
 * backup code is offering six other token families as second factors.
 *
 * So: filter every `recovery` read on a purpose from this table, and delete by
 * purpose ({@link deleteCredentialsByPurpose}) rather than by kind.
 */
export const RECOVERY_PURPOSES = {
  accountDeletion: 'account-deletion',
  accountDeletionCancel: 'account-deletion-cancel',
  emailVerification: 'email-verification',
  mfaBackupCode: 'mfa-backup-code',
  passwordReset: 'password-reset',
  signupFlow: 'signup-flow',
  trustedDevice: 'trusted-device',
} as const

/**
 * The `deleteByKind` a caller that owns one purpose actually wants: list the
 * kind, keep the rows whose `metadata.purpose` matches, delete only those.
 *
 * Costs one extra round trip against a store that cannot filter on metadata,
 * which every adapter here is. Returns the number of rows removed so a caller
 * can assert on it; `delete` returning `null` for a row that went between the
 * list and the delete is a concurrent delete, not an error, and is not counted.
 */
export async function deleteCredentialsByPurpose(
  store: Pick<Credential.Store, 'listByIdentity' | 'delete'>,
  identityId: string,
  kind: Credential.Kind,
  purpose: string,
  ctx: TenantContext,
): Promise<number> {
  const rows = await store.listByIdentity(identityId, kind, ctx)
  let removed = 0
  for (const row of rows) {
    if (getCredentialPurpose(row) !== purpose) continue
    if ((await store.delete(row.id, ctx)) !== null) removed++
  }
  return removed
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

/**
 * Read a finite-number field off an unknown metadata object.
 *
 * `NaN` is rejected rather than returned: a caller guarding with
 * `typeof x === 'number'` accepts it, and every comparison against `NaN` is
 * `false`, so a replay or expiry check written the obvious way passes.
 */
export function getProfileNumber(profile: unknown, key: string): number | undefined {
  if (!isPlainObject(profile)) return undefined
  const value = profile[key]
  return isFiniteNumber(value) ? value : undefined
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** Returns `true` only when `profile[key]` is strictly the boolean `true`. */
export function isProfileBooleanTrue(profile: unknown, key: string): boolean {
  if (!isPlainObject(profile)) return false
  return profile[key] === true
}

/**
 * Returns `true` only when `profile[key]` is strictly the boolean `false`.
 *
 * Not the negation of {@link isProfileBooleanTrue}: an absent key is neither,
 * and the difference is what tells "explicitly not yet confirmed" apart from
 * "never had the field".
 */
export function isProfileBooleanFalse(profile: unknown, key: string): boolean {
  if (!isPlainObject(profile)) return false
  return profile[key] === false
}
