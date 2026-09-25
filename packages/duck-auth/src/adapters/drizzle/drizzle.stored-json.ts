/** What a JSON column hands back, and the parsers that turn it into row types.
 *  NOTE: a date inside a JSON column came back as an ISO string, so `$type<Date>()` names the intention. */

import { AuthError } from '~/core/errors'
import type { Identities } from '~/core/identities/identities.types'
import { isFactorMethod, type Sessions } from '~/core/sessions/sessions.types'

/** ISO string, epoch number or `Date` in, a usable `Date` or `null` out. Unparseable is `null`, not the
 *  `Invalid Date` that `new Date(value)` gives, which every guard accepts and every comparison rejects. */
export function storedDate(value: unknown): Date | null {
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null
  if (typeof value === 'string') {
    const parsed = new Date(value)
    return Number.isFinite(parsed.getTime()) ? parsed : null
  }
  if (typeof value === 'number' && Number.isFinite(value)) return new Date(value)
  return null
}

/** What the guards below narrow to: the row's own shape, with the date fields still as JSON left them. */
type StoredProviderLink = { addedAt?: unknown; providerId: string; providerSub: string }
type StoredFactor = { completedAt?: unknown; method: Sessions.FactorMethod }

/** A link is the pair a lookup matches on, so one missing either half can never match and is dropped. */
export function isProviderLink(value: unknown): value is StoredProviderLink {
  if (typeof value !== 'object' || value === null) return false
  if (!('providerId' in value) || typeof value.providerId !== 'string') return false
  return 'providerSub' in value && typeof value.providerSub === 'string'
}

/** WARN: a method outside the union is dropped, because `eligibleAal` counts distinct methods, and one
 *  no `switch` handles is worse than one that is absent. */
export function isFactor(value: unknown): value is StoredFactor {
  if (typeof value !== 'object' || value === null) return false
  if (!('method' in value)) return false
  return isFactorMethod(value.method)
}

/** A date the column cannot be read back as one. The entry stays, since dropping it would remove a way into
 *  the account, or downgrade an AAL, and an epoch reads as the unknown it is. */
const UNKNOWN_DATE = new Date(0)

/** NOTE: no dialect calls this, since the links are rows now. It reads the column a backfill migrates off. */
export function parseProviders(value: unknown): Identities.ProviderLink[] {
  if (!Array.isArray(value)) return []
  const links: Identities.ProviderLink[] = []
  for (const entry of value) {
    if (!isProviderLink(entry)) continue
    links.push({
      addedAt: storedDate(entry.addedAt) ?? UNKNOWN_DATE,
      // The column this reads predates `added_by`, so nothing it hands back can name an actor.
      addedBy: null,
      providerId: entry.providerId,
      providerSub: entry.providerSub,
    })
  }
  return links
}

/** Each field is read by name rather than spread, so a stored key the row type never had stays out. */
export function parseFactors(value: unknown): Sessions.Factor[] {
  if (!Array.isArray(value)) return []
  const factors: Sessions.Factor[] = []
  for (const entry of value) {
    if (!isFactor(entry)) continue
    factors.push({ completedAt: storedDate(entry.completedAt) ?? UNKNOWN_DATE, method: entry.method })
  }
  return factors
}

/** An impersonation window whose start or end cannot be read is not one anyone should be inside, so it
 *  is dropped whole rather than given a fallback date. */
export function parseActingAs(value: unknown): Sessions.ActingAs | null {
  // An empty column is a session that was never an impersonation.
  if (value === null || value === undefined) return null
  // SECURITY: present but unreadable refuses the session; `null` would say "not an impersonation", so the
  // row loads as the impersonated person's own session with no window check and no admin in the audit trail.
  const broken = (): never => {
    throw new AuthError('AUTH_SESSION_REVOKED', { reason: 'the impersonation window is present but unreadable' })
  }
  if (typeof value !== 'object') return broken()
  const startedAt = storedDate(Reflect.get(value, 'startedAt'))
  const expiresAt = storedDate(Reflect.get(value, 'expiresAt'))
  const realIdentityId = Reflect.get(value, 'realIdentityId')
  const reason = Reflect.get(value, 'reason')
  if (!startedAt || !expiresAt) return broken()
  if (typeof realIdentityId !== 'string' || typeof reason !== 'string') return broken()
  return { expiresAt, realIdentityId, reason, startedAt }
}

/** `pg` and `mysql2` hand back already-parsed JSON, sqlite the raw `TEXT`. Drizzle's own `jsonb` codec
 *  tolerates both, so must this one, or a row would read as `[]` on one driver and correctly on another. */
export function fromJsonColumn(value: unknown): unknown {
  if (typeof value !== 'string') return value
  try {
    return JSON.parse(value)
  } catch {
    // SECURITY: the unparseable string, not `null`. A SQL NULL is not a string and returned above, so
    // `null` here would make a corrupt column read as an absent one - and absent is exactly the answer
    // `parseActingAs` must refuse to give. Left present, each parser applies its own policy.
    return value
  }
}
