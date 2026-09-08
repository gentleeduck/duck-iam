/**
 * What a JSON column hands back, and the parsers that turn it into row types.
 *
 * Three typed-`Date` fields live inside `jsonb`/`json`/`text` columns:
 * `providers[].addedAt`, `factors[].completedAt`, and both dates on `actingAs`.
 * `JSON.stringify` wrote every one of them as an ISO string, so a `$type<T>()`
 * naming `Date` describes the intention and not the bytes. These parsers are
 * the runtime half the drizzle dialects wire into `customType`, and the same
 * ones `createSqlStores` runs as a second pass over any bridge.
 */

import type { Identities } from '~/core/identities/identities.types'
import { AUTH_SESSION_FACTOR_METHODS, type Sessions } from '~/core/sessions/sessions.types'

/**
 * A provider link as it comes back out of the column. `addedAt` is nullable
 * where {@link Identities.ProviderLink} has a `Date`: a column-level parser
 * cannot see the row's `createdAt` to fall back to, and inventing a date - or
 * an `Invalid Date`, which satisfies `instanceof Date` and compares `false`
 * against everything - would be the same lie one layer down.
 */
export type StoredProviderLink = Omit<Identities.ProviderLink, 'addedAt'> & { addedAt: Date | null }

/** As {@link StoredProviderLink}: the session's `createdAt` fallback is out of scope here. */
export type StoredFactor = Omit<Sessions.Factor, 'completedAt'> & { completedAt: Date | null }

/**
 * ISO string, epoch number or `Date` in, a usable `Date` or `null` out. An
 * unparseable value is `null` rather than `new Date(value)`, which would be an
 * `Invalid Date` - the shape every guard accepts and every comparison rejects.
 */
export function storedDate(value: unknown): Date | null {
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null
  if (typeof value === 'string') {
    const parsed = new Date(value)
    return Number.isFinite(parsed.getTime()) ? parsed : null
  }
  if (typeof value === 'number' && Number.isFinite(value)) return new Date(value)
  return null
}

/**
 * `$type<ProviderLink[]>()` is a compile-time assertion drizzle makes about a
 * JSON column; the database enforces `NOT NULL` and nothing else. A row written
 * by an older migration, another service, or a hand-run `UPDATE` can hold
 * `null`, `{}`, `"..."` or `[1, 2]` in that column, and every one of those used
 * to reach `.length`/`.map` and throw a `TypeError` out of a plain `findById`.
 * A link missing its `providerId` can never match a lookup, so keeping it would
 * only inflate the array.
 */
export function isProviderLink(value: unknown): value is Identities.ProviderLink {
  if (typeof value !== 'object' || value === null) return false
  if (!('providerId' in value) || typeof value.providerId !== 'string') return false
  if (!('providerSub' in value)) return false
  return value.providerSub === null || typeof value.providerSub === 'string'
}

/** A factor whose `method` is outside the union is dropped: an AAL decision has
 * to read the same on every backend, and a method no `switch` handles is worse
 * than one that is simply absent. */
export function isFactor(value: unknown): value is Sessions.Factor {
  if (typeof value !== 'object' || value === null) return false
  if (!('method' in value)) return false
  return AUTH_SESSION_FACTOR_METHODS.some((method) => method === value.method)
}

export function parseProviders(value: unknown): StoredProviderLink[] {
  if (!Array.isArray(value)) return []
  return value.filter(isProviderLink).map((link) => ({ ...link, addedAt: storedDate(link.addedAt) }))
}

export function parseFactors(value: unknown): StoredFactor[] {
  if (!Array.isArray(value)) return []
  return value.filter(isFactor).map((factor) => ({ ...factor, completedAt: storedDate(factor.completedAt) }))
}

/**
 * `actingAs` needs no sibling fallback and so is settled here in full: an
 * impersonation window whose start or end cannot be read is not a window anyone
 * should be inside, so it is dropped.
 */
export function parseActingAs(value: unknown): Sessions.ActingAs | null {
  if (typeof value !== 'object' || value === null) return null
  const startedAt = storedDate(Reflect.get(value, 'startedAt'))
  const expiresAt = storedDate(Reflect.get(value, 'expiresAt'))
  const realIdentityId = Reflect.get(value, 'realIdentityId')
  const reason = Reflect.get(value, 'reason')
  if (!startedAt || !expiresAt) return null
  if (typeof realIdentityId !== 'string' || typeof reason !== 'string') return null
  return { expiresAt, realIdentityId, reason, startedAt }
}

/**
 * Normalise what a JSON column's driver hands back before parsing. `pg` and
 * `mysql2` return already-parsed JSON; sqlite returns the raw `TEXT`, and
 * drizzle's own `jsonb` codec tolerates both - so must this one, or the same
 * row would read as `[]` on one driver and correctly on another.
 */
export function fromJsonColumn(value: unknown): unknown {
  if (typeof value !== 'string') return value
  try {
    return JSON.parse(value)
  } catch {
    return null
  }
}

/**
 * The half of JSON-column revival the column codecs cannot do.
 * `providers[].addedAt` and `factors[].completedAt` fall back to the row's own
 * `createdAt` when the stored value was unreadable - a sibling column, which a
 * `fromDriver` never sees. The date is informational, while dropping the entry
 * would silently remove a way into the account, or downgrade an AAL over a bad
 * timestamp. `actingAs` needs nothing here: it has no fallback, so its codec
 * settles it in full.
 */
export function reviveIdentityRow<T extends { providers: StoredProviderLink[]; createdAt: Date }>(
  row: T,
): Omit<T, 'providers'> & { providers: Identities.ProviderLink[] } {
  return { ...row, providers: row.providers.map((link) => ({ ...link, addedAt: link.addedAt ?? row.createdAt })) }
}

export function reviveIdentityRowOrNull<T extends { providers: StoredProviderLink[]; createdAt: Date }>(
  row: T | null,
): (Omit<T, 'providers'> & { providers: Identities.ProviderLink[] }) | null {
  return row ? reviveIdentityRow(row) : null
}

export function reviveSessionRowRequired<T extends { factors: StoredFactor[]; createdAt: Date }>(
  row: T,
): Omit<T, 'factors'> & { factors: Sessions.Factor[] } {
  return { ...row, factors: row.factors.map((f) => ({ ...f, completedAt: f.completedAt ?? row.createdAt })) }
}

export function reviveSessionRow<T extends { factors: StoredFactor[]; createdAt: Date }>(
  row: T | null,
): (Omit<T, 'factors'> & { factors: Sessions.Factor[] }) | null {
  return row ? reviveSessionRowRequired(row) : null
}
