/** Shared structural parsers for the drizzle sqlite + mysql adapters. */

import { isFiniteNumber } from '../../core/credential-utils'

/**
 * Strictly-typed provider link as written by the drizzle adapters.
 * Mirrors `Identity.ProviderLink` from `core/types/identity` without
 * importing it (we only need the JSON-serializable surface).
 */
export interface DrizzleProviderLink {
  providerId: string
  providerSub?: string
  addedAt: number
}

/**
 * Parse the providers TEXT/JSON column into a guaranteed-typed array.
 * Returns `[]` on every malformed shape (null, non-array, primitive,
 * truncated JSON, SyntaxError). Per-entry validation: drops rows
 * missing `providerId` (required string) or with `providerSub` /
 * `addedAt` of wrong type. `addedAt` defaults to `0` ONLY when the
 * column is missing it on a legacy row - `isFiniteNumber` rejects
 * NaN / Infinity / strings.
 */
export function parseProviderLinks(raw: string | null | undefined): DrizzleProviderLink[] {
  if (typeof raw !== 'string' || raw.length === 0) return []
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return []
  }
  if (!Array.isArray(parsed)) return []
  const out: DrizzleProviderLink[] = []
  for (const entry of parsed) {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) continue
    const providerId: unknown = Reflect.get(entry, 'providerId')
    if (typeof providerId !== 'string' || providerId.length === 0) continue
    const providerSub: unknown = Reflect.get(entry, 'providerSub')
    if (providerSub !== undefined && typeof providerSub !== 'string') continue
    const addedAt: unknown = Reflect.get(entry, 'addedAt')
    // addedAt = 0 is legitimate (Date.UTC(1970) - corner case); only
    // reject non-finite / non-numeric. Missing field defaults to 0
    // so a legacy row that pre-dates the column population still loads.
    if (addedAt !== undefined && !isFiniteNumber(addedAt)) continue
    const link: DrizzleProviderLink = { providerId, addedAt: addedAt === undefined ? 0 : addedAt }
    if (providerSub !== undefined) link.providerSub = providerSub
    out.push(link)
  }
  return out
}

/**
 * Namespace merge for `ParseProviderLinks`. Co-locates the flat type exports
 * alongside the primary symbol via TS class+namespace merging.
 */
export namespace ParseProviderLinks {
  /** Alias for the flat `DrizzleProviderLink` type. */
  export type IDrizzleProviderLink = DrizzleProviderLink
}
