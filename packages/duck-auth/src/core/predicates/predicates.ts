/** A JSON object and not an array, which `typeof v === 'object'` answers yes to on its own. */
export function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

export function isFiniteNumber(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v)
}

/** ISO string, epoch number or `Date` in, a usable `Date` or `null` out. Unparseable is `null`, not the
 *  `Invalid Date` that `new Date(value)` gives, which every guard accepts and every comparison rejects. */
export function storedDate(value: unknown): Date | null {
  if (value instanceof Date) return Number.isFinite(value.getTime()) ? value : null
  if (typeof value === 'string') {
    const parsed = new Date(value)
    return Number.isFinite(parsed.getTime()) ? parsed : null
  }
  return isFiniteNumber(value) ? new Date(value) : null
}

/** No expiry is not expired; anything unreadable is. */
export function isExpiredAt(timestampMs: unknown, now: number = Date.now()): boolean {
  if (timestampMs == null) return false
  if (timestampMs instanceof Date) {
    const t = timestampMs.getTime()
    return !Number.isFinite(t) || t < now
  }
  if (!isFiniteNumber(timestampMs)) return true
  return timestampMs < now
}

/** An empty string answers `undefined`, as a missing key does. */
export function getProfileString(profile: unknown, key: string): string | undefined {
  if (!isRecord(profile)) return undefined
  const value = profile[key]
  if (typeof value !== 'string' || value.length === 0) return undefined
  return value
}

/** NaN and Infinity answer `undefined`, as a missing key does. */
export function getProfileNumber(profile: unknown, key: string): number | undefined {
  if (!isRecord(profile)) return undefined
  const value = profile[key]
  return isFiniteNumber(value) ? value : undefined
}

/** Strictly `true`; a truthy value is not enough. */
export function isProfileBooleanTrue(profile: unknown, key: string): boolean {
  if (!isRecord(profile)) return false
  return profile[key] === true
}

/** Strictly `false`; an absent key is neither this nor {@link isProfileBooleanTrue}. */
export function isProfileBooleanFalse(profile: unknown, key: string): boolean {
  if (!isRecord(profile)) return false
  return profile[key] === false
}
