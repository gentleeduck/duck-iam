export function isFiniteNumber(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v)
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

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** An empty string answers `undefined`, as a missing key does. */
export function getProfileString(profile: unknown, key: string): string | undefined {
  if (!isPlainObject(profile)) return undefined
  const value = profile[key]
  if (typeof value !== 'string' || value.length === 0) return undefined
  return value
}

/** NaN and Infinity answer `undefined`, as a missing key does. */
export function getProfileNumber(profile: unknown, key: string): number | undefined {
  if (!isPlainObject(profile)) return undefined
  const value = profile[key]
  return isFiniteNumber(value) ? value : undefined
}

/** Strictly `true`; a truthy value is not enough. */
export function isProfileBooleanTrue(profile: unknown, key: string): boolean {
  if (!isPlainObject(profile)) return false
  return profile[key] === true
}

/** Strictly `false`; an absent key is neither this nor {@link isProfileBooleanTrue}. */
export function isProfileBooleanFalse(profile: unknown, key: string): boolean {
  if (!isPlainObject(profile)) return false
  return profile[key] === false
}
