import { randomBytes } from 'node:crypto'

/** Bounds and helpers for webhook delivery. */

/** RFC 7230 token: what `fetch` will accept as a header name. */
export const HEADER_TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/

export const MAX_ATTEMPTS = 20
export const BACKOFF_DEFAULT_MS = 500
/**
 * An hour between two attempts is already past any retry policy that means to deliver, and a base
 * larger than this doubles into the range where `setTimeout` treats the wait as zero, so the
 * longest configured delay would behave as the shortest.
 */
export const BACKOFF_BASE_MAX_MS = 3_600_000
/** `setTimeout` treats anything past 2^31-1 as zero. */
export const BACKOFF_MAX_MS = 2 ** 31 - 1
export const TIMEOUT_DEFAULT_MS = 5_000
export const PAYLOAD_MAX_BYTES = 1_048_576
export const TOLERANCE_DEFAULT_MS = 5 * 60_000

/** Keys whose value is a credential wherever it appears. Matched case-insensitively, as a substring. */
export function sanitiseEndpointUrl(rawUrl: string): string {
  try {
    const parsed = new URL(rawUrl)
    return `${parsed.origin}${parsed.pathname}`
  } catch {
    return rawUrl
  }
}

/**
 * A float in [0, 1). Drawn from the CSPRNG because `Math.random` is refused everywhere under
 * `core/`, and a jitter source is not worth an exception to that rule.
 */
export function jitterSource(): number {
  return randomBytes(4).readUInt32BE(0) / 2 ** 32
}

/**
 * Exponential backoff, capped, with jitter over the lower half of the interval.
 *
 * Without the jitter every instance that saw the same failure retries in the same millisecond, so
 * a consumer coming back up is hit by the whole fleet at once and goes down again.
 */
export function backoffFor(baseMs: number, attempt: number, random: () => number = jitterSource): number {
  const ceiling = Math.min(baseMs * 2 ** (attempt - 1), BACKOFF_MAX_MS)
  return Math.floor(ceiling / 2 + random() * (ceiling / 2))
}
