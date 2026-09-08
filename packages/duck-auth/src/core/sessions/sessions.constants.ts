import type { Sessions } from './sessions.types'

export const DEFAULT_SESSION_CONFIG: Sessions.Cfg = {
  ttlMs: 7 * 24 * 60 * 60 * 1000,
  absoluteTtlMs: 30 * 24 * 60 * 60 * 1000,
  freshnessMs: 5 * 60 * 1000,
}

/**
 * Caps on the header-derived columns of a session row. A hostile header must not be able to
 * bloat the row, and these are what `SessionsImpl.create` truncates to.
 *
 * They are also the caps a caller fingerprint has to obey. `hijack.evaluate` compares the value
 * read off a later request against the value stored here, so anything that normalises a
 * fingerprint - `server/generic`'s `callerContext` - must truncate to the same lengths, or a
 * client with a long User-Agent reads as permanent drift on every single request.
 */
export const SESSION_COLUMN_CAPS = {
  /** `fingerprint`; matches the library's other opaque-identifier caps. */
  fingerprint: 256,
  /** `ip`; comfortably past an IPv6 address with a scope id. */
  ip: 64,
  /** `userAgent`. */
  userAgent: 512,
} as const
