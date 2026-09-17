import { AuthError } from '../errors'
import { AUTH_SESSION_KINDS, type Sessions } from './sessions.types'

export const DEFAULT_SESSION_CONFIG: Sessions.Cfg = {
  ttlMs: 7 * 24 * 60 * 60 * 1000,
  absoluteTtlMs: 30 * 24 * 60 * 60 * 1000,
  freshnessMs: 5 * 60 * 1000,
}

/** `SessionsImpl.create` truncates to these. Anything that normalises a fingerprint must use the same
 *  lengths, or `hijack.evaluate` reads a long User-Agent as permanent drift on every request. */
export const SESSION_COLUMN_CAPS = {
  fingerprint: 256,
  /** Comfortably past an IPv6 address with a scope id. */
  ip: 64,
  userAgent: 512,
} as const

/**
 * The session rules every dialect carries as table constraints, applied by the stores that have no schema
 * to carry them. Redis needs them most: its reader rejects an unknown `kind` and an out-of-range `aal`, so
 * a write that skipped these was stored and then never readable again.
 */
export function assertSessionAllowed(
  s: Pick<Sessions.Me, 'aal' | 'kind' | 'id' | 'createdAt' | 'expiresAt' | 'absoluteExpiresAt' | 'rotatedAt'> & {
    tenantId?: string | null
  },
): void {
  if (!AUTH_SESSION_KINDS.includes(s.kind)) {
    throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: `unknown session kind: ${s.kind}` })
  }
  if (s.aal !== 1 && s.aal !== 2 && s.aal !== 3) {
    throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: `aal out of range: ${s.aal}` })
  }
  if (s.tenantId === '') {
    throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'tenant is blank' })
  }
  // SECURITY: the id is a sha256 of the token in hex, and every dialect pins its width. Shorter is a raw
  // token, or a caller that skipped the hash, being used as the primary key.
  if (s.id.length !== 64) {
    throw new AuthError('AUTH_INVALID_PARAMETERS', {
      detail: `session id must be a 64-character hash, got ${s.id.length}`,
    })
  }
  // A stamp that is not a Date compares as NaN and so passes every test below: the reader's deadline gate
  // already fails closed on one, and refusing it here would turn a malformed row into a write error on a
  // path that has no way to report which store produced it.
  const at = (d: unknown): number => (d instanceof Date ? d.getTime() : Number.NaN)
  if (at(s.expiresAt) < at(s.createdAt)) {
    throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'expiresAt precedes createdAt' })
  }
  if (at(s.rotatedAt) < at(s.createdAt)) {
    throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'rotatedAt precedes createdAt' })
  }
  // The absolute cap is what forces re-auth; below the rolling expiry it caps nothing the refresh has not
  // already passed, and the row is one every dialect refuses to store.
  if (at(s.absoluteExpiresAt) < at(s.expiresAt)) {
    throw new AuthError('AUTH_INVALID_PARAMETERS', { detail: 'absoluteExpiresAt precedes expiresAt' })
  }
}
