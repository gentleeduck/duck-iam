/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { randomToken, sha256, timingSafeEqual } from './crypto'
import { AuthErrorObject } from './errors'

/**
 * CSRF protection - DESIGN section 39.
 *
 * Defense-in-depth layered on top of `Origin` + `Sec-Fetch-Site` checks,
 * not the only line. Apps using Bearer transport + DPoP can disable the
 * cookie token via `mode: 'origin-only'`.
 *
 * Token lifecycle
 *   - Issued at session create + every rotation
 *   - Hashed at rest (sha256) in `session.csrfHash`; plaintext lives in a
 *     non-HttpOnly cookie (`__Host-duck-csrf` by default) so JS can read it
 *     and stitch it onto the `X-CSRF-Token` header
 *   - NOT rotated per-request (breaks back-button + multi-tab)
 *
 * Validation discipline
 *   - Mutating requests (POST/PUT/PATCH/DELETE) require the header to match
 *     the session's stored hash. Constant-time compare.
 *   - OPTIONS/GET/HEAD exempt by definition
 *   - Bearer/DPoP requests exempt (no ambient credential)
 *   - Origin/Sec-Fetch-Site check runs FIRST; CSRF token is the secondary line
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface CsrfConfig {
  /** Cookie name carrying the plaintext token. Default `__Host-duck-csrf`. */
  cookieName?: string
  /** Header name the client puts the token on. Default `x-csrf-token`. */
  headerName?: string
  /**
   * 'double-submit' - header + cookie + session-stored hash (default).
   * 'origin-only'   - skip the token, rely on Origin/Sec-Fetch-Site only
   *                   (only safe for Bearer/DPoP transports with no ambient
   *                   credential).
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  mode?: 'double-submit' | 'origin-only'
  /** Allowed Origin headers for cross-site checks. */
  allowedOrigins?: string[]
}

export const DEFAULT_CSRF_CONFIG: Required<Omit<CsrfConfig, 'allowedOrigins'>> & {
  allowedOrigins: string[]
} = {
  cookieName: '__Host-duck-csrf',
  headerName: 'x-csrf-token',
  mode: 'double-submit',
  allowedOrigins: [],
}

/** Methods that don't mutate state - exempt from CSRF validation. */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE'])

/** Generate a CSRF token + its hash (for session storage). */
export function issueCsrfToken(): { token: string; hash: string } {
  const token = randomToken(32)
  return { token, hash: sha256(token) }
}

/** Build a Set-Cookie intent body for the CSRF cookie. */
export function buildCsrfCookieOptions(
  token: string,
  cfg: CsrfConfig = {},
): {
  name: string
  value: string
  options: {
    httpOnly: boolean
    secure: boolean
    sameSite: 'lax' | 'strict' | 'none'
    path: string
  }
} {
  return {
    name: cfg.cookieName ?? DEFAULT_CSRF_CONFIG.cookieName,
    value: token,
    options: {
      // MUST be readable by JS to stitch onto X-CSRF-Token header.
      httpOnly: false,
      secure: true,
      sameSite: 'lax',
      path: '/',
    },
  }
}

/**
 * Verify a request meets CSRF requirements. Throws AUTH/CSRF on failure.
 * Pass `sessionCsrfHash` from the resolved session; safe-method requests
 * + Bearer/DPoP requests pass through without validation.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function verifyCsrf(opts: {
  method: string
  headers: Headers
  sessionCsrfHash?: string
  cfg?: CsrfConfig
  /** True when the request authenticated via a non-ambient bearer (header, JWT, DPoP). */
  isBearer?: boolean
}): void {
  const method = opts.method.toUpperCase()
  if (SAFE_METHODS.has(method)) return
  if (opts.isBearer) return

  const cfg = { ...DEFAULT_CSRF_CONFIG, ...(opts.cfg ?? {}) }

  // Layer 1: Origin / Sec-Fetch-Site.
  const sfs = opts.headers.get('sec-fetch-site')
  if (sfs && sfs !== 'same-origin' && sfs !== 'same-site' && sfs !== 'none') {
    throw new AuthErrorObject('AUTH/CSRF')
  }
  if (cfg.allowedOrigins.length > 0) {
    const origin = opts.headers.get('origin')
    if (!origin || !cfg.allowedOrigins.includes(origin)) {
      throw new AuthErrorObject('AUTH/CSRF')
    }
  }

  if (cfg.mode === 'origin-only') return

  // Layer 2: double-submit token.
  const headerToken = opts.headers.get(cfg.headerName)
  if (!headerToken || !opts.sessionCsrfHash) {
    throw new AuthErrorObject('AUTH/CSRF')
  }
  const headerHash = sha256(headerToken)
  if (!timingSafeEqual(headerHash, opts.sessionCsrfHash)) {
    throw new AuthErrorObject('AUTH/CSRF')
  }
}
