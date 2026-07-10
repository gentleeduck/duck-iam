import { randomToken, sha256, timingSafeEqual } from '../crypto'
import { AuthError } from '../errors'

export const AUTH_DEFAULT_CSRF_CONFIG: Required<Omit<Csrf.Cfg, 'allowedOrigins'>> & {
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
  cfg: Csrf.Cfg = {},
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
    name: cfg.cookieName ?? AUTH_DEFAULT_CSRF_CONFIG.cookieName,
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
 */
export function verifyCsrf(opts: {
  method: string
  headers: Headers
  sessionCsrfHash?: string
  cfg?: Csrf.Cfg
  /** True when the request authenticated via a non-ambient bearer (header, JWT, DPoP). */
  isBearer?: boolean
}): void {
  const method = opts.method.toUpperCase()
  if (SAFE_METHODS.has(method)) return
  if (opts.isBearer) return

  const cfg = { ...AUTH_DEFAULT_CSRF_CONFIG, ...(opts.cfg ?? {}) }

  // Layer 1: Origin / Sec-Fetch-Site.
  const sfs = opts.headers.get('sec-fetch-site')
  if (sfs && sfs !== 'same-origin' && sfs !== 'same-site' && sfs !== 'none') {
    throw new AuthError('AUTH_CSRF')
  }
  if (cfg.allowedOrigins.length > 0) {
    const origin = opts.headers.get('origin')
    if (!origin || !cfg.allowedOrigins.includes(origin)) {
      throw new AuthError('AUTH_CSRF')
    }
  } else if (cfg.mode === 'origin-only' && (sfs === 'none' || sfs === null)) {
    // origin-only mode without an Origin allowlist has no defense for
    // direct navigations or stripped headers; refuse rather than fail-open.
    throw new AuthError('AUTH_CSRF')
  }

  if (cfg.mode === 'origin-only') return

  // Layer 2: double-submit token. Skip when no session exists yet
  // (signin / signup-begin); Layer 1's same-origin gate covers those.
  if (opts.sessionCsrfHash === undefined) return
  const headerToken = opts.headers.get(cfg.headerName)
  if (!headerToken) {
    throw new AuthError('AUTH_CSRF')
  }
  // Cap supplied token length before hashing so a multi-MB header
  // cannot DoS via sha256 amplification.
  if (headerToken.length > CSRF_TOKEN_MAX) {
    throw new AuthError('AUTH_CSRF')
  }
  const headerHash = sha256(headerToken)
  if (!timingSafeEqual(headerHash, opts.sessionCsrfHash)) {
    throw new AuthError('AUTH_CSRF')
  }
}

const CSRF_TOKEN_MAX = 256

/** True for an `Authorization: Bearer ...` header without `,` (matches `BearerTransport.extract`). */
function hasBearerAuthorization(headers: Headers): boolean {
  const raw = headers.get('authorization')
  if (!raw) return false
  if (raw.includes(',')) return false
  const SCHEME = 'bearer '
  const head = raw.slice(0, SCHEME.length)
  return head.toLowerCase() === SCHEME
}

/** Framework-adapter guard: resolves session + verifies CSRF; throws `AUTH/CSRF` on miss. Safe methods + bearer pass through. */
export async function csrfGuard(
  auth: {
    resolveSession(
      req: { headers: Headers },
      opts?: { expectedTenantId?: string },
    ): Promise<{
      session: { csrfHash?: string | null }
      identity: unknown
    } | null>
  },
  req: { method: string; headers: Headers },
  opts: { isBearer?: boolean; cfg?: Csrf.Cfg; expectedTenantId?: string } = {},
): Promise<void> {
  if (SAFE_METHODS.has(req.method.toUpperCase())) return
  // Bearer / JWT transports carry auth in the Authorization header,
  // not an ambient cookie, so browsers cannot CSRF them.
  if (opts.isBearer || hasBearerAuthorization(req.headers)) return
  const resolved = await auth.resolveSession(
    req,
    opts.expectedTenantId !== undefined ? { expectedTenantId: opts.expectedTenantId } : undefined,
  )
  verifyCsrf({
    method: req.method,
    headers: req.headers,
    ...(resolved?.session.csrfHash != null && { sessionCsrfHash: resolved.session.csrfHash }),
    ...(opts.cfg !== undefined && { cfg: opts.cfg }),
  })
}

export namespace Csrf {
  export type Cfg = {
    /** Cookie name carrying the plaintext token. Default `__Host-duck-csrf`. */
    cookieName?: string
    /** Header name the client puts the token on. Default `x-csrf-token`. */
    headerName?: string
    /**
     * 'double-submit' - header + cookie + session-stored hash (default).
     * 'origin-only'   - skip the token, rely on Origin/Sec-Fetch-Site only
     *                   (only safe for Bearer/DPoP transports with no ambient
     *                   credential).
     */
    mode?: 'double-submit' | 'origin-only'
    /** Allowed Origin headers for cross-site checks. */
    allowedOrigins?: string[]
  }
}
