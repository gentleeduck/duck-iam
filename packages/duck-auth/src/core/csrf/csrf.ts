import { orNull } from '../answer'
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

/** Non-mutating, so exempt from the check. */
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE'])

/** The plaintext goes to the cookie, the hash onto the session row. */
export function issueCsrfToken(): { token: string; hash: string } {
  const token = randomToken(32)
  return { token, hash: sha256(token) }
}

/** The double-submit cookie carrying the plaintext token, built for the transport's cookie settings. */
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
      // WARN: must stay readable by JS, which is what stitches it onto the `x-csrf-token` header.
      httpOnly: false,
      secure: true,
      sameSite: 'lax',
      path: '/',
    },
  }
}

/** Throws `AUTH_CSRF` on failure. A safe method passes through unchecked; a Bearer/DPoP request skips
 *  the double-submit token but is still held to the origin checks. */
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

  const cfg = { ...AUTH_DEFAULT_CSRF_CONFIG, ...(opts.cfg ?? {}) }

  // Read off the headers when the caller did not say, since this function documents the exemption as its
  // own and `csrfGuard` is not the only way in: a caller that already resolved the session calls straight
  // through, and refused every bearer client because nobody had told it.
  const isBearer = opts.isBearer ?? hasBearerAuthorization(opts.headers)

  // SECURITY: the bearer exemption reaches layer 1 only when the request carries no cookie. That is the
  // whole justification for it - a header credential is not ambient, so a browser cannot make the
  // request on the victim's behalf - and it stops being true the moment a cookie rides along.
  if (isBearer && !opts.headers.get('cookie')) return

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

  if (isBearer) return

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

/** A `,` disqualifies it, matching `BearerTransport.extract`. */
function hasBearerAuthorization(headers: Headers): boolean {
  const raw = headers.get('authorization')
  if (!raw) return false
  if (raw.includes(',')) return false
  const SCHEME = 'bearer '
  const head = raw.slice(0, SCHEME.length)
  return head.toLowerCase() === SCHEME
}

/** Resolves the session, then runs {@link verifyCsrf} over it. Structural for the same reason
 *  `Actor.Resolvable` is, and a plain `Promise` for the same reason too. */
export async function csrfGuard(
  auth: {
    resolveSession(
      req: { headers: Headers },
      opts?: { expectedTenantId?: string },
    ): Promise<{
      session: { csrfHash?: string | null }
      identity: unknown
    }>
  },
  req: { method: string; headers: Headers },
  opts: Csrf.GuardOptions = {},
): Promise<void> {
  if (SAFE_METHODS.has(req.method.toUpperCase())) return
  // Bearer and JWT carry auth in a header rather than an ambient cookie, so the double-submit token is
  // pointless for them. `verifyCsrf` decides how far that exemption reaches; the session still need not
  // be loaded to find out.
  if (opts.isBearer || hasBearerAuthorization(req.headers)) {
    verifyCsrf({
      headers: req.headers,
      isBearer: true,
      method: req.method,
      ...(opts.cfg !== undefined && { cfg: opts.cfg }),
    })
    return
  }
  // An unauthenticated request still gets the double-submit check below, against the cookie alone.
  const resolved = await orNull(
    auth.resolveSession(
      req,
      opts.expectedTenantId !== undefined ? { expectedTenantId: opts.expectedTenantId } : undefined,
    ),
  )
  verifyCsrf({
    method: req.method,
    headers: req.headers,
    ...(resolved?.session.csrfHash != null && { sessionCsrfHash: resolved.session.csrfHash }),
    ...(opts.cfg !== undefined && { cfg: opts.cfg }),
  })
}

/** CSRF configuration: the cookie and header names, and which strategy verifies them. */
export namespace Csrf {
  export type Cfg = {
    /** Cookie name carrying the plaintext token. Default `__Host-duck-csrf`. */
    cookieName?: string
    /** Header name the client puts the token on. Default `x-csrf-token`. */
    headerName?: string
    /**
     * - `'double-submit'` (default): header, cookie and the session-stored hash must agree.
     * - `'origin-only'`: no token, Origin and Sec-Fetch-Site alone.
     *
     * SECURITY: `'origin-only'` is safe only for a transport with no ambient credential, since a cookie
     * rides along on a cross-site request whether or not the caller meant it to.
     */
    mode?: 'double-submit' | 'origin-only'
    /** Allowed Origin headers for cross-site checks. */
    allowedOrigins?: string[]
  }

  /** Options every server adapter's CSRF middleware forwards to {@link csrfGuard}. */
  export type GuardOptions = {
    /** Forces the bearer bypass on; otherwise it is read off the Authorization header. */
    isBearer?: boolean
    cfg?: Csrf.Cfg
    expectedTenantId?: string
  }
}
