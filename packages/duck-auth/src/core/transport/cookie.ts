import type { AuthProvider } from '../types/provider'
import type { AuthSession } from '../types/session'
import type { AuthTransport } from '../types/transport'

/**
 * Cookie transport - opaque session ID in an HttpOnly cookie. Default for web apps.
 * Verify is unset -> caller must call AuthSession.IStore.getByHash() to resolve.
 */
export class AuthCookieTransport implements AuthTransport.ITransport {
  private readonly _name: string
  private readonly _options: AuthTransport.CookieOptions

  constructor(cfg: AuthCookieTransport.IConfig = {}) {
    // Reject invalid cookie names early: RFC 6265 forbids CTL chars and the
    // separators below. Otherwise authSerializeCookie would emit a malformed
    // Set-Cookie that browsers silently drop, producing "session never sticks"
    // outages with no error surface.
    if (cfg.name !== undefined) {
      if (typeof cfg.name !== 'string' || cfg.name.length === 0 || cfg.name.length > 256) {
        throw new Error('@gentleduck/auth AuthCookieTransport: name must be a non-empty string <=256 chars')
      }
      // RFC 6265 token: alphanumerics + small set of safe punctuation. `-` is
      // allowed (the default `duck-sid`).
      if (!/^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(cfg.name)) {
        throw new Error('@gentleduck/auth AuthCookieTransport: name contains an RFC 6265-forbidden character')
      }
    }
    const hasDomain = Boolean(cfg.domain)
    this._name = cfg.name ?? (hasDomain ? 'duck-sid' : '__Host-duck-sid')
    this._options = {
      httpOnly: true,
      secure: cfg.secure ?? true,
      sameSite: cfg.sameSite ?? 'lax',
      path: cfg.path ?? '/',
      maxAge: (cfg.maxAgeSec ?? 7 * 24 * 60 * 60) * 1,
    }
    if (cfg.domain) this._options.domain = cfg.domain
    // Fail-fast on __Host- violations; browsers silently drop them.
    if (this._name.startsWith('__Host-')) {
      if (cfg.domain) {
        throw new Error(
          '@gentleduck/auth AuthCookieTransport: __Host- prefix forbids the Domain attribute. ' +
            'Either drop `domain` or override `name` to a non-__Host- value.',
        )
      }
      if (this._options.path !== '/') {
        throw new Error(
          `@gentleduck/auth AuthCookieTransport: __Host- prefix requires Path=/. Got Path=${this._options.path}.`,
        )
      }
      if (this._options.secure !== true) {
        throw new Error(
          '@gentleduck/auth AuthCookieTransport: __Host- prefix requires Secure=true. ' +
            'Either set { secure: true } (production) or override `name` to a non-__Host- value.',
        )
      }
    }
  }

  /**
   * Diagnostic getter consumed by `AuthEngine.strict()` to assert that
   * production deployments have `secure: true`. Read-only.
   */
  get secure(): boolean {
    return this._options.secure === true
  }

  /**
   * Diagnostic getter exposing the cookie name (e.g. `__Host-duck-sid`).
   * Read-only; used by tests + framework adapters that need to render the
   * name in user-facing output.
   */
  get cookieName(): string {
    return this._name
  }

  extract(req: { headers: Headers }): string | null {
    const header = req.headers.get('cookie')
    if (!header) return null
    return parseCookie(header, this._name)
  }

  issue(sid: string, session: AuthSession.ISession, opts: AuthTransport.IssueOpts): AuthProvider.Intent[] {
    const expiresInMs = Math.max(0, session.expiresAt - Date.now())
    const maxAge = Math.min(this._options.maxAge ?? 0, Math.floor(expiresInMs / 1000))
    const intents: AuthProvider.Intent[] = [
      {
        type: 'setCookie',
        name: this._name,
        value: sid,
        options: { ...this._options, maxAge },
      },
    ]
    // Emit `__Host-duck-csrf` for JS to read back as the `x-csrf-token`
    // header. httpOnly:false is intentional; the hash lives on the row.
    if (opts.csrfToken !== undefined) {
      intents.push({
        type: 'setCookie',
        name: '__Host-duck-csrf',
        value: opts.csrfToken,
        options: {
          httpOnly: false,
          secure: true,
          sameSite: 'lax',
          path: '/',
          maxAge,
        },
      })
    }
    return intents
  }

  revoke(): AuthProvider.Intent[] {
    return [
      {
        type: 'clearCookie',
        name: this._name,
        options: { ...this._options, maxAge: 0 },
      },
      {
        type: 'clearCookie',
        name: '__Host-duck-csrf',
        options: { httpOnly: false, secure: true, sameSite: 'lax', path: '/', maxAge: 0 },
      },
    ]
  }
}

/** SEC: per-value length cap. A real opaque SID is 64 hex chars; JWTs
 * commonly run a few hundred. 1024 is generous. Without the cap, an
 * attacker who can fit a large cookie under the HTTP-server header
 * limit (typically 8-16k) can still force `decodeURIComponent` + a
 * downstream `sha256` over the whole blob per request. Reject early. */
const COOKIE_VALUE_MAX = 1024

function parseCookie(header: string, name: string): string | null {
  // Whole-header cap: browsers cap Cookie at ~8KB by default; servers may
  // accept more. Refuse outliers up-front so a multi-MB header cannot force
  // a giant string.split(';') allocation.
  if (header.length > 16384) return null
  // Reject ambiguous Cookie headers (path/domain shadowing) by failing
  // closed when more than one match for `name=` appears.
  const pairs = header.split(';')
  let found: string | null = null
  for (const raw of pairs) {
    const eq = raw.indexOf('=')
    if (eq < 0) continue
    const k = raw.slice(0, eq).trim()
    if (k !== name) continue
    if (found !== null) {
      // Duplicate - refuse to choose. Caller surfaces as missing-session.
      return null
    }
    const rawValue = raw.slice(eq + 1).trim()
    // cap value length BEFORE `decodeURIComponent` so an oversize
    // cookie cannot force a multi-KB decode-then-sha256 per request.
    if (rawValue.length > COOKIE_VALUE_MAX) return null
    // Catch URIError on malformed `%XX`; would otherwise crash the auth pipeline.
    try {
      found = decodeURIComponent(rawValue)
    } catch {
      return null
    }
  }
  return found
}

export namespace AuthCookieTransport {
  export interface IConfig {
    /**
     * Cookie name. Defaults to `__Host-duck-sid` when no `domain` is set
     * (browser enforces Secure + Path=/ + no Domain), else `duck-sid`.
     */
    name?: string
    /** Set only for cross-subdomain deployments. Forbidden together with `__Host-` prefix. */
    domain?: string
    path?: string
    /** Must be true in production; strict() rejects false. */
    secure?: boolean
    sameSite?: 'strict' | 'lax' | 'none'
    /** Default 7d. Overridden by AuthSession.absoluteExpiresAt at issue time. */
    maxAgeSec?: number
  }
}
