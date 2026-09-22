import { AuthError } from '~/core/errors'
import type { Provider } from '../provider/provider.types'
import type { Sessions } from '../sessions/sessions.types'
import type { Transport } from '../transport/transport.types'

export namespace CookieTransport {
  export interface Cfg {
    /** `__Host-duck-sid` when no `domain` is set, which is the prefix browsers enforce Secure, `Path=/`
     *  and no Domain for; `duck-sid` otherwise. */
    name?: string
    /** For cross-subdomain deployments only, and forbidden alongside the `__Host-` prefix. */
    domain?: string
    path?: string
    /** `strict()` rejects `false` in production. The CSRF companion follows it, and drops its `__Host-`
     *  prefix along with it, since the prefix is what requires Secure. */
    secure?: boolean
    sameSite?: 'strict' | 'lax' | 'none'
    /** Default 7d, capped at issue time by `Sessions.Me.expiresAt` - the sliding deadline, which each
     *  rotation reissues the cookie against. The absolute cap is server-side, in `isSessionExpired`. */
    maxAgeSec?: number
  }
}

/** An opaque session id in an HttpOnly cookie, the default for web apps. `verify` is unset, so the
 *  caller resolves the id through `Session.IStore.getByHash()`. */
export class CookieTransport implements Transport.ITransport {
  private readonly _name: string
  private readonly _options: Transport.CookieOptions
  private readonly _csrfName: string
  private readonly _csrfOptions: Transport.CookieOptions

  constructor(cfg: CookieTransport.Cfg = {}) {
    // RFC 6265 forbids CTL chars and the separators below. Left to `serializeCookie`, a bad name emits a
    // malformed Set-Cookie that browsers silently drop: a "session never sticks" outage with no error.
    if (cfg.name !== undefined) {
      if (typeof cfg.name !== 'string' || cfg.name.length === 0 || cfg.name.length > 256) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: '@gentleduck/auth CookieTransport: name must be a non-empty string <=256 chars',
        })
      }
      // RFC 6265 token: alphanumerics and a small set of safe punctuation, `-` included, as the default
      // `duck-sid` needs.
      if (!/^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(cfg.name)) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: '@gentleduck/auth CookieTransport: name contains an RFC 6265-forbidden character',
        })
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
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail:
            '@gentleduck/auth CookieTransport: __Host- prefix forbids the Domain attribute. ' +
            'Either drop `domain` or override `name` to a non-__Host- value.',
        })
      }
      if (this._options.path !== '/') {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `@gentleduck/auth CookieTransport: __Host- prefix requires Path=/. Got Path=${this._options.path}.`,
        })
      }
      if (this._options.secure !== true) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail:
            '@gentleduck/auth CookieTransport: __Host- prefix requires Secure=true. ' +
            'Either set { secure: true } (production) or override `name` to a non-__Host- value.',
        })
      }
    }
    // SECURITY: the companion is scoped to the session cookie rather than to a fixed shape, and every one
    // of these attributes was hardcoded. Measured: `{ domain: '.example.com' }` - the option that exists
    // for cross-subdomain deployments, and the one the checks above validate - emitted the session cookie
    // for the whole domain and a `__Host-` CSRF cookie for the issuing host alone, so a page on a sibling
    // subdomain could not read the token, could not put it on `x-csrf-token`, and had every state-changing
    // request refused `AUTH_CSRF` with nothing said. `sameSite: 'none'` sent the session cookie cross-site
    // and held the companion back; `path: '/app'` scoped the session down and left the token readable at
    // `/`. The prefix goes exactly when its three conditions do, which is also what had a `secure: false`
    // dev deployment dropping the cookie rather than renaming it.
    const hostPrefixOk = this._options.secure === true && this._options.path === '/' && !hasDomain
    this._csrfName = hostPrefixOk ? '__Host-duck-csrf' : 'duck-csrf'
    this._csrfOptions = { ...this._options, httpOnly: false }
  }

  /** The companion CSRF cookie's name, which drops the `__Host-` prefix when the transport's own settings
   *  forbid it. This is what a client passes as `csrfCookieName`. */
  get csrfCookieName(): string {
    return this._csrfName
  }

  /** Read by `AuthEngine.strict()` to assert a production deployment set `secure: true`. */
  get secure(): boolean {
    return this._options.secure === true
  }

  /** For tests, and for a framework adapter that renders the name in user-facing output. */
  get cookieName(): string {
    return this._name
  }

  /** The session id out of the `Cookie` header, or `null` when it is absent or ambiguous. */
  extract(req: { headers: Headers }): string | null {
    const header = req.headers.get('cookie')
    if (!header) return null
    return parseCookie(header, this._name)
  }

  /** Sets the session cookie, capped by the session's own deadline, plus the CSRF companion. */
  issue(sid: string, session: Sessions.Me, opts: Transport.IssueOpts): Provider.Intent[] {
    const expiresInMs = Math.max(0, session.expiresAt.getTime() - Date.now())
    const maxAge = Math.min(this._options.maxAge ?? 0, Math.floor(expiresInMs / 1000))
    const intents: Provider.Intent[] = [
      {
        type: 'setCookie',
        name: this._name,
        value: sid,
        options: { ...this._options, maxAge },
      },
    ]
    // For JS to read back as the `x-csrf-token` header. `httpOnly` is the one attribute that deliberately
    // differs from the session cookie: the hash lives on the row.
    if (opts.csrfToken !== undefined) {
      intents.push({
        type: 'setCookie',
        name: this._csrfName,
        value: opts.csrfToken,
        options: { ...this._csrfOptions, maxAge },
      })
    }
    return intents
  }

  /** Clears both cookies it sets. */
  revoke(): Provider.Intent[] {
    return [
      {
        type: 'clearCookie',
        name: this._name,
        options: { ...this._options, maxAge: 0 },
      },
      {
        // The attributes it was set with: a clear that does not match on path or domain leaves the cookie
        // in the browser.
        type: 'clearCookie',
        name: this._csrfName,
        options: { ...this._csrfOptions, maxAge: 0 },
      },
    ]
  }
}

/** A real opaque SID is 64 hex chars and a JWT a few hundred, so 1024 is generous.
 *  SECURITY: without the cap, a large cookie that still fits under the HTTP server's 8-16k header limit
 *  forces a `decodeURIComponent` and a `sha256` over the whole blob on every request. */
const COOKIE_VALUE_MAX = 1024

/** One cookie's value out of a `Cookie` header, or `null` when absent. */
export function parseCookie(header: string, name: string): string | null {
  // Browsers cap Cookie at ~8KB and servers may accept more, so an outlier is refused up front: a
  // multi-MB header would otherwise force a giant `string.split(';')` allocation.
  if (header.length > 16384) return null
  // Ambiguous headers, from path or domain shadowing, fail closed: more than one match for `name=` is
  // refused rather than picked between.
  const pairs = header.split(';')
  let found: string | null = null
  for (const raw of pairs) {
    const eq = raw.indexOf('=')
    if (eq < 0) continue
    const k = raw.slice(0, eq).trim()
    if (k !== name) continue
    if (found !== null) {
      // A duplicate is refused rather than chosen between; the caller surfaces it as a missing session.
      return null
    }
    const rawValue = raw.slice(eq + 1).trim()
    // Capped before `decodeURIComponent`, so an oversize cookie cannot force a multi-KB decode and
    // sha256 on every request.
    if (rawValue.length > COOKIE_VALUE_MAX) return null
    // A malformed `%XX` raises URIError, which would otherwise crash the auth pipeline.
    try {
      found = decodeURIComponent(rawValue)
    } catch {
      return null
    }
  }
  return found
}

/** Constructs a {@link CookieTransport}. */
export function cookieTransport(cfg: CookieTransport.Cfg = {}): CookieTransport {
  return new CookieTransport(cfg)
}
