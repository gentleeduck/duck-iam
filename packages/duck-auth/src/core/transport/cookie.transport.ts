import { isProduction } from '~/core/env'
import { AuthError } from '~/core/errors'
import type { Provider } from '../provider/provider.types'
import type { Sessions } from '../sessions/sessions.types'
import type { Transport } from './transport.types'

export namespace CookieTransport {
  /** The session cookie's name and attributes. */
  export interface Cfg {
    /** `__Host-duck-sid` when no `domain` is set, which is the prefix browsers enforce Secure, `Path=/`
     *  and no Domain for; `duck-sid` otherwise. Outside production the prefix is dropped with Secure. */
    name?: string
    /** For cross-subdomain deployments only, and forbidden alongside the `__Host-` prefix. */
    domain?: string
    /** Default `/`, which the `__Host-` prefix requires. */
    path?: string
    /** Default `'lax'`. `'none'` keeps the cookie Secure in every environment. */
    sameSite?: 'strict' | 'lax' | 'none'
    /** A positive whole number of seconds, to end the cookie before the session does. Unset, it lives to
     *  `Sessions.Me.absoluteExpiresAt`, so a session `resolveSession` slides keeps its cookie; the idle
     *  deadline is server-side, in `isSessionExpired`. */
    maxAgeSec?: number
  }
}

/** An opaque session id in an HttpOnly cookie, the default for web apps. `verify` is unset, so the
 *  caller resolves the id through `Sessions.Store.getByHash()`. */
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
      // RFC 6265 token: alphanumerics and a small set of safe punctuation, `-` and `_` included, as the
      // default `__Host-duck-sid` needs.
      if (!/^[A-Za-z0-9!#$%&'*+\-.^_`|~]+$/.test(cfg.name)) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: '@gentleduck/auth CookieTransport: name contains an RFC 6265-forbidden character',
        })
      }
    }
    // Max-Age 0 or below deletes the cookie on arrival; a fraction or NaN is ignored, leaving a browser-session cookie.
    if (cfg.maxAgeSec !== undefined && (!Number.isSafeInteger(cfg.maxAgeSec) || cfg.maxAgeSec <= 0)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: '@gentleduck/auth CookieTransport: maxAgeSec must be a positive whole number of seconds',
      })
    }
    // RFC 6265 5.2.4 and 5.3: a Path not starting with `/` becomes the sign-in route's own directory, and a
    // Domain the host cannot match, one carrying a scheme or a port, drops the cookie. Neither says so.
    if (cfg.path !== undefined && !/^\/[\x20-\x3a\x3c-\x7e]*$/.test(cfg.path)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `@gentleduck/auth CookieTransport: path must start with / (got ${JSON.stringify(cfg.path)})`,
      })
    }
    if (cfg.domain && !/^\.?[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*$/.test(cfg.domain)) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `@gentleduck/auth CookieTransport: domain must be a bare host, no scheme or port (got ${JSON.stringify(cfg.domain)})`,
      })
    }
    const hasDomain = Boolean(cfg.domain)
    const path = cfg.path ?? '/'
    const sameSite = cfg.sameSite ?? 'lax'
    const named = cfg.name ?? (hasDomain ? 'duck-sid' : '__Host-duck-sid')
    // Fail-fast on __Host- violations, in every environment; browsers silently drop them.
    if (named.startsWith('__Host-')) {
      if (cfg.domain) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail:
            '@gentleduck/auth CookieTransport: __Host- prefix forbids the Domain attribute. ' +
            'Either drop `domain` or override `name` to a non-__Host- value.',
        })
      }
      if (path !== '/') {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: `@gentleduck/auth CookieTransport: __Host- prefix requires Path=/. Got Path=${path}.`,
        })
      }
    }
    const { name, secure } = cookieSecurity(named, sameSite)
    this._name = name
    this._options = { httpOnly: true, secure, sameSite, path }
    if (cfg.maxAgeSec !== undefined) this._options.maxAge = cfg.maxAgeSec
    if (cfg.domain) this._options.domain = cfg.domain
    // SECURITY: the companion follows the session cookie's own attributes rather than a fixed shape.
    // Hardcoding them left a CSRF cookie the page could not read on every cross-subdomain, cross-site or
    // scoped deployment, and refused every state-changing request `AUTH_CSRF` with nothing said. The
    // `__Host-` prefix goes exactly when its three conditions do.
    this._csrfName = cookieSecurity(path === '/' && !hasDomain ? '__Host-duck-csrf' : 'duck-csrf', sameSite).name
    this._csrfOptions = { ...this._options, httpOnly: false }
  }

  /** The companion CSRF cookie's name, which drops the `__Host-` prefix when the transport's own settings
   *  forbid it, and so the name a page reads the token by. */
  get csrfCookieName(): string {
    return this._csrfName
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

  /** Sets the session cookie, capped by the session's absolute deadline, plus the CSRF companion. */
  issue(sid: string, session: Sessions.Me, opts: Transport.IssueOpts): Provider.Intent[] {
    const liveSec = Math.floor(Math.max(0, session.absoluteExpiresAt.getTime() - Date.now()) / 1000)
    const maxAge = Math.min(this._options.maxAge ?? liveSec, liveSec)
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

/** The name and Secure flag a cookie is set with: Secure in production, and under `SameSite=None`, which a
 *  browser drops without it. Otherwise the cookie is not Secure, so a `__Host-` or `__Secure-` prefix, which
 *  requires it, is dropped from the name. */
export function cookieSecurity(name: string, sameSite: 'strict' | 'lax' | 'none'): { name: string; secure: boolean } {
  const secure = sameSite === 'none' || isProduction()
  return { name: secure ? name : name.replace(/^__(?:Host|Secure)-/i, ''), secure }
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
