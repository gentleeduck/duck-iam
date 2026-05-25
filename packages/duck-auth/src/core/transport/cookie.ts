import type { Provider } from '../types/provider'
import type { Session } from '../types/session'
import type { Transport } from '../types/transport'

export interface CookieTransportConfig {
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
  /** Default 7d. Overridden by Session.absoluteExpiresAt at issue time. */
  maxAgeSec?: number
}

/**
 * Cookie transport — opaque session ID in an HttpOnly cookie. Default for web apps.
 * Verify is unset → caller must call Session.IStore.getByHash() to resolve.
 */
export class CookieTransport implements Transport.ITransport {
  private readonly _name: string
  private readonly _options: Transport.CookieOptions

  constructor(cfg: CookieTransportConfig = {}) {
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
    // __Host- prefix forbids Domain; refuse the combination.
    if (this._name.startsWith('__Host-') && cfg.domain) {
      throw new Error(
        '@gentleduck/auth CookieTransport: __Host- prefix forbids the Domain attribute. ' +
          'Either drop `domain` or override `name` to a non-__Host- value.',
      )
    }
  }

  extract(req: { headers: Headers }): string | null {
    const header = req.headers.get('cookie')
    if (!header) return null
    return parseCookie(header, this._name)
  }

  issue(session: Session.ISession, opts: Transport.IssueOpts): Provider.Intent[] {
    const expiresInMs = Math.max(0, session.expiresAt - Date.now())
    const maxAge = Math.min(this._options.maxAge ?? 0, Math.floor(expiresInMs / 1000))
    return [
      {
        type: 'setCookie',
        name: this._name,
        value: session.id,
        options: { ...this._options, maxAge },
      },
    ]
  }

  revoke(): Provider.Intent[] {
    return [
      {
        type: 'clearCookie',
        name: this._name,
        options: { ...this._options, maxAge: 0 },
      },
    ]
  }
}

function parseCookie(header: string, name: string): string | null {
  // Permissive parser; matches `name=value; …`. Production swap to a hardened
  // implementation if the request might contain RFC-edge cases.
  const pairs = header.split(';')
  for (const raw of pairs) {
    const eq = raw.indexOf('=')
    if (eq < 0) continue
    const k = raw.slice(0, eq).trim()
    if (k === name) return decodeURIComponent(raw.slice(eq + 1).trim())
  }
  return null
}
