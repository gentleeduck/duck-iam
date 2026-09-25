import { AuthError } from '../errors'
import type { Provider } from '../provider/provider.types'
import type { Sessions } from '../sessions/sessions.types'
import type { Transport } from '../transport/transport.types'

export namespace BearerTransport {
  export type Cfg = {
    /** Default `Authorization`. */
    header?: string
    /** Whitespace-separated from the token. Default `Bearer`. */
    scheme?: string
  }
}

/** An `Authorization: Bearer <opaque>` header, for native, mobile and API-key callers. Issue answers a
 *  JSON intent carrying the token, and persisting it is the client's job. */
export class BearerTransport implements Transport.ITransport {
  private readonly _header: string
  private readonly _scheme: string

  constructor(cfg: BearerTransport.Cfg = {}) {
    this._header = cfg.header ?? 'authorization'
    this._scheme = cfg.scheme ?? 'Bearer'
    // A blank scheme makes the prefix a single space, and `Headers` strips leading whitespace from a
    // value, so nothing could ever match it: the transport extracts nothing, forever, and inside a
    // composite that is indistinguishable from the credential not having been presented.
    if (this._scheme.trim() === '' || this._scheme !== this._scheme.trim()) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `@gentleduck/auth BearerTransport: scheme must be non-blank and carry no surrounding whitespace (got ${JSON.stringify(cfg.scheme)})`,
      })
    }
    if (this._header.trim() === '') {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: '@gentleduck/auth BearerTransport: header must be a non-blank header name',
      })
    }
  }

  /** The token out of the configured header, or `null` when the scheme does not match. */
  extract(req: { headers: Headers }): string | null {
    const raw = req.headers.get(this._header)
    if (!raw) return null
    // Case-insensitive scheme match (RFC 7235 2.1).
    const schemePrefix = `${this._scheme.toLowerCase()} `
    const head = raw.slice(0, schemePrefix.length)
    if (head.toLowerCase() !== schemePrefix) return null
    const token = raw.slice(schemePrefix.length).trim()
    if (!token) return null
    // 4KB covers a large JWT and refuses a multi-MB header.
    if (token.length > 4096) return null
    // Reject multi-header smuggling (Headers.get joins with `, `).
    if (token.includes(',')) return null
    return token
  }

  /** Answers the token in the response body; persisting it is the client's job. */
  issue(sid: string, session: Sessions.Me): Provider.Intent[] {
    return [
      {
        type: 'json',
        status: 200,
        body: { token: sid, expiresAt: session.expiresAt },
      },
    ]
  }

  /** Nothing to clear on the client beyond the token itself, so this only acknowledges. */
  revoke(): Provider.Intent[] {
    // Revocation is server-side through `Sessions.Store.delete`; the client only drops the token.
    return [{ type: 'json', status: 200, body: { revoked: true } }]
  }
}

/** Constructs a {@link BearerTransport}. */
export function bearerTransport(cfg?: Partial<BearerTransport.Cfg>): BearerTransport {
  return new BearerTransport(cfg)
}
