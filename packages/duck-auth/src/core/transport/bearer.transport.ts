import { AuthError } from '../errors'
import type { Provider } from '../provider/provider.types'
import type { Sessions } from '../sessions/sessions.types'
import type { Transport } from '../transport/transport.types'

export namespace BearerTransport {
  export type Cfg = {
    /** Header name. Default `Authorization`. */
    header?: string
    /** Scheme prefix; whitespace-separated from the token. Default `Bearer`. */
    scheme?: string
  }
}

/**
 * Bearer transport - `Authorization: Bearer <opaque>` header. Native/mobile, API keys.
 * Issue returns a JSON intent carrying the token; client is responsible for persisting it.
 */
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

  extract(req: { headers: Headers }): string | null {
    const raw = req.headers.get(this._header)
    if (!raw) return null
    // Case-insensitive scheme match (RFC 7235 2.1).
    const schemePrefix = `${this._scheme.toLowerCase()} `
    const head = raw.slice(0, schemePrefix.length)
    if (head.toLowerCase() !== schemePrefix) return null
    const token = raw.slice(schemePrefix.length).trim()
    if (!token) return null
    // 4KB cap covers large JWTs; refuses multi-MB DoS headers.
    if (token.length > 4096) return null
    // Reject multi-header smuggling (Headers.get joins with `, `).
    if (token.includes(',')) return null
    return token
  }

  issue(sid: string, session: Sessions.Me): Provider.Intent[] {
    return [
      {
        type: 'json',
        status: 200,
        body: { token: sid, expiresAt: session.expiresAt },
      },
    ]
  }

  revoke(): Provider.Intent[] {
    // Bearer revoke is server-side (Session.IStore.delete); the client just drops the token.
    return [{ type: 'json', status: 200, body: { revoked: true } }]
  }
}

/** Factory around {@link BearerTransport} for functional-style config. */
export function bearerTransport(cfg?: Partial<BearerTransport.Cfg>): BearerTransport {
  return new BearerTransport(cfg)
}
