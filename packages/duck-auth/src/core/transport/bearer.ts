import type { Provider } from '../types/provider'
import type { Session, Transport } from '../types/session'

/**
 * Bearer transport - `Authorization: Bearer <opaque>` header. Native/mobile, API keys.
 * Issue returns a JSON intent carrying the token; client is responsible for persisting it.
 */
export class BearerTransport implements Transport.ITransport {
  private readonly _header: string
  private readonly _scheme: string

  constructor(cfg: BearerTransport.Config = {}) {
    this._header = cfg.header ?? 'authorization'
    this._scheme = cfg.scheme ?? 'Bearer'
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

  issue(sid: string, session: Session.Me): Provider.Intent[] {
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

export namespace BearerTransport {
  export type Config = {
    /** Header name. Default `Authorization`. */
    header?: string
    /** Scheme prefix; whitespace-separated from the token. Default `Bearer`. */
    scheme?: string
  }
}
