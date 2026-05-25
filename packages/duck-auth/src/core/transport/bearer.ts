import type { Provider } from '../types/provider'
import type { Session } from '../types/session'
import type { Transport } from '../types/transport'

export interface BearerTransportConfig {
  /** Header name. Default `Authorization`. */
  header?: string
  /** Scheme prefix; whitespace-separated from the token. Default `Bearer`. */
  scheme?: string
}

/**
 * Bearer transport — `Authorization: Bearer <opaque>` header. Native/mobile, API keys.
 * Issue returns a JSON intent carrying the token; client is responsible for persisting it.
 */
export class BearerTransport implements Transport.ITransport {
  private readonly _header: string
  private readonly _scheme: string

  constructor(cfg: BearerTransportConfig = {}) {
    this._header = cfg.header ?? 'authorization'
    this._scheme = cfg.scheme ?? 'Bearer'
  }

  extract(req: { headers: Headers }): string | null {
    const raw = req.headers.get(this._header)
    if (!raw) return null
    const expected = `${this._scheme} `
    if (!raw.startsWith(expected)) return null
    return raw.slice(expected.length).trim() || null
  }

  issue(sid: string, session: Session.ISession): Provider.Intent[] {
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
