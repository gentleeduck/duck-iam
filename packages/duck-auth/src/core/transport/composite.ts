import type { Provider } from '../types/provider'
import type { Session } from '../types/session'
import type { Transport } from '../types/transport'

/**
 * Try each transport in order on extract; emit Intents from every transport
 * on issue/revoke (so cookie + bearer co-exist on the same response).
 */
export class CompositeTransport implements Transport.ITransport {
  constructor(private readonly _transports: Transport.ITransport[]) {
    if (_transports.length === 0) {
      throw new Error('@gentleduck/auth CompositeTransport: at least one transport required')
    }
  }

  extract(req: { headers: Headers }): string | null {
    for (const t of this._transports) {
      const token = t.extract(req)
      if (token) return token
    }
    return null
  }

  issue(sid: string, session: Session.ISession, opts: Transport.IssueOpts): Provider.Intent[] {
    return this._transports.flatMap((t) => t.issue(sid, session, opts))
  }

  revoke(): Provider.Intent[] {
    return this._transports.flatMap((t) => t.revoke())
  }

  async verify(token: string): Promise<Session.ISession | null> {
    // Cap once before walking transports; 4096 is the largest any
    // shipped transport accepts.
    if (typeof token !== 'string' || token.length === 0 || token.length > 4096) {
      return null
    }
    for (const t of this._transports) {
      if (!t.verify) continue
      const s = await t.verify(token)
      if (s) return s
    }
    return null
  }
}
