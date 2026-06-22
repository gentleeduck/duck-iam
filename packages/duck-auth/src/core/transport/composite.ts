import type { AuthProvider } from '../types/provider'
import type { AuthSession } from '../types/session'
import type { AuthTransport } from '../types/transport'

/**
 * Try each transport in order on extract; emit Intents from every transport
 * on issue/revoke (so cookie + bearer co-exist on the same response).
 */
export class AuthCompositeTransport implements AuthTransport.ITransport {
  constructor(private readonly _transports: AuthTransport.ITransport[]) {
    if (_transports.length === 0) {
      throw new Error('@gentleduck/auth AuthCompositeTransport: at least one transport required')
    }
  }

  extract(req: { headers: Headers }): string | null {
    for (const t of this._transports) {
      const token = t.extract(req)
      if (token) return token
    }
    return null
  }

  issue(sid: string, session: AuthSession.ISession, opts: AuthTransport.IssueOpts): AuthProvider.Intent[] {
    return this._transports.flatMap((t) => t.issue(sid, session, opts))
  }

  revoke(): AuthProvider.Intent[] {
    return this._transports.flatMap((t) => t.revoke())
  }

  async verify(token: string): Promise<AuthSession.ISession | null> {
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
