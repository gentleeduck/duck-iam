/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { Provider } from './provider'
import type { Session } from './session'

/**
 * Session-bearer transport contract. Cookie (web), Bearer (native + API keys),
 * JWT (stateless edge). Apps pick one or compose; the same AuthRoot wires them.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace Transport {
  export interface CookieOptions {
    domain?: string
    path?: string
    httpOnly?: boolean
    secure?: boolean
    sameSite?: 'strict' | 'lax' | 'none'
    maxAge?: number
    expires?: Date
  }

  export interface IssueOpts {
    /** Newly created or just-rotated session. Drives cookie `Max-Age`/JWT `exp`. */
    fresh: boolean
    /** Whether the absolute TTL is being hit (forces re-auth instead of refresh). */
    absolute: boolean
  }

  export interface ITransport {
    /** Pull the bearer token (cookie value, header token, JWT) from an inbound request. */
    extract(req: { headers: Headers }): string | null
    /**
     * Build a response Intent that persists the bearer for subsequent requests.
     * `sid` is the **plaintext** session identifier - the value the client will
     * send back on subsequent requests. `session` carries the row metadata
     * (`session.id` is the hashed row key; never put it on the wire).
     * Cookie transport -> setCookie intent. JWT transport -> setCookie (refresh)
     * + json (access token); the access token is derived from `session`.
     *
     * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
     */
    issue(sid: string, session: Session.ISession, opts: IssueOpts): Provider.Intent[]
    /** Build a response Intent that revokes any persisted bearer. */
    revoke(): Provider.Intent[]
    /**
     * Optional verify step - JWT transports verify locally and reconstruct Session
     * without a store hit; opaque transports return null and rely on Session.IStore lookup.
     *
     * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
     */
    verify?(token: string): Promise<Session.ISession | null>
  }
}
