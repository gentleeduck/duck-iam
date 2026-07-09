import type { Provider } from '~/core/provider/provider.types'
import type { Session } from '~/core/sessions/sessions.types'

/**
 * Session-bearer transport contract. Cookie (web), Bearer (native + API keys),
 * JWT (stateless edge). Apps pick one or compose; the same AuthEngine wires them.
 */
export namespace Transport {
  export type CookieOptions = {
    domain?: string
    path?: string
    httpOnly?: boolean
    secure?: boolean
    sameSite?: 'strict' | 'lax' | 'none'
    maxAge?: number
    expires?: Date
  }

  export type IssueOpts = {
    /** Newly created or just-rotated session. Drives cookie `Max-Age`/JWT `exp`. */
    fresh: boolean
    /** Whether the absolute TTL is being hit (forces re-auth instead of refresh). */
    absolute: boolean
    /** oauth-style scope string embedded in the bearer (JWT `scope` claim); CookieTransport ignores. */
    scope?: string
    /**
     * Plaintext CSRF token to emit alongside the session cookie. Minted
     * by `SessionsFacet.create` (returned as `csrfToken`); the hash
     * lives on the session row. `CookieTransport.issue` emits a
     * `__Host-duck-csrf` cookie (httpOnly:false so JS can read it for
     * the `x-csrf-token` header); other transports ignore.
     */
    csrfToken?: string
  }

  export type ITransport = {
    /** Pull the bearer token (cookie value, header token, JWT) from an inbound request. */
    extract(req: { headers: Headers }): string | null
    /**
     * Build a response Intent that persists the bearer for subsequent requests.
     * `sid` is the **plaintext** session identifier - the value the client will
     * send back on subsequent requests. `session` carries the row metadata
     * (`session.id` is the hashed row key; never put it on the wire).
     * Cookie transport -> setCookie intent. JWT transport -> setCookie (refresh)
     * + json (access token); the access token is derived from `session`.
     */
    issue(sid: string, session: Session.Me, opts: IssueOpts): Provider.Intent[]
    /** Build a response Intent that revokes any persisted bearer. */
    revoke(): Provider.Intent[]
    /**
     * Optional verify step - JWT transports verify locally and reconstruct Session
     * without a store hit; opaque transports return null and rely on Session.IStore lookup.
     */
    verify?(token: string): Promise<Session.Me | null>
  }
}
