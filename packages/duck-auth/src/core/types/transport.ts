import type { Provider } from './provider'
import type { Session } from './session'

/**
 * Session-bearer transport contract. Cookie (web), Bearer (native + API keys),
 * JWT (stateless edge). Apps pick one or compose; the same AuthRoot wires them.
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
    /**
     * Space-separated OAuth-style scope string to embed in the issued
     * bearer. JwtTransport copies this into the JWT's `scope` claim so
     * resource servers can authorize without a separate scope lookup.
     * CookieTransport ignores it (the session row carries scope state
     * out-of-band).
     *
     * Used by `M2MFacet.exchange` to project the granted scope set onto
     * the wire; without this, `scopeMode: intersect/strict` is
     * bookkeeping only.
     */
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
     */
    issue(sid: string, session: Session.ISession, opts: IssueOpts): Provider.Intent[]
    /** Build a response Intent that revokes any persisted bearer. */
    revoke(): Provider.Intent[]
    /**
     * Optional verify step - JWT transports verify locally and reconstruct Session
     * without a store hit; opaque transports return null and rely on Session.IStore lookup.
     */
    verify?(token: string): Promise<Session.ISession | null>
  }
}
