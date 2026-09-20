import type { Provider } from '~/core/provider/provider.types'
import type { Sessions } from '~/core/sessions/sessions.types'

/** Cookie for web, Bearer for native and API keys, JWT for the stateless edge. Apps pick one or
 *  compose them, and the same AuthEngine wires either way. */
export namespace Transport {
  export type CookieOptions = {
    domain?: string
    path?: string
    httpOnly?: boolean
    secure?: boolean
    /** Cross-site policy written onto the cookie; `none` is only valid alongside `secure`. */
    sameSite?: 'strict' | 'lax' | 'none'
    /** Lifetime in **seconds**, the unit Set-Cookie takes, not the ms used elsewhere. */
    maxAge?: number
    expires?: Date
  }

  export type IssueOpts = {
    /** Newly created or just rotated; drives the cookie `Max-Age` and the JWT `exp`. */
    fresh: boolean
    /** Hitting the absolute TTL forces re-auth rather than a refresh. */
    absolute: boolean
    /** Embedded in the bearer as the JWT `scope` claim; CookieTransport ignores it. */
    scope?: string
    /** Plaintext CSRF token to emit beside the session cookie, minted by `SessionsImpl.create` with its hash on
     *  the session row. `CookieTransport.issue` emits it as the CSRF companion cookie, not httpOnly so JS can
     *  read it back for the `x-csrf-token` header; every other transport ignores it. */
    csrfToken?: string
  }

  export type ITransport = {
    /** The cookie value, header token or JWT carried by an inbound request. */
    extract(req: { headers: Headers }): string | null
    /** Build the Intent that persists the bearer for later requests. `sid` is the plaintext identifier the
     *  client sends back; `session` carries the row metadata. SECURITY: `session.id` is the hashed row key and
     *  never goes on the wire. Cookie transport emits a setCookie; JWT emits setCookie plus a json access token. */
    issue(sid: string, session: Sessions.Me, opts: IssueOpts): Provider.Intent[]
    /** The response Intent that revokes any persisted bearer. */
    revoke(): Provider.Intent[]
    /**  has no `verify` at all and leaves the caller to the `Session.IStore` lookup. */
    verify?(token: string): Promise<Sessions.Me>
    /** The longest token this transport accepts. A composite takes the largest its members declare rather than
     *  carrying its own constant, which silently clamped any member with a wider ceiling. */
    maxTokenLength?: number
    /** SECURITY: a refusal here ends verification instead of falling through. A composite verifies by
     *  disjunction, so putting DPoP beside a plain bearer adds nothing on its own, the unbound path still
     *  answering for every token the bound one rejects. Set this and the strict transport's refusal is a
     *  veto. */
    authoritative?: boolean
  }

  /** How a {@link ITransport} composite behaves when its members disagree. */
  export type CompositeOpts = {
    /** SECURITY: what to do when one request presents a credential by more than one method. RFC 6750 section 2
     *  says a client must not and a server must refuse. `'first'` lets array order pick a winner and discards
     *  the rest silently, which lets anyone who can plant a cookie choose which identity the request runs as. */
    onMultipleCredentials?: 'refuse' | 'first'
  }
}
