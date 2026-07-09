/** Transport, errors, and the response envelope. (The `Session` domain now lives in `~/core/sessions/sessions.types`.) */
import type { Session } from '~/core/sessions/sessions.types'
import type { Provider } from './provider'

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

/**
 * Discriminated union of every error code shipped by `@gentleduck/auth`.
 * Codes are stable; statuses are fixed per code and never variable. UIs
 * switch on `code`, not on status or message.
 *
 * full taxonomy enumeration.
 */
export namespace AuthError {
  /** Stable string id of an error; used as the discriminant. */
  export type Code = IError['code']

  /** Origin metadata - which provider / flow surfaced the error. */
  export type Origin = {
    providerId?: string
    flow?: string
  }

  export type IError =
    | { code: 'AUTH_UNAUTHENTICATED'; status: 401 }
    | { code: 'AUTH_SESSION_EXPIRED'; status: 401; expiredAt: Date }
    | { code: 'AUTH_SESSION_REVOKED'; status: 401; reason: string }
    | { code: 'AUTH_AAL_INSUFFICIENT'; status: 401; required: Session.AAL; have: Session.AAL }
    | { code: 'AUTH_STEP_UP_REQUIRED'; status: 401; challenge: unknown }
    | { code: 'AUTH_MFA_REQUIRED'; status: 401; methods: string[] }
    | { code: 'AUTH_INVALID_CREDENTIALS'; status: 401 }
    | { code: 'AUTH_PASSKEY_MISMATCH'; status: 401 }
    | { code: 'AUTH_EMAIL_NOT_VERIFIED'; status: 403 }
    | { code: 'AUTH_RATE_LIMITED'; status: 429; retryAfter: number }
    | { code: 'AUTH_LOCKED'; status: 423; until: number; reason: string }
    | { code: 'AUTH_QUOTA_EXCEEDED'; status: 429; quota: string; limit: number }
    | { code: 'AUTH_PROVIDER_FAILED'; status: 400; providerId: string; detail?: string }
    | { code: 'AUTH_OAUTH_REUSE_DETECTED'; status: 401; familyRevoked: boolean }
    | { code: 'AUTH_OAUTH_STATE_MISMATCH'; status: 400 }
    | { code: 'AUTH_OAUTH_NONCE_REPLAY'; status: 400 }
    | { code: 'AUTH_CSRF'; status: 403 }
    | { code: 'AUTH_DPOP_INVALID'; status: 401; reason: string }
    | { code: 'AUTH_JWT_INVALID'; status: 401; reason: string }
    | { code: 'AUTH_JWT_KEY_UNKNOWN'; status: 401; kid: string }
    | { code: 'AUTH_SIGNUP_INCOMPLETE'; status: 409; missing: string[] }
    | { code: 'AUTH_SIGNUP_TOKEN_INVALID'; status: 400 }
    | { code: 'AUTH_RECOVERY_TOKEN_INVALID'; status: 400 }
    | { code: 'AUTH_RECOVERY_TOKEN_EXPIRED'; status: 410 }
    | { code: 'AUTH_RECOVERY_REQUIRES_MFA'; status: 401; methods: string[] }
    | { code: 'AUTH_STALE_WRITE'; status: 409; expected: number; actual: number }
    | { code: 'AUTH_GRACE_EXPIRED'; status: 410 }
    | { code: 'AUTH_EMAIL_TAKEN'; status: 409 }
    | { code: 'AUTH_EMAIL_CHANGE_PENDING'; status: 409; pendingNewEmail?: string }
    | { code: 'AUTH_IMPERSONATE_FORBIDDEN'; status: 403; reason: string }
    | { code: 'AUTH_IMPERSONATE_REQUIRES_IAM'; status: 500 }
    | { code: 'AUTH_IMPERSONATE_EXPIRED'; status: 401 }
    | { code: 'AUTH_APIKEY_INVALID'; status: 401 }
    | { code: 'AUTH_APIKEY_REVOKED'; status: 401 }
    | {
        code: 'AUTH_APIKEY_SCOPE_INSUFFICIENT'
        status: 403
        required: string[]
        have: string[]
      }
    | { code: 'AUTH_MAINTENANCE'; status: 503; retryAfter: number; message?: string }
    | { code: 'AUTH_READONLY_MODE'; status: 423 }
    | { code: 'AUTH_MISCONFIGURED'; status: 500; detail: string }
}
/**
 * `Envelope` — the discriminated response envelope the auth client speaks.
 *
 * Deliberately dependency-free but shape-identical to a standard `{ ok, code,
 * data } | { ok:false, error }` API envelope, so a server that returns this
 * pattern (like a NestJS `ResponseType`) needs no client-side adapter.
 */
export type Envelope<T, C extends string = string> =
  | { ok: true; code: C; data: T }
  | { ok: false; error: { code: C; cause?: unknown; issues?: readonly string[] } }
