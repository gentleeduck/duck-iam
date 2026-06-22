import type { AuthSession } from './session'

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
  export interface Origin {
    providerId?: string
    flow?: string
  }

  export type IError =
    | { code: 'AUTH/UNAUTHENTICATED'; status: 401 }
    | { code: 'AUTH/SESSION_EXPIRED'; status: 401; expiredAt: number }
    | { code: 'AUTH/SESSION_REVOKED'; status: 401; reason: string }
    | { code: 'AUTH/AAL_INSUFFICIENT'; status: 401; required: AuthSession.AAL; have: AuthSession.AAL }
    | { code: 'AUTH/STEP_UP_REQUIRED'; status: 401; challenge: unknown }
    | { code: 'AUTH/MFA_REQUIRED'; status: 401; methods: string[] }
    | { code: 'AUTH/INVALID_CREDENTIALS'; status: 401 }
    | { code: 'AUTH/PASSKEY_MISMATCH'; status: 401 }
    | { code: 'AUTH/EMAIL_NOT_VERIFIED'; status: 403 }
    | { code: 'AUTH/RATE_LIMITED'; status: 429; retryAfter: number }
    | { code: 'AUTH/LOCKED'; status: 423; until: number; reason: string }
    | { code: 'AUTH/QUOTA_EXCEEDED'; status: 429; quota: string; limit: number }
    | { code: 'AUTH/PROVIDER_FAILED'; status: 400; providerId: string; detail?: string }
    | { code: 'AUTH/OAUTH_REUSE_DETECTED'; status: 401; familyRevoked: true }
    | { code: 'AUTH/OAUTH_STATE_MISMATCH'; status: 400 }
    | { code: 'AUTH/OAUTH_NONCE_REPLAY'; status: 400 }
    | { code: 'AUTH/CSRF'; status: 403 }
    | { code: 'AUTH/DPOP_INVALID'; status: 401; reason: string }
    | { code: 'AUTH/JWT_INVALID'; status: 401; reason: string }
    | { code: 'AUTH/JWT_KEY_UNKNOWN'; status: 401; kid: string }
    | { code: 'AUTH/SIGNUP_INCOMPLETE'; status: 409; missing: string[] }
    | { code: 'AUTH/SIGNUP_TOKEN_INVALID'; status: 400 }
    | { code: 'AUTH/RECOVERY_TOKEN_INVALID'; status: 400 }
    | { code: 'AUTH/RECOVERY_TOKEN_EXPIRED'; status: 410 }
    | { code: 'AUTH/RECOVERY_REQUIRES_MFA'; status: 401; methods: string[] }
    | { code: 'AUTH/STALE_WRITE'; status: 409; expected: number; actual: number }
    | { code: 'AUTH/GRACE_EXPIRED'; status: 410 }
    | { code: 'AUTH/EMAIL_TAKEN'; status: 409 }
    | { code: 'AUTH/EMAIL_CHANGE_PENDING'; status: 409; pendingNewEmail?: string }
    | { code: 'AUTH/IMPERSONATE_FORBIDDEN'; status: 403; reason: string }
    | { code: 'AUTH/IMPERSONATE_REQUIRES_IAM'; status: 500 }
    | { code: 'AUTH/IMPERSONATE_EXPIRED'; status: 401 }
    | { code: 'AUTH/APIKEY_INVALID'; status: 401 }
    | { code: 'AUTH/APIKEY_REVOKED'; status: 401 }
    | {
        code: 'AUTH/APIKEY_SCOPE_INSUFFICIENT'
        status: 403
        required: string[]
        have: string[]
      }
    | { code: 'AUTH/MAINTENANCE'; status: 503; retryAfter: number; message?: string }
    | { code: 'AUTH/READONLY_MODE'; status: 423 }
    | { code: 'AUTH/MISCONFIGURED'; status: 500; detail: string }
}
