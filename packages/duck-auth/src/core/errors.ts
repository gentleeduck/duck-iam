import type { Session } from './types/session'

const STATUS_FOR: Record<AuthErrorObject.IAuthErrorCode, number> = {
  'AUTH/UNAUTHENTICATED': 401,
  'AUTH/SESSION_EXPIRED': 401,
  'AUTH/SESSION_REVOKED': 401,
  'AUTH/AAL_INSUFFICIENT': 401,
  'AUTH/STEP_UP_REQUIRED': 401,
  'AUTH/MFA_REQUIRED': 401,
  'AUTH/INVALID_CREDENTIALS': 401,
  'AUTH/PASSKEY_MISMATCH': 401,
  'AUTH/EMAIL_NOT_VERIFIED': 403,
  'AUTH/RATE_LIMITED': 429,
  'AUTH/LOCKED': 423,
  'AUTH/QUOTA_EXCEEDED': 429,
  'AUTH/PROVIDER_FAILED': 400,
  'AUTH/OAUTH_REUSE_DETECTED': 401,
  'AUTH/OAUTH_STATE_MISMATCH': 400,
  'AUTH/OAUTH_NONCE_REPLAY': 400,
  'AUTH/CSRF': 403,
  'AUTH/DPOP_INVALID': 401,
  'AUTH/JWT_INVALID': 401,
  'AUTH/JWT_KEY_UNKNOWN': 401,
  'AUTH/SIGNUP_INCOMPLETE': 409,
  'AUTH/SIGNUP_TOKEN_INVALID': 400,
  'AUTH/RECOVERY_TOKEN_INVALID': 400,
  'AUTH/RECOVERY_TOKEN_EXPIRED': 410,
  'AUTH/RECOVERY_REQUIRES_MFA': 401,
  'AUTH/STALE_WRITE': 409,
  'AUTH/GRACE_EXPIRED': 410,
  'AUTH/EMAIL_TAKEN': 409,
  'AUTH/EMAIL_CHANGE_PENDING': 409,
  'AUTH/IMPERSONATE_FORBIDDEN': 403,
  'AUTH/IMPERSONATE_REQUIRES_IAM': 500,
  'AUTH/IMPERSONATE_EXPIRED': 401,
  'AUTH/APIKEY_INVALID': 401,
  'AUTH/APIKEY_REVOKED': 401,
  'AUTH/APIKEY_SCOPE_INSUFFICIENT': 403,
  'AUTH/MAINTENANCE': 503,
  'AUTH/READONLY_MODE': 423,
  'AUTH/MISCONFIGURED': 500,
}

export class AuthErrorObject<C extends AuthErrorObject.IAuthErrorCode = AuthErrorObject.IAuthErrorCode> extends Error {
  readonly code: C
  readonly status: number
  readonly meta: Record<string, unknown>
  readonly origin?: { providerId?: string; flow?: string }

  constructor(code: C, meta: Record<string, unknown> = {}, origin?: { providerId?: string; flow?: string }) {
    super(code)
    this.name = 'AuthErrorObject.IAuthError'
    this.code = code
    this.status = STATUS_FOR[code]
    this.meta = meta
    if (origin) this.origin = origin
  }

  /** Wire-safe envelope for response bodies - never leaks `meta` keys flagged sensitive. */
  toJSON(): { code: C; status: number } & Record<string, unknown> {
    // Filter sensitive meta keys at the serialisation boundary so the
    // wire contract holds even when callers attach secrets to meta.
    const safeMeta: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(this.meta)) {
      if (SENSITIVE_META_KEYS.has(k.toLowerCase())) continue
      safeMeta[k] = v
    }
    return { code: this.code, status: this.status, ...safeMeta }
  }
}

/**
 * denylist of `meta` keys that must never reach the HTTP wire via
 * `AuthErrorObject.toJSON()`. Lower-cased before lookup so common
 * variations (`Password`, `SECRET`, etc.) are also filtered. The list
 * is conservative - additions are free, removals require re-auditing
 * every callsite that attached the key.
 */
const SENSITIVE_META_KEYS: ReadonlySet<string> = new Set([
  'secret',
  'password',
  'plaintext',
  'privatekey',
  'token',
  'refreshtoken',
  'accesstoken',
  'idtoken',
  'clientsecret',
  'hash',
  'presentedhash',
  'codehash',
  'tokenhash',
])

/**
 * Namespace merge for `AuthErrorObject`. Co-locates the flat type exports
 * alongside the primary symbol via TS class+namespace merging.
 */
export namespace AuthErrorObject {
  export type IAuthError =
    | { code: 'AUTH/UNAUTHENTICATED'; status: 401 }
    | { code: 'AUTH/SESSION_EXPIRED'; status: 401; expiredAt: number }
    | { code: 'AUTH/SESSION_REVOKED'; status: 401; reason: string }
    | { code: 'AUTH/AAL_INSUFFICIENT'; status: 401; required: Session.AAL; have: Session.AAL }
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

  export type IAuthErrorCode = AuthErrorObject.IAuthError['code']
}
