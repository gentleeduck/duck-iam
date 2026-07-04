import type { Session } from './types/session'

const STATUS_FOR: Record<AuthError.Code, number> = {
  AUTH_UNAUTHENTICATED: 401,
  AUTH_SESSION_EXPIRED: 401,
  AUTH_SESSION_REVOKED: 401,
  AUTH_AAL_INSUFFICIENT: 401,
  AUTH_STEP_UP_REQUIRED: 401,
  AUTH_MFA_REQUIRED: 401,
  AUTH_INVALID_CREDENTIALS: 401,
  AUTH_PASSKEY_MISMATCH: 401,
  AUTH_EMAIL_NOT_VERIFIED: 403,
  AUTH_RATE_LIMITED: 429,
  AUTH_LOCKED: 423,
  AUTH_QUOTA_EXCEEDED: 429,
  AUTH_PROVIDER_FAILED: 400,
  AUTH_OAUTH_REUSE_DETECTED: 401,
  AUTH_OAUTH_STATE_MISMATCH: 400,
  AUTH_OAUTH_NONCE_REPLAY: 400,
  AUTH_CSRF: 403,
  AUTH_DPOP_INVALID: 401,
  AUTH_JWT_INVALID: 401,
  AUTH_JWT_KEY_UNKNOWN: 401,
  AUTH_SIGNUP_INCOMPLETE: 409,
  AUTH_SIGNUP_TOKEN_INVALID: 400,
  AUTH_RECOVERY_TOKEN_INVALID: 400,
  AUTH_RECOVERY_TOKEN_EXPIRED: 410,
  AUTH_RECOVERY_REQUIRES_MFA: 401,
  AUTH_STALE_WRITE: 409,
  AUTH_GRACE_EXPIRED: 410,
  AUTH_EMAIL_TAKEN: 409,
  AUTH_EMAIL_CHANGE_PENDING: 409,
  AUTH_IMPERSONATE_FORBIDDEN: 403,
  AUTH_IMPERSONATE_REQUIRES_IAM: 500,
  AUTH_IMPERSONATE_EXPIRED: 401,
  AUTH_APIKEY_INVALID: 401,
  AUTH_APIKEY_REVOKED: 401,
  AUTH_APIKEY_SCOPE_INSUFFICIENT: 403,
  AUTH_MAINTENANCE: 503,
  AUTH_READONLY_MODE: 423,
  AUTH_MISCONFIGURED: 500,
}

export class AuthError<C extends AuthError.Code = AuthError.Code> extends Error {
  readonly code: C
  readonly status: number
  readonly meta: Record<string, unknown>
  readonly origin?: AuthError.Origin

  constructor(code: C, ...args: AuthError.Args<C>) {
    super(code)
    this.name = 'AuthError.IAuthError'
    this.code = code
    this.status = STATUS_FOR[code]
    this.meta = (args[0] ?? {}) as Record<string, unknown>
    const origin = args[1] as AuthError.Origin | undefined
    if (origin) this.origin = origin
  }

  /** Wire-safe envelope matching ResponseType<T, M> error branch. Never leaks sensitive meta keys. */
  toJSON(): { ok: false; error: { code: C; status: number } & Record<string, unknown> } {
    const safeMeta = scrubSensitive(this.meta) as Record<string, unknown>
    return { ok: false, error: { code: this.code, status: this.status, ...safeMeta } }
  }
}

/**
 * Throw a typed AuthError. Matches the `throwXxxError(code)` pattern used
 * throughout the app so callers never construct `new AuthError(...)` directly.
 */
export function throwAuthError<C extends AuthError.Code>(code: C, ...args: AuthError.Args<C>): never {
  throw new AuthError(code, ...args)
}

/**
 * Re-throw already-typed errors unchanged; wrap unknown errors as a typed
 * AuthError with the provided fallback code.
 * Mirrors `rethrowXxxError(error, code)` used in NestJS service layers.
 */
export function rethrowAuthError<C extends AuthError.Code>(error: unknown, code: C, ...args: AuthError.Args<C>): never {
  if (error instanceof AuthError) throw error
  throw new AuthError(code, ...args)
}

function scrubSensitive(value: unknown, depth = 0): unknown {
  if (depth > 8) return '[depth-cap]'
  if (Array.isArray(value)) return value.map((v) => scrubSensitive(v, depth + 1))
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value)) {
      if (SENSITIVE_META_KEYS.has(k.toLowerCase())) continue
      out[k] = scrubSensitive(v, depth + 1)
    }
    return out
  }
  return value
}

/** Lower-cased meta keys stripped from `toJSON()` output. */
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

export namespace AuthError {
  export interface Origin {
    providerId?: string
    flow?: string
  }

  export type Error =
    | { code: 'AUTH_UNAUTHENTICATED'; status: 401 }
    | { code: 'AUTH_SESSION_EXPIRED'; status: 401; expiredAt: number }
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

  export type Code = AuthError.Error['code']

  /** Extra fields for a given error code (everything except `code` and `status`). */
  export type Meta<C extends AuthError.Code> = Omit<Extract<AuthError.Error, { code: C }>, 'code' | 'status'>

  /** Whether T has at least one required (non-optional) key. */
  export type HasRequired<T> = { [K in keyof T]-?: undefined extends T[K] ? never : K }[keyof T]

  /** Conditional rest args: meta optional when no required fields, required otherwise. */
  export type Args<C extends AuthError.Code> = [HasRequired<Meta<C>>] extends [never]
    ? [meta?: Meta<C>, origin?: AuthError.Origin]
    : [meta: Meta<C>, origin?: AuthError.Origin]
}
