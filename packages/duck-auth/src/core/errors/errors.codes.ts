import type { Sessions } from '../sessions/sessions.types'

declare const CARRIES: unique symbol
declare const FAULT: unique symbol

/**
 * A status that also says what its code hands back. The brand is required rather than optional: an optional one is
 * satisfied structurally by any plain `number`, and every code would then look like it carried something.
 */
export type Carries<M extends object> = number & { readonly [CARRIES]: M }

/** A status whose code an adapter can answer with, rather than one only a flow raises. */
export type Fault = number & { readonly [FAULT]: true }

/** What a status says its code hands back. A plain status says nothing, which is a meta with no keys. */
export type MetaOf<S> = S extends Carries<infer M> ? M : Record<never, never>

/**
 * A code's status and what it hands back with it, in one declaration. It is the status and nothing else at runtime,
 * so `AUTH_ERRORS[code]` stays the number every reader of the map wants.
 */
export function detail<M extends object>(status: number): Carries<M> {
  return status as Carries<M>
}

/** The same declaration for a code an adapter answers with, so the range a store draws from is read off this map. */
export function fault(status: number): Fault
export function fault<M extends object>(status: number): Carries<M> & Fault
export function fault<M extends object>(status: number): Carries<M> & Fault {
  return status as Carries<M> & Fault
}

/** Every code this package raises, at its HTTP status, carrying what the code itself cannot say. */
export const AUTH_ERRORS = {
  AUTH_UNAUTHENTICATED: 401,
  AUTH_SESSION_EXPIRED: detail<{ expiredAt: number }>(401),
  AUTH_SESSION_REVOKED: fault<{ reason: string }>(401),
  /** SECURITY: deliberately outside the absent set, so `orNull()` cannot read a live session whose
   *  identity was erased as a plain sign-out. Absence is `AUTH_SESSION_REVOKED`; this is a data-integrity
   *  violation and stays loud through every reader. */
  AUTH_SESSION_IDENTITY_ERASED: 401,
  AUTH_AAL_INSUFFICIENT: detail<{ required: Sessions.AAL; have: Sessions.AAL }>(401),
  AUTH_STEP_UP_REQUIRED: detail<{ challenge: unknown }>(401),
  AUTH_MFA_REQUIRED: detail<{ methods: string[] }>(401),
  AUTH_INVALID_CREDENTIALS: 401,
  AUTH_PASSKEY_MISMATCH: 401,
  AUTH_EMAIL_NOT_VERIFIED: 403,
  AUTH_RATE_LIMITED: detail<{ retryAfter: number }>(429),
  AUTH_LOCKED: detail<{ until: number; reason: string }>(423),
  AUTH_QUOTA_EXCEEDED: detail<{ quota: string; limit: number }>(429),
  AUTH_PROVIDER_FAILED: detail<{ providerId: string; detail?: string }>(400),
  // Separate from PROVIDER_FAILED because "no such provider" and "that one signs nobody in" are
  // different things to have done wrong, and only one of them is worth retrying against another id.
  AUTH_PROVIDER_UNSUPPORTED: detail<{ providerId: string; detail?: string }>(400),
  AUTH_OAUTH_REUSE_DETECTED: detail<{ familyRevoked: boolean }>(401),
  AUTH_OAUTH_STATE_MISMATCH: 400,
  AUTH_OAUTH_NONCE_REPLAY: 400,
  AUTH_CSRF: 403,
  AUTH_DPOP_INVALID: detail<{ reason: string }>(401),
  AUTH_JWT_INVALID: detail<{ reason: string }>(401),
  AUTH_JWT_KEY_UNKNOWN: detail<{ kid: string }>(401),
  AUTH_SIGNUP_INCOMPLETE: detail<{ missing: string[] }>(409),
  AUTH_SIGNUP_TOKEN_INVALID: 400,
  AUTH_RECOVERY_TOKEN_INVALID: 400,
  AUTH_RECOVERY_TOKEN_EXPIRED: 410,
  AUTH_RECOVERY_REQUIRES_MFA: detail<{ methods: string[] }>(401),
  // Optional because a driver that refuses a write for a conflict names no versions; a store that read them supplies both.
  AUTH_STALE_WRITE: fault<{ expected?: number; actual?: number }>(409),
  AUTH_GRACE_EXPIRED: fault(410),
  AUTH_EMAIL_TAKEN: fault(409),
  AUTH_USERNAME_TAKEN: fault(409),
  AUTH_PROVIDER_TAKEN: fault<{ providerId?: string }>(409),
  AUTH_EMAIL_CHANGE_PENDING: detail<{ pendingNewEmail?: string }>(409),
  AUTH_IMPERSONATE_FORBIDDEN: detail<{ reason: string }>(403),
  AUTH_IMPERSONATE_REQUIRES_IAM: 500,
  AUTH_IMPERSONATE_EXPIRED: 401,
  AUTH_APIKEY_INVALID: 401,
  AUTH_APIKEY_REVOKED: 401,
  AUTH_APIKEY_SCOPE_INSUFFICIENT: detail<{ required: string[]; missing: string[] }>(403),
  AUTH_MAINTENANCE: detail<{ retryAfter: number; message?: string }>(503),
  AUTH_READONLY_MODE: 423,
  AUTH_PROVIDER_NOT_REGISTERED: detail<{ detail: string }>(500),
  AUTH_MISCONFIGURED: fault<{ detail: string }>(500),
  // ADAPTER_FAILED carries the driver error on `cause`, which is the only place it survives.
  AUTH_IDENTITY_NOT_FOUND: fault(404),
  AUTH_CREDENTIAL_NOT_FOUND: fault(404),
  AUTH_SESSION_NOT_FOUND: 404,
  AUTH_ORG_NOT_FOUND: fault(404),
  AUTH_MEMBERSHIP_NOT_FOUND: fault(404),
  AUTH_IDEMPOTENCY_MISS: fault(404),
  AUTH_OPERATION_NOT_FOUND: fault(404),
  AUTH_NOT_ENOUGH_PARAMETERS: fault<{ detail?: string }>(500),
  AUTH_ADAPTER_FAILED: fault(500),
  AUTH_ALREADY_EXISTS: fault<{ detail?: string }>(409),
  // Optional because a driver refusal names nothing; a parser that refused a value says which value.
  AUTH_INVALID_PARAMETERS: fault<{ detail?: string }>(400),
  AUTH_ADAPTER_UNAVAILABLE: fault(503),
} as const satisfies Record<string, number>
