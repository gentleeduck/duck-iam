import { detail, fault } from '@gentleduck/error'

export { detail, fault }

/** Every code this package raises, at its HTTP status, carrying what the code itself cannot say. */
export const AUTH_ERRORS = {
  AUTH_UNAUTHENTICATED: 401,
  AUTH_SESSION_EXPIRED: detail<{ expiredAt: number }>(401),
  AUTH_SESSION_REVOKED: fault<{ reason: string }>(401),
  /** SECURITY: deliberately outside the absent set, so `orNull()` cannot read a live session whose
   *  identity was erased as a plain sign-out. Absence is `AUTH_SESSION_REVOKED`; this is a data-integrity
   *  violation and stays loud through every reader. */
  AUTH_SESSION_IDENTITY_ERASED: 401,
  AUTH_STEP_UP_REQUIRED: detail<{ challenge: unknown }>(401),
  /** The adaptive-detector verdict, distinct from `AUTH_SESSION_REVOKED`, which the hijack policy raises
   *  about a fingerprint that drifted. 403, not 401: the session is valid and the request is refused on
   *  score, so presenting the same credential again changes nothing.
   *  SECURITY: deliberately outside the absent set. A refusal must not read back through `orNull()` as
   *  "no session", which is how a denial becomes an anonymous request that is served anyway. */
  AUTH_ANOMALY_DENIED: detail<{ score: number }>(403),
  AUTH_MFA_REQUIRED: detail<{ methods: string[] }>(401),
  AUTH_INVALID_CREDENTIALS: detail<{ detail?: string }>(401),
  AUTH_PASSKEY_MISMATCH: 401,
  AUTH_RATE_LIMITED: detail<{ retryAfter: number }>(429),
  AUTH_PROVIDER_FAILED: detail<{ providerId: string; detail?: string }>(400),
  // Separate from PROVIDER_FAILED because "no such provider" and "that one signs nobody in" are
  // different things to have done wrong, and only one of them is worth retrying against another id.
  AUTH_PROVIDER_UNSUPPORTED: detail<{ providerId: string; detail?: string }>(400),
  AUTH_OAUTH_REUSE_DETECTED: detail<{ familyRevoked: boolean }>(401),
  AUTH_OAUTH_STATE_MISMATCH: 400,
  AUTH_OAUTH_NONCE_REPLAY: 400,
  AUTH_CSRF: 403,
  AUTH_DPOP_INVALID: detail<{ reason: string }>(401),
  // Both are in the absent set: a token that does not verify means the request carries no session.
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
  AUTH_IMPERSONATE_FORBIDDEN: detail<{ reason: string }>(403),
  AUTH_IMPERSONATE_EXPIRED: 401,
  /** The verify-time verdict, distinct from `AUTH_IMPERSONATE_EXPIRED`, which `releaseImpersonation`
   *  raises about a session that is not an impersonation at all. This one is absence-shaped and in the
   *  absent set; that one is a refusal the caller asked for and must stay loud through every reader. */
  AUTH_IMPERSONATE_WINDOW_CLOSED: detail<{ closedAt: number }>(401),
  AUTH_APIKEY_INVALID: 401,
  AUTH_APIKEY_REVOKED: 401,
  AUTH_APIKEY_SCOPE_INSUFFICIENT: detail<{ required: string[]; missing: string[] }>(403),
  AUTH_PROVIDER_NOT_REGISTERED: detail<{ detail: string }>(500),
  AUTH_MISCONFIGURED: fault<{ detail: string }>(500),
  // ADAPTER_FAILED carries the driver error on `cause`, which is the only place it survives.
  AUTH_IDENTITY_NOT_FOUND: fault(404),
  AUTH_CREDENTIAL_NOT_FOUND: fault(404),
  AUTH_ORG_NOT_FOUND: fault(404),
  AUTH_MEMBERSHIP_NOT_FOUND: fault(404),
  AUTH_IDEMPOTENCY_MISS: fault(404),
  AUTH_NOT_ENOUGH_PARAMETERS: fault<{ detail?: string }>(500),
  AUTH_ADAPTER_FAILED: fault(500),
  /** A store answered a row scoped to a tenant other than the one asked for. 500 because it is the store
   *  breaking its contract, not the caller asking wrongly.
   *  SECURITY: deliberately outside the absent set. A cross-tenant row must not read back through
   *  `orNull()` as "no row", which is how a disclosure becomes a 404 nobody looks at. */
  AUTH_TENANT_SCOPE_VIOLATION: fault<{ asked: string; got: string | null }>(500),
  AUTH_ALREADY_EXISTS: fault<{ detail?: string }>(409),
  // Optional because a driver refusal names nothing; a parser that refused a value says which value.
  AUTH_INVALID_PARAMETERS: fault<{ detail?: string }>(400),
  AUTH_ADAPTER_UNAVAILABLE: fault(503),
} as const satisfies Record<string, number>
