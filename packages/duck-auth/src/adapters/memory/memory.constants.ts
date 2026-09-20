import { declares, GENERIC, type RangeOf } from '~/core/errors'

/**
 * The codes the in-memory store raises itself. It maps no driver, so this is its whole range.
 * WARN: a `throw new AuthError(...)` in the store whose code is missing here is re-labelled
 * AUTH_ADAPTER_FAILED by `run()`; add it in the same change. `declared-range.test.ts` catches the drift.
 */
export const MEMORY_RAISES = declares(GENERIC, [
  'AUTH_ALREADY_EXISTS',
  'AUTH_CREDENTIAL_NOT_FOUND',
  'AUTH_EMAIL_TAKEN',
  'AUTH_GRACE_EXPIRED',
  'AUTH_IDENTITY_NOT_FOUND',
  'AUTH_INVALID_PARAMETERS',
  'AUTH_MEMBERSHIP_NOT_FOUND',
  'AUTH_ORG_NOT_FOUND',
  'AUTH_PROVIDER_TAKEN',
  'AUTH_SESSION_REVOKED',
  'AUTH_STALE_WRITE',
  'AUTH_USERNAME_TAKEN',
])

/** What the in-memory store answers with. */
export type MemoryFault = RangeOf<typeof MEMORY_RAISES>
