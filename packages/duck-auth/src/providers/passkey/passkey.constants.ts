/** Default passkey ceremony knobs; overridden per-call via `passkey(opts)`. */
export const DEFAULT_PASSKEY_CONFIG = {
  /** TTL applied to issued challenges, ms. */
  challengeTtlMs: 5 * 60 * 1000,
  /** Required user verification level. */
  userVerification: 'preferred' as const,
}
