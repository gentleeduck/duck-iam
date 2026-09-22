/** Overridden per call through `passkey(opts)`. */
export const DEFAULT_PASSKEY_CONFIG = {
  /** Challenge TTL in ms. */
  challengeTtlMs: 5 * 60 * 1000,
  /** Required user verification level. */
  userVerification: 'preferred' as const,
  /** Rate-limit key prefix for `begin`. */
  limiterKeyPrefix: 'passkey:begin:',
  /** Attestation requested at registration. */
  attestationType: 'none' as const,
}
