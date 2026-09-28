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
  /** COSE algorithms registration offers and accepts: Ed25519, ES256 and RS256. */
  supportedAlgorithmIDs: [-8, -7, -257],
  /** WebAuthn 7.1 caps a credential id at 1023 bytes: 1364 base64url characters. */
  maxCredentialIdChars: 1364,
}
