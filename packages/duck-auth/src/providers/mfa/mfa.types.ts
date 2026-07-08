import type { Compliance } from '~/core/compliance'
import type { PasskeyTypes } from '~/providers/passkey/types'

/**
 * Every type the MFA provider exposes lives under this one namespace, so
 * consumers reach for `Mfa.Config`, `Mfa.WebauthnLibrary`, etc. from a single
 * place.
 */
export namespace Mfa {
  /** Resolved, total facet config — every field explicit (null-discipline). */
  export type Config = {
    /** Brand shown in TOTP authenticator app entries. */
    issuer: string
    /** How many backup codes to generate per enrollment. Default 10. */
    backupCodeCount: number
    /** Backup code length in characters. Default 10. */
    backupCodeLen: number
  }

  /**
   * Ergonomic, end-user-facing config. Every field optional; the boundary
   * coalesces each key to its default (`toMfaConfig`) so the facet never sees
   * `undefined`.
   */
  export type ConfigInput = {
    /** Brand shown in TOTP authenticator app entries. Default 'duck-auth'. */
    issuer?: string
    backupCodeCount?: number
    backupCodeLen?: number
    /** Compliance preset(s); ratchets `backupCodeCount` up to the preset floor. */
    compliance?: Compliance.Preset | Compliance.Preset[]
  }

  export type TotpEnrollChallenge = {
    secret: string
    uri: string
  }

  /** Structural shape of the `@simplewebauthn/server` module we use. */
  export type WebauthnLibrary = {
    generateRegistrationOptions(input: unknown): Promise<PasskeyTypes.RegistrationOptions>
    verifyRegistrationResponse(input: unknown): Promise<{
      verified: boolean
      registrationInfo?: {
        credential: { id: string; publicKey: Uint8Array; counter?: number; transports?: string[] }
      }
    }>
    generateAuthenticationOptions(input: unknown): Promise<PasskeyTypes.AuthenticationOptions>
    verifyAuthenticationResponse(input: unknown): Promise<{
      verified: boolean
      authenticationInfo: { newCounter: number; credentialID: string; userVerified: boolean }
    }>
  }

  /** Caller-supplied per-session challenge store. The passkey
   * provider's `MemoryPasskeyChallengeStore` is the canonical impl. */
  export type WebauthnChallengeStore = {
    put(key: string, challenge: string, ttlMs: number): Promise<void>
    take(key: string): Promise<string | null>
  }

  export type WebauthnMfaEnrollOpts = {
    rpID: string
    rpName: string
    userName: string
    expectedOrigins: string | string[]
    challengeStore: WebauthnChallengeStore
    /** Stable opaque key (typically the session id) tying enrollment ceremony pieces. */
    challengeKey: string
    challengeTtlMs?: number
    userVerification?: 'required' | 'preferred' | 'discouraged'
    attestation?: 'none' | 'direct' | 'indirect' | 'enterprise'
    /** Algorithm allowlist; default `[-8, -7, -257]` (Ed25519 + ES256 + RS256). */
    supportedAlgorithmIDs?: number[]
    /** Override the library instance (tests). */
    webauthnModule?: WebauthnLibrary
  }

  export type WebauthnMfaConfirmOpts = {
    rpID: string
    expectedOrigins: string | string[]
    challengeStore: WebauthnChallengeStore
    challengeKey: string
    /** The browser's `RegistrationResponseJSON` from `navigator.credentials.create`. */
    response: unknown
    userVerification?: 'required' | 'preferred' | 'discouraged'
    webauthnModule?: WebauthnLibrary
  }

  export type WebauthnMfaVerifyBeginOpts = {
    rpID: string
    challengeStore: WebauthnChallengeStore
    challengeKey: string
    challengeTtlMs?: number
    userVerification?: 'required' | 'preferred' | 'discouraged'
    webauthnModule?: WebauthnLibrary
  }

  export type WebauthnMfaVerifyOpts = {
    rpID: string
    expectedOrigins: string | string[]
    challengeStore: WebauthnChallengeStore
    challengeKey: string
    /** The browser's `AuthenticationResponseJSON` from `navigator.credentials.get`. */
    response: unknown
    userVerification?: 'required' | 'preferred' | 'discouraged'
    webauthnModule?: WebauthnLibrary
  }

  // Minimal metadata shapes read by MfaFacet — defined locally to avoid
  // core → provider dependency direction.
  export type TotpMetadata = {
    confirmed?: boolean
  }
  export type PasskeyMetadata = {
    deviceType?: string
    backedUp?: boolean
  }
}
