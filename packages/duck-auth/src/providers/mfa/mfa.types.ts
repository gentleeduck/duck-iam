import type { Compliance } from '~/core/compliance'
import type { Passkey } from '~/providers/passkey/passkey.types'

/** MFA configuration, the factors it enrols, and the step-up contract. */
export namespace Mfa {
  /** Total: every field explicit. */
  export type Cfg = {
    /** The brand an authenticator app shows against the entry. */
    issuer: string
    /** Per enrollment. Default 10. */
    backupCodeCount: number
    /** In characters. Default 10. */
    backupCodeLen: number
    /** Compliance preset(s); ratchets `backupCodeCount` up to the preset floor. */
    compliance: Compliance.Preset | Compliance.Preset[]
  }

  /** Every field optional: each is coalesced to its default, so the facet never sees an
   *  `undefined`. */
  export type CfgInput = {
    /** The brand an authenticator app shows against the entry. Default 'duck-auth'. */
    issuer?: string
    /** How many single-use backup codes are minted at enrollment. */
    backupCodeCount?: number
    backupCodeLen?: number
    /** Compliance preset(s); ratchets `backupCodeCount` up to the preset floor. */
    compliance?: Compliance.Preset | Compliance.Preset[]
  }

  export type TotpEnrollChallenge = {
    secret: string
    uri: string
  }

  /** The part of `@simplewebauthn/server` this uses. */
  export type WebauthnLibrary = {
    generateRegistrationOptions(input: unknown): Promise<Passkey.RegistrationOptions>
    verifyRegistrationResponse(input: unknown): Promise<{
      verified: boolean
      registrationInfo?: {
        credential: { id: string; publicKey: Uint8Array; counter?: number; transports?: string[] }
      }
    }>
    generateAuthenticationOptions(input: unknown): Promise<Passkey.AuthenticationOptions>
    verifyAuthenticationResponse(input: unknown): Promise<{
      verified: boolean
      authenticationInfo: { newCounter: number; credentialID: string; userVerified: boolean }
    }>
  }

  export type WebauthnMfaEnrollOpts = {
    rpID: string
    rpName: string
    userName: string
    expectedOrigins: string | string[]
    challengeStore: Passkey.ChallengeStore
    /** Ties the enrollment ceremony's pieces together; the session id, typically. */
    challengeKey: string
    /** How long the WebAuthn challenge stays claimable, in ms. */
    challengeTtlMs?: number
    /** WebAuthn user-verification requirement, passed through to the authenticator. */
    userVerification?: 'required' | 'preferred' | 'discouraged'
    /** How much attestation the authenticator is asked for. */
    attestation?: 'none' | 'direct' | 'indirect' | 'enterprise'
    /** Default `[-8, -7, -257]`: Ed25519, ES256 and RS256. */
    supportedAlgorithmIDs?: number[]
    /** Where a test injects its own library instance. */
    webauthnModule?: WebauthnLibrary
  }

  export type WebauthnMfaConfirmOpts = {
    rpID: string
    expectedOrigins: string | string[]
    challengeStore: Passkey.ChallengeStore
    challengeKey: string
    /** The browser's `RegistrationResponseJSON` from `navigator.credentials.create`. */
    response: unknown
    /** WebAuthn user-verification requirement, passed through to the authenticator. */
    userVerification?: 'required' | 'preferred' | 'discouraged'
    webauthnModule?: WebauthnLibrary
  }

  export type WebauthnMfaVerifyBeginOpts = {
    rpID: string
    challengeStore: Passkey.ChallengeStore
    challengeKey: string
    /** How long the WebAuthn challenge stays claimable, in ms. */
    challengeTtlMs?: number
    /** WebAuthn user-verification requirement, passed through to the authenticator. */
    userVerification?: 'required' | 'preferred' | 'discouraged'
    webauthnModule?: WebauthnLibrary
  }

  export type WebauthnMfaVerifyOpts = {
    rpID: string
    expectedOrigins: string | string[]
    challengeStore: Passkey.ChallengeStore
    challengeKey: string
    /** The browser's `AuthenticationResponseJSON` from `navigator.credentials.get`. */
    response: unknown
    /** WebAuthn user-verification requirement, passed through to the authenticator. */
    userVerification?: 'required' | 'preferred' | 'discouraged'
    webauthnModule?: WebauthnLibrary
  }
}
