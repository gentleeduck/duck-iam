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
    /** In characters. Default 10. */
    backupCodeLen?: number
    /** Compliance preset(s); ratchets `backupCodeCount` up to the preset floor. */
    compliance?: Compliance.Preset | Compliance.Preset[]
  }

  /** The secret and `otpauth://` URI a TOTP enrollment answers, for the QR code. */
  export type TotpEnrollChallenge = {
    secret: string
    uri: string
  }

  /** What `beginWebauthnMfaEnrollment` takes. */
  export type WebauthnMfaEnrollOpts = {
    /** The relying-party id: the site's registrable domain. */
    rpID: string
    /** Shown in the authenticator's prompt. */
    rpName: string
    /** The account name the authenticator shows. */
    userName: string
    /** The origins a response may come from. */
    expectedOrigins: string | string[]
    /** Where the ceremony's challenge is kept between its two calls. */
    challengeStore: Passkey.ChallengeStore
    /** Ties the enrollment ceremony's pieces together; the session id, typically. */
    challengeKey: string
    /** How long the WebAuthn challenge stays claimable, in ms. */
    challengeTtlMs?: number
    /** WebAuthn user-verification requirement, passed through to the authenticator. */
    userVerification?: 'required' | 'preferred' | 'discouraged'
    /** How much attestation the authenticator is asked for. */
    attestation?: Passkey.RegistrationOptionsInput['attestationType']
    /** Default `[-8, -7, -257]`: Ed25519, ES256 and RS256. */
    supportedAlgorithmIDs?: number[]
    /** Where a test injects its own library instance. */
    webauthnModule?: Passkey.SimpleWebAuthnServerModule
  }

  /** What `confirmWebauthnMfaEnrollment` takes. */
  export type WebauthnMfaConfirmOpts = {
    /** The relying-party id: the site's registrable domain. */
    rpID: string
    /** The origins a response may come from. */
    expectedOrigins: string | string[]
    /** Where the ceremony's challenge is kept between its two calls. */
    challengeStore: Passkey.ChallengeStore
    /** Ties the ceremony's two calls together; the session id, typically. */
    challengeKey: string
    /** The browser's `RegistrationResponseJSON` from `navigator.credentials.create`. */
    response: unknown
    /** WebAuthn user-verification requirement, passed through to the authenticator. */
    userVerification?: 'required' | 'preferred' | 'discouraged'
    /** The algorithms enrollment offered; a key under any other is refused. Default `[-8, -7, -257]`. */
    supportedAlgorithmIDs?: number[]
    /** Where a test injects its own library instance. */
    webauthnModule?: Passkey.SimpleWebAuthnServerModule
  }

  /** What `beginWebauthnMfaVerify` takes. */
  export type WebauthnMfaVerifyBeginOpts = {
    /** The relying-party id: the site's registrable domain. */
    rpID: string
    /** Where the ceremony's challenge is kept between its two calls. */
    challengeStore: Passkey.ChallengeStore
    /** Ties the ceremony's two calls together; the session id, typically. */
    challengeKey: string
    /** How long the WebAuthn challenge stays claimable, in ms. */
    challengeTtlMs?: number
    /** WebAuthn user-verification requirement, passed through to the authenticator. */
    userVerification?: 'required' | 'preferred' | 'discouraged'
    /** Where a test injects its own library instance. */
    webauthnModule?: Passkey.SimpleWebAuthnServerModule
  }

  /** What `verifyWebauthnMfa` takes. */
  export type WebauthnMfaVerifyOpts = {
    /** The relying-party id: the site's registrable domain. */
    rpID: string
    /** The origins a response may come from. */
    expectedOrigins: string | string[]
    /** Where the ceremony's challenge is kept between its two calls. */
    challengeStore: Passkey.ChallengeStore
    /** Ties the ceremony's two calls together; the session id, typically. */
    challengeKey: string
    /** The browser's `AuthenticationResponseJSON` from `navigator.credentials.get`. */
    response: unknown
    /** WebAuthn user-verification requirement, passed through to the authenticator. */
    userVerification?: 'required' | 'preferred' | 'discouraged'
    /** Where a test injects its own library instance. */
    webauthnModule?: Passkey.SimpleWebAuthnServerModule
  }
}
