export namespace Passkey {
  /**
   * Subset of `@simplewebauthn/server` we depend on. Kept narrow so
   * the lazy import surface stays small.
   */
  export type SimpleWebAuthnServerModule = {
    generateRegistrationOptions: (opts: RegistrationOptionsInput) => Promise<RegistrationOptions>
    verifyRegistrationResponse: (
      opts: VerifyRegistrationInput,
    ) => Promise<{ verified: boolean; registrationInfo?: RegistrationInfo }>
    generateAuthenticationOptions: (opts: AuthenticationOptionsInput) => Promise<AuthenticationOptions>
    verifyAuthenticationResponse: (
      opts: VerifyAuthenticationInput,
    ) => Promise<{ verified: boolean; authenticationInfo: AuthenticationInfo }>
  }

  export type RegistrationOptionsInput = {
    rpName: string
    rpID: string
    userID: Uint8Array
    userName: string
    userDisplayName?: string
    attestationType?: 'none' | 'direct' | 'indirect'
    excludeCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>
    authenticatorSelection?: {
      residentKey?: 'discouraged' | 'preferred' | 'required'
      userVerification?: 'discouraged' | 'preferred' | 'required'
    }
    supportedAlgorithmIDs?: number[]
    timeout?: number
  }

  export type RegistrationOptions = {
    challenge: string
    rp: { id: string; name: string }
    user: { id: string; name: string; displayName?: string }
    pubKeyCredParams: Array<{ alg: number; type: 'public-key' }>
    timeout?: number
    excludeCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>
    authenticatorSelection?: RegistrationOptionsInput['authenticatorSelection']
    attestation?: string
  }

  export type VerifyRegistrationInput = {
    response: unknown
    expectedChallenge: string | ((challenge: string) => boolean | Promise<boolean>)
    expectedOrigin: string | string[]
    expectedRPID: string | string[]
    requireUserVerification?: boolean
  }

  export type RegistrationInfo = {
    credential: {
      id: string
      publicKey: Uint8Array
      counter: number
      transports?: string[]
    }
    fmt?: string
    aaguid?: string
    credentialDeviceType?: 'singleDevice' | 'multiDevice'
    credentialBackedUp?: boolean
  }

  export type AuthenticationOptionsInput = {
    rpID: string
    allowCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>
    userVerification?: 'discouraged' | 'preferred' | 'required'
    timeout?: number
  }

  export type AuthenticationOptions = {
    challenge: string
    rpId: string
    allowCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>
    userVerification?: 'discouraged' | 'preferred' | 'required'
    timeout?: number
  }

  export type VerifyAuthenticationInput = {
    response: unknown
    expectedChallenge: string | ((challenge: string) => boolean | Promise<boolean>)
    expectedOrigin: string | string[]
    expectedRPID: string | string[]
    credential: {
      id: string
      publicKey: Uint8Array
      counter: number
      transports?: string[]
    }
    requireUserVerification?: boolean
  }

  export type AuthenticationInfo = {
    newCounter: number
    credentialID: string
    userVerified: boolean
  }

  /**
   * Short-lived challenge persistence. Sign-up + sign-in begin store
   * a fresh challenge keyed by `userId` (registration) or `sessionId`
   * (authentication); complete consumes it.
   */
  export type ChallengeStore = {
    put(key: string, challenge: string, ttlMs: number): Promise<void>
    take(key: string): Promise<string | null>
  }

  /** Cfg knobs for {@link passkey}. */
  export type Options = {
    /** Relying-party display name (shown in the OS picker). */
    rpName: string
    /** Relying-party id - the eTLD+1 the credential will be bound to. */
    rpID: string
    /** Allowed origins for verification. */
    expectedOrigins: string | string[]
    /** Locate identity given an email. */
    findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
    /** Optional override of the challenge store. Default in-memory. */
    challengeStore?: Passkey.ChallengeStore
    /** TTL applied to issued challenges, ms. Default 5 minutes. */
    challengeTtlMs?: number
    /** Required user verification level. Default `'preferred'`. */
    userVerification?: 'discouraged' | 'preferred' | 'required'
    /** Lazy override of the WebAuthn module (tests inject a mock). */
    webauthnModule?: Passkey.SimpleWebAuthnServerModule
  }

  /** Input to begin. */
  export type BeginInput = {
    /** Optional email hint - narrows allowCredentials to that user. */
    email?: string
    /** Caller-supplied stable session id; the challenge is keyed by it. */
    sessionId: string
  }

  /** Input to complete. */
  export type CompleteInput = {
    /** The WebAuthn AuthenticatorAssertionResponse, JSON-encoded. */
    response: unknown
    /** Same sessionId the begin call returned. */
    sessionId: string
    /** Email used in begin (so verify can re-resolve the identity). */
    email?: string
  }

  /** Shape stored in `Credential.ICredential.metadata` for passkey credentials. */
  export type CredentialMetadata = {
    publicKey: string
    counter: number
    transports?: string[]
    aaguid?: string
    deviceType?: string
    backedUp?: boolean
  }
}
