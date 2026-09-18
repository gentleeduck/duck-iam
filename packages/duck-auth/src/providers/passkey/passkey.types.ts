/** Passkey options, the WebAuthn surface it needs, and the challenge store contract. */
export namespace Passkey {
  /** The subset of `@simplewebauthn/server` this depends on, kept narrow so the lazy import surface stays
   *  small. */
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

  /** Short-lived challenge persistence. Both begin paths store a fresh challenge, keyed by `userId` for
   *  registration and `sessionId` for authentication, and complete consumes it. */
  export type ChallengeStore = {
    put(key: string, challenge: string, ttlMs: number): Promise<void>
    /** Reads and deletes in one step. Rejects `AUTH_CREDENTIAL_NOT_FOUND` for a key never put, an elapsed
     *  TTL and a challenge already consumed; all three are a replay as far as the caller is concerned, and
     *  it answers `AUTH_PASSKEY_MISMATCH` for every one. */
    take(key: string): Promise<string>
  }

  export type Options = {
    /** Shown in the OS picker. */
    rpName: string
    /** The eTLD+1 the credential is bound to. */
    rpID: string
    /** Allowed origins for verification. */
    expectedOrigins: string | string[]
    /** How an identity is found from an email. Returning `null` and rejecting with an absence code both
     *  read as "no such address", so `auth.identities.getByEmail` wires straight in. */
    findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
    /** In-memory by default. */
    challengeStore?: Passkey.ChallengeStore
    /** Default 5 minutes. */
    challengeTtlMs?: number
    /** Default `'preferred'`. */
    userVerification?: 'discouraged' | 'preferred' | 'required'
    /** How much attestation registration asks the authenticator for. Default `'none'`; the `fips`
     *  compliance preset requires `'direct'`. */
    attestationType?: 'none' | 'direct' | 'indirect'
    /** Default `passkey:begin:`. */
    limiterKeyPrefix?: string
    /** Where a test injects a mock WebAuthn module. */
    webauthnModule?: Passkey.SimpleWebAuthnServerModule
  }

  export type BeginInput = {
    /** Narrows `allowCredentials` to that user. */
    email?: string
    /** Caller-supplied stable session id; the challenge is keyed by it. */
    sessionId: string
  }

  export type CompleteInput = {
    /** A JSON-encoded WebAuthn `AuthenticatorAssertionResponse`. */
    response: unknown
    /** The one the begin call answered. */
    sessionId: string
    /** The address begin used, so verify re-resolves the same identity. */
    email?: string
  }

  /** Shape stored in `Credential.Me.metadata` for passkey credentials. */
  export type CredentialMetadata = {
    publicKey: string
    counter: number
    transports?: string[]
    aaguid?: string
    deviceType?: string
    backedUp?: boolean
  }
}
