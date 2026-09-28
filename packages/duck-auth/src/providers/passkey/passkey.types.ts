/** Passkey options, the WebAuthn surface it needs, and the challenge store contract. */
export namespace Passkey {
  /** The subset of `@simplewebauthn/server` this depends on, checked against the library where
   *  `loadWebAuthn` imports it. */
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

  /** A transport as the library names one. */
  export type Transport = 'ble' | 'cable' | 'hybrid' | 'internal' | 'nfc' | 'smart-card' | 'usb'

  /** `generateRegistrationOptions` input, as the library types it. */
  export type RegistrationOptionsInput = {
    rpName: string
    rpID: string
    userID: Uint8Array<ArrayBuffer>
    userName: string
    userDisplayName?: string
    attestationType?: 'none' | 'direct' | 'enterprise'
    excludeCredentials?: Array<{ id: string; type: 'public-key'; transports?: Transport[] }>
    authenticatorSelection?: {
      residentKey?: 'discouraged' | 'preferred' | 'required'
      userVerification?: 'discouraged' | 'preferred' | 'required'
    }
    supportedAlgorithmIDs?: number[]
    timeout?: number
  }

  /** `generateRegistrationOptions` output, as the library types it. */
  export type RegistrationOptions = {
    challenge: string
    rp: { id?: string; name: string }
    user: { id: string; name: string; displayName?: string }
    pubKeyCredParams: Array<{ alg: number; type: 'public-key' }>
    timeout?: number
    excludeCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>
    authenticatorSelection?: RegistrationOptionsInput['authenticatorSelection']
    attestation?: string
  }

  /** `verifyRegistrationResponse` input, as the library types it. */
  export type VerifyRegistrationInput = {
    /** The client's JSON, unparsed: the library validates the shape its type assumes. */
    response: any
    expectedChallenge: string | ((challenge: string) => boolean | Promise<boolean>)
    expectedOrigin: string | string[]
    expectedRPID: string | string[]
    requireUserVerification?: boolean
    supportedAlgorithmIDs?: number[]
  }

  /** A verified registration, as the library types it. */
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

  /** `generateAuthenticationOptions` input, as the library types it. */
  export type AuthenticationOptionsInput = {
    rpID: string
    allowCredentials?: Array<{ id: string; type: 'public-key'; transports?: Transport[] }>
    userVerification?: 'discouraged' | 'preferred' | 'required'
    timeout?: number
  }

  /** `generateAuthenticationOptions` output, as the library types it. */
  export type AuthenticationOptions = {
    challenge: string
    rpId?: string
    allowCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>
    userVerification?: 'discouraged' | 'preferred' | 'required'
    timeout?: number
  }

  /** `verifyAuthenticationResponse` input, as the library types it. */
  export type VerifyAuthenticationInput = {
    /** The client's JSON, unparsed: the library validates the shape its type assumes. */
    response: any
    expectedChallenge: string | ((challenge: string) => boolean | Promise<boolean>)
    expectedOrigin: string | string[]
    expectedRPID: string | string[]
    credential: {
      id: string
      publicKey: Uint8Array<ArrayBuffer>
      counter: number
      transports?: Transport[]
    }
    requireUserVerification?: boolean
  }

  /** A verified authentication, as the library types it. */
  export type AuthenticationInfo = {
    newCounter: number
    credentialID: string
    userVerified: boolean
  }

  /** Short-lived challenge persistence. Both begin paths store a fresh challenge, keyed by `userId` for
   *  registration and `sessionId` for authentication, and complete consumes it. */
  export type ChallengeStore = {
    /** Stores `challenge` under `key` for `ttlMs`. */
    put(key: string, challenge: string, ttlMs: number): Promise<void>
    /** Reads and deletes in one step. Rejects `AUTH_CREDENTIAL_NOT_FOUND` for a key never put, an elapsed
     *  TTL and a challenge already consumed; all three are a replay as far as the caller is concerned, and
     *  it answers `AUTH_PASSKEY_MISMATCH` for every one. */
    take(key: string): Promise<string>
  }

  /** The relying party, and where challenges are kept. */
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
    /** Default `'preferred'`. A sign-in the authenticator did not verify the user for opens an AAL 1 session;
     *  `'required'` refuses it instead. */
    userVerification?: 'discouraged' | 'preferred' | 'required'
    /** How much attestation registration asks the authenticator for. Default `'none'`; the `fips`
     *  compliance preset requires `'direct'`. */
    attestationType?: Passkey.RegistrationOptionsInput['attestationType']
    /** Default `passkey:begin:`. */
    limiterKeyPrefix?: string
    /** Where a test injects a mock WebAuthn module. */
    webauthnModule?: Passkey.SimpleWebAuthnServerModule
  }

  /** What starting a passkey sign-in takes. */
  export type BeginInput = {
    /** Narrows `allowCredentials` to that user. */
    email?: string
    /** Caller-supplied stable session id; the challenge is keyed by it. */
    sessionId: string
  }

  /** What finishing a passkey sign-in takes. */
  export type CompleteInput = {
    /** The browser's `AuthenticationResponseJSON` from `navigator.credentials.get`. */
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
    transports?: Transport[]
    aaguid?: string
    deviceType?: string
    backedUp?: boolean
  }
}
