export namespace PasskeyTypes {
  /**
   * Subset of `@simplewebauthn/server` we depend on. Kept narrow so
   * the lazy import surface stays small.
   */
  export interface ISimpleWebAuthnServerModule {
    generateRegistrationOptions: (opts: IRegistrationOptionsInput) => Promise<IRegistrationOptions>
    verifyRegistrationResponse: (
      opts: IVerifyRegistrationInput,
    ) => Promise<{ verified: boolean; registrationInfo?: IRegistrationInfo }>
    generateAuthenticationOptions: (opts: IAuthenticationOptionsInput) => Promise<IAuthenticationOptions>
    verifyAuthenticationResponse: (
      opts: IVerifyAuthenticationInput,
    ) => Promise<{ verified: boolean; authenticationInfo: IAuthenticationInfo }>
  }

  export interface IRegistrationOptionsInput {
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

  export interface IRegistrationOptions {
    challenge: string
    rp: { id: string; name: string }
    user: { id: string; name: string; displayName?: string }
    pubKeyCredParams: Array<{ alg: number; type: 'public-key' }>
    timeout?: number
    excludeCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>
    authenticatorSelection?: IRegistrationOptionsInput['authenticatorSelection']
    attestation?: string
  }

  export interface IVerifyRegistrationInput {
    response: unknown
    expectedChallenge: string | ((challenge: string) => boolean | Promise<boolean>)
    expectedOrigin: string | string[]
    expectedRPID: string | string[]
    requireUserVerification?: boolean
  }

  export interface IRegistrationInfo {
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

  export interface IAuthenticationOptionsInput {
    rpID: string
    allowCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>
    userVerification?: 'discouraged' | 'preferred' | 'required'
    timeout?: number
  }

  export interface IAuthenticationOptions {
    challenge: string
    rpId: string
    allowCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>
    userVerification?: 'discouraged' | 'preferred' | 'required'
    timeout?: number
  }

  export interface IVerifyAuthenticationInput {
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

  export interface IAuthenticationInfo {
    newCounter: number
    credentialID: string
    userVerified: boolean
  }

  /**
   * Short-lived challenge persistence. Sign-up + sign-in begin store
   * a fresh challenge keyed by `userId` (registration) or `sessionId`
   * (authentication); complete consumes it.
   */
  export interface IChallengeStore {
    put(key: string, challenge: string, ttlMs: number): Promise<void>
    take(key: string): Promise<string | null>
  }
}
