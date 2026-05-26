/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

/**
 * Subset of `@simplewebauthn/server` we depend on. Kept narrow so the
 * lazy import surface (and the auth lib's coupling to a single WebAuthn
 * library version) stays small.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface SimpleWebAuthnServerModule {
  generateRegistrationOptions: (opts: RegistrationOptionsInput) => Promise<RegistrationOptions>
  verifyRegistrationResponse: (
    opts: VerifyRegistrationInput,
  ) => Promise<{ verified: boolean; registrationInfo?: RegistrationInfo }>
  generateAuthenticationOptions: (opts: AuthenticationOptionsInput) => Promise<AuthenticationOptions>
  verifyAuthenticationResponse: (
    opts: VerifyAuthenticationInput,
  ) => Promise<{ verified: boolean; authenticationInfo: AuthenticationInfo }>
}

export interface RegistrationOptionsInput {
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

export interface RegistrationOptions {
  challenge: string
  rp: { id: string; name: string }
  user: { id: string; name: string; displayName?: string }
  pubKeyCredParams: Array<{ alg: number; type: 'public-key' }>
  timeout?: number
  excludeCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>
  authenticatorSelection?: RegistrationOptionsInput['authenticatorSelection']
  attestation?: string
}

export interface VerifyRegistrationInput {
  response: unknown
  expectedChallenge: string | ((challenge: string) => boolean | Promise<boolean>)
  expectedOrigin: string | string[]
  expectedRPID: string | string[]
  requireUserVerification?: boolean
}

export interface RegistrationInfo {
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

export interface AuthenticationOptionsInput {
  rpID: string
  allowCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>
  userVerification?: 'discouraged' | 'preferred' | 'required'
  timeout?: number
}

export interface AuthenticationOptions {
  challenge: string
  rpId: string
  allowCredentials?: Array<{ id: string; type: 'public-key'; transports?: string[] }>
  userVerification?: 'discouraged' | 'preferred' | 'required'
  timeout?: number
}

export interface VerifyAuthenticationInput {
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

export interface AuthenticationInfo {
  newCounter: number
  credentialID: string
  userVerified: boolean
}

/**
 * Short-lived challenge persistence. Sign-up + sign-in begin store a
 * fresh challenge keyed by `userId` (registration) or `sessionId`
 * (authentication); complete consumes it. Implementations must TTL the
 * entry (default 5 min) and may be Redis-backed in production.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface PasskeyChallengeStore {
  put(key: string, challenge: string, ttlMs: number): Promise<void>
  take(key: string): Promise<string | null>
}
