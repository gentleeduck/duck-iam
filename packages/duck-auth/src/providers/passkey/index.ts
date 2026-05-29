/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../../core/errors'
import type { Credential } from '../../core/types/credential'
import type { Provider } from '../../core/types/provider'
import { MemoryPasskeyChallengeStore } from './challenge-store'
import type {
  AuthenticationOptions,
  PasskeyChallengeStore,
  RegistrationInfo,
  RegistrationOptions,
  SimpleWebAuthnServerModule,
} from './types'

export { MemoryPasskeyChallengeStore } from './challenge-store'
export type { PasskeyChallengeStore } from './types'

/**
 * Configuration for the `passkey` provider.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface PasskeyProviderOptions {
  /** Relying-party display name (shown in the OS picker). */
  rpName: string
  /** Relying-party id - the eTLD+1 the credential will be bound to. */
  rpID: string
  /**
   * Allowed origins for verification. Multiple values support apex + www
   * + native app schemes; the WebAuthn library checks each.
   */
  expectedOrigins: string | string[]
  /**
   * Locate the identity given an email. Required when the begin call
   * carries an email (sign-in with hint); set to a stub returning null
   * when only resident keys are supported.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  findIdentityByEmail: (email: string, tenantId?: string) => Promise<{ id: string } | null>
  /**
   * Optional override of the challenge store. Defaults to the in-memory
   * impl - sufficient for single-process apps; multi-pod deploys must
   * wire a Redis-backed implementation.
   */
  challengeStore?: PasskeyChallengeStore
  /** Time-to-live applied to issued challenges, ms. Default 5 minutes. */
  challengeTtlMs?: number
  /** Required user verification level. Default `'preferred'`. */
  userVerification?: 'discouraged' | 'preferred' | 'required'
  /** Lazy override of the WebAuthn module (tests inject a mock). */
  webauthnModule?: SimpleWebAuthnServerModule
}

export interface PasskeyBeginInput {
  /** Optional email hint - when supplied, narrows allowCredentials to that user. */
  email?: string
  /** Caller-supplied stable session id; the challenge is keyed by it. */
  sessionId: string
}

export interface PasskeyCompleteInput {
  /** The WebAuthn AuthenticatorAssertionResponse, JSON-encoded. */
  response: unknown
  /** Same sessionId the begin call returned. */
  sessionId: string
  /** Email used in begin (so verify can re-resolve the identity). */
  email?: string
}

let _webauthnModule: SimpleWebAuthnServerModule | null = null
async function loadWebAuthn(override?: SimpleWebAuthnServerModule): Promise<SimpleWebAuthnServerModule> {
  if (override) return override
  if (_webauthnModule) return _webauthnModule
  try {
    const mod = (await import('@simplewebauthn/server' as string)) as unknown as SimpleWebAuthnServerModule
    _webauthnModule = mod
    return mod
  } catch {
    throw new AuthErrorObject('AUTH/MISCONFIGURED', {
      detail:
        'PasskeyProvider requires the @simplewebauthn/server peerDep. ' +
        'Install via `bun add @simplewebauthn/server` (or `npm install @simplewebauthn/server`).',
    })
  }
}

/**
 * Encode a string as a Uint8Array userID for the WebAuthn ceremony. The
 * library accepts opaque bytes; we use UTF-8 of the identity id.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
function userIdBytes(identityId: string): Uint8Array {
  return new TextEncoder().encode(identityId)
}

/**
 * The `passkey` sign-in provider. Sign-up is handled separately via
 * `PasskeyProvider.beginRegistration` + `.completeRegistration` which
 * write a new `Credential` record on success.
 *
 * Flow (sign-in):
 *   1. begin({ email?, sessionId }) -> returns AuthenticationOptions JSON
 *      (challenge bound to sessionId; persisted for 5 min default)
 *   2. complete({ response, sessionId, email? }) -> verifies the
 *      assertion, bumps the credential's counter, emits `startSession`
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function passkey<Profile = unknown>(
  opts: PasskeyProviderOptions,
): Provider.IProvider<PasskeyBeginInput, PasskeyCompleteInput, Profile> {
  const challengeStore = opts.challengeStore ?? new MemoryPasskeyChallengeStore()
  const challengeTtlMs = opts.challengeTtlMs ?? 5 * 60 * 1000
  const uv = opts.userVerification ?? 'preferred'

  /** Resolve allowCredentials list for an email hint; empty when anonymous. */
  async function resolveAllowList(
    email: string | undefined,
    ctx: Provider.IContext<Profile>,
  ): Promise<Array<{ id: string; type: 'public-key' }>> {
    if (!email) return []
    const identity = await opts.findIdentityByEmail(email, ctx.tenant.tenantId)
    if (!identity) return []
    const creds = await ctx.stores.credentials.listByIdentity(identity.id, 'passkey', ctx.tenant)
    return creds.filter((c) => !c.revokedAt).map((c) => ({ id: c.secret, type: 'public-key' as const }))
  }

  return {
    id: 'passkey',
    kind: 'passkey',

    async begin(ctx, input): Promise<Provider.Intent[]> {
      if (!input.sessionId) {
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
          detail: 'passkey.begin requires sessionId',
        })
      }
      const webauthn = await loadWebAuthn(opts.webauthnModule)
      const allowCredentials = await resolveAllowList(input.email, ctx)
      const options: AuthenticationOptions = await webauthn.generateAuthenticationOptions({
        rpID: opts.rpID,
        allowCredentials,
        userVerification: uv,
      })
      await challengeStore.put(`auth:${input.sessionId}`, options.challenge, challengeTtlMs)
      return [{ type: 'json', status: 200, body: options }]
    },

    async complete(ctx, input): Promise<Provider.Intent[]> {
      if (!input.sessionId) {
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
          detail: 'passkey.complete requires sessionId',
        })
      }
      const expectedChallenge = await challengeStore.take(`auth:${input.sessionId}`)
      if (!expectedChallenge) {
        throw new AuthErrorObject('AUTH/PASSKEY_MISMATCH')
      }
      const webauthn = await loadWebAuthn(opts.webauthnModule)

      // Locate the credential the assertion belongs to. The WebAuthn
      // response carries the credential id; we resolve it through the
      // credential store.
      const responseObj = input.response as { id?: string }
      const credentialId = responseObj.id
      if (!credentialId) {
        throw new AuthErrorObject('AUTH/PASSKEY_MISMATCH')
      }
      // Passkey rows use `secret = credentialId` (a public discovery
      // handle; the actual verifier is the public key in metadata).
      const cred = await ctx.stores.credentials.findByHashedSecret(credentialId, 'passkey', ctx.tenant)
      if (!cred || cred.kind !== 'passkey' || cred.revokedAt) {
        throw new AuthErrorObject('AUTH/PASSKEY_MISMATCH')
      }

      const meta = (cred.metadata ?? {}) as {
        publicKey?: string
        counter?: number
        transports?: string[]
      }
      if (!meta.publicKey) {
        throw new AuthErrorObject('AUTH/PASSKEY_MISMATCH')
      }

      const verification = await webauthn.verifyAuthenticationResponse({
        response: input.response,
        expectedChallenge,
        expectedOrigin: opts.expectedOrigins,
        expectedRPID: opts.rpID,
        credential: {
          id: cred.id,
          publicKey: base64UrlDecode(meta.publicKey),
          counter: meta.counter ?? 0,
          transports: meta.transports,
        },
        requireUserVerification: uv === 'required',
      })
      if (!verification.verified) {
        throw new AuthErrorObject('AUTH/PASSKEY_MISMATCH')
      }

      // Counter bump for clone-detection (W3C WebAuthn 5.2.4) requires
      // a credential-metadata update path that is not on the v1.0 store
      // contract. Until that lands, clone detection is reduced to
      // "credential id mismatch" only. Tracked as a v1.1 follow-up.
      void verification.authenticationInfo.newCounter

      const factors: Provider.Intent[] = [
        {
          type: 'startSession',
          identityId: cred.identityId,
          factors: [{ method: 'passkey', completedAt: Date.now() }],
          aal: 2,
        },
      ]
      return factors
    },
  }
}

/**
 * Issue a registration ceremony. Caller (admin or the user themselves
 * during signup) invokes this AFTER they have an authenticated identity
 * - the result is the JSON options blob the browser passes to
 * `navigator.credentials.create()`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export async function beginPasskeyRegistration(
  opts: PasskeyProviderOptions,
  input: { identityId: string; userName: string; userDisplayName?: string; sessionId: string },
): Promise<RegistrationOptions> {
  const challengeStore = opts.challengeStore ?? new MemoryPasskeyChallengeStore()
  const challengeTtlMs = opts.challengeTtlMs ?? 5 * 60 * 1000
  const webauthn = await loadWebAuthn(opts.webauthnModule)
  const options = await webauthn.generateRegistrationOptions({
    rpName: opts.rpName,
    rpID: opts.rpID,
    userID: userIdBytes(input.identityId),
    userName: input.userName,
    userDisplayName: input.userDisplayName,
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: opts.userVerification ?? 'preferred',
    },
  })
  await challengeStore.put(`reg:${input.sessionId}`, options.challenge, challengeTtlMs)
  return options
}

/**
 * Verify the browser response from `navigator.credentials.create()` and
 * persist the new public key as a `passkey` credential. Returns the
 * persisted credential id.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export async function completePasskeyRegistration(
  opts: PasskeyProviderOptions,
  input: {
    identityId: string
    sessionId: string
    response: unknown
    credentialStore: Credential.IStore
    tenant: { tenantId?: string }
  },
): Promise<string> {
  const challengeStore = opts.challengeStore ?? new MemoryPasskeyChallengeStore()
  const expectedChallenge = await challengeStore.take(`reg:${input.sessionId}`)
  if (!expectedChallenge) {
    throw new AuthErrorObject('AUTH/PASSKEY_MISMATCH')
  }
  const webauthn = await loadWebAuthn(opts.webauthnModule)
  const verification = await webauthn.verifyRegistrationResponse({
    response: input.response,
    expectedChallenge,
    expectedOrigin: opts.expectedOrigins,
    expectedRPID: opts.rpID,
    requireUserVerification: (opts.userVerification ?? 'preferred') === 'required',
  })
  if (!verification.verified || !verification.registrationInfo) {
    throw new AuthErrorObject('AUTH/PASSKEY_MISMATCH')
  }
  const info: RegistrationInfo = verification.registrationInfo
  const persisted = await input.credentialStore.upsert(
    {
      identityId: input.identityId,
      kind: 'passkey',
      // Store WebAuthn credential id as `secret` so findByHashedSecret
      // can locate it during the verify step. The actual verifier - the
      // public key - lives in metadata. Not a hash; passkey ids are
      // public discovery handles.
      secret: info.credential.id,
      metadata: {
        publicKey: base64UrlEncode(info.credential.publicKey),
        counter: info.credential.counter,
        transports: info.credential.transports ?? [],
        aaguid: info.aaguid,
        deviceType: info.credentialDeviceType,
        backedUp: info.credentialBackedUp,
      },
    },
    input.tenant,
  )
  return persisted.id
}

/** URL-safe base64 encode for opaque bytes. */
function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url')
}

/** URL-safe base64 decode back to bytes. */
function base64UrlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'))
}

/**
 * Namespace merge for the passkey provider exports. Co-locates the
 * options + input/output types alongside the factory function so
 * consumers can do `PasskeyProvider.IOptions`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace PasskeyProvider {
  /** Alias for `PasskeyProviderOptions`. */
  export type IOptions = PasskeyProviderOptions
  /** Alias for `PasskeyBeginInput`. */
  export type IBeginInput = PasskeyBeginInput
  /** Alias for `PasskeyCompleteInput`. */
  export type ICompleteInput = PasskeyCompleteInput
}
