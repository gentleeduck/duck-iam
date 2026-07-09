import { createHash } from 'node:crypto'
import { isFiniteNumber, isRevoked, toCredentialUpsert } from '~/core/credential-utils'
import { AuthError } from '~/core/errors'
import type { Identity } from '~/core/identities/identities.types'
import type { Provider } from '~/core/provider/provider.types'
import type { Credential } from '~/core/types/identity'
import { MemoryPasskeyChallengeStore } from './internal/challenge-store'
import { DEFAULT_PASSKEY_CONFIG } from './passkey.constants'
import type { Passkey } from './passkey.types'

let _webauthnModule: Passkey.SimpleWebAuthnServerModule | null = null
async function loadWebAuthn(
  override?: Passkey.SimpleWebAuthnServerModule,
): Promise<Passkey.SimpleWebAuthnServerModule> {
  if (override) return override
  if (_webauthnModule) return _webauthnModule
  try {
    const mod = (await import('@simplewebauthn/server' as string)) as unknown as Passkey.SimpleWebAuthnServerModule
    _webauthnModule = mod
    return mod
  } catch {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail:
        'AuthPasskeyProvider requires the @simplewebauthn/server peerDep. ' +
        'Install via `bun add @simplewebauthn/server` (or `npm install @simplewebauthn/server`).',
    })
  }
}

/** sha-256 of identity id - stable 32-byte WebAuthn `user.id` (cap is 1-64 bytes; long ids would collide). */
function userIdBytes(identityId: string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(identityId, 'utf8').digest())
}

/** Canonical base64url encoding of the user handle for an identity. */
function userHandleFor(identityId: string): string {
  return Buffer.from(userIdBytes(identityId)).toString('base64url')
}

/** Best-effort decode of a wire `userHandle` to its base64url canonical form.
 * The browser may send base64, base64url, or already-decoded bytes; we
 * normalize so comparisons are stable. */
function decodeUserHandle(wireValue: string): string | null {
  if (!wireValue) return null
  // Already base64url? Strip padding + normalize.
  try {
    return Buffer.from(wireValue, 'base64url').toString('base64url')
  } catch {
    return null
  }
}

/**
 * The `authPasskey` sign-in provider. Sign-up via
 * `authBeginPasskeyRegistration` + `authCompletePasskeyRegistration` (separate
 * exports).
 */
export function passkey<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  opts: Passkey.Options,
): Provider.Me<Passkey.BeginInput, Passkey.CompleteInput, Profile> {
  const challengeStore = opts.challengeStore ?? new MemoryPasskeyChallengeStore()
  const challengeTtlMs = opts.challengeTtlMs ?? DEFAULT_PASSKEY_CONFIG.challengeTtlMs
  const uv = opts.userVerification ?? DEFAULT_PASSKEY_CONFIG.userVerification

  async function resolveAllowList(
    email: string | undefined,
    ctx: Provider.Context<Profile>,
  ): Promise<Array<{ id: string; type: 'public-key' }>> {
    if (!email) return []
    const identity = await opts.findIdentityByEmail(email, ctx.tenant.tenantId)
    if (!identity) return []
    const creds = await ctx.stores.credentials.listByIdentity(identity.id, 'passkey', ctx.tenant)
    // `isRevoked` fails closed; `!revokedAt` would let `revokedAt: 0` slip past.
    return creds.filter((c) => !isRevoked(c)).map((c) => ({ id: c.secret, type: 'public-key' as const }))
  }

  return {
    id: 'passkey',
    kind: 'passkey',

    async begin(ctx, input): Promise<Provider.Intent[]> {
      if (typeof input.sessionId !== 'string' || input.sessionId.length === 0 || input.sessionId.length > 256) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'passkey.begin requires sessionId (string, 1-256 chars)',
        })
      }
      if (input.email !== undefined) {
        if (typeof input.email !== 'string' || input.email.length === 0 || input.email.length > 254) {
          throw new AuthError('AUTH_INVALID_CREDENTIALS')
        }
      }
      const webauthn = await loadWebAuthn(opts.webauthnModule)
      const allowCredentials = await resolveAllowList(input.email, ctx)
      const options: Passkey.AuthenticationOptions = await webauthn.generateAuthenticationOptions({
        rpID: opts.rpID,
        allowCredentials,
        userVerification: uv,
      })
      await challengeStore.put(`auth:${input.sessionId}`, options.challenge, challengeTtlMs)
      return [{ type: 'json', status: 200, body: options }]
    },

    async complete(ctx, input): Promise<Provider.InternalIntent[]> {
      if (typeof input.sessionId !== 'string' || input.sessionId.length === 0 || input.sessionId.length > 256) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'passkey.complete requires sessionId (string, 1-256 chars)',
        })
      }
      const expectedChallenge = await challengeStore.take(`auth:${input.sessionId}`)
      if (!expectedChallenge) {
        throw new AuthError('AUTH_PASSKEY_MISMATCH')
      }
      const webauthn = await loadWebAuthn(opts.webauthnModule)

      const responseObj = input.response as { id?: string }
      const credentialId = responseObj.id
      // WebAuthn credential IDs are base64url-encoded random bytes (<255 raw
      // bytes per spec -> ~340 chars max); 1024 is generous + refuses attacker
      // multi-MB IDs.
      if (typeof credentialId !== 'string' || credentialId.length === 0 || credentialId.length > 1024) {
        throw new AuthError('AUTH_PASSKEY_MISMATCH')
      }
      const cred = await ctx.stores.credentials.findByHashedSecret(credentialId, 'passkey', ctx.tenant)
      if (cred?.kind !== 'passkey' || cred.revokedAt) {
        throw new AuthError('AUTH_PASSKEY_MISMATCH')
      }

      // The `email` field is a security assertion - bind the credential
      // to it so a stolen credentialId cannot impersonate the owner.
      if (input.email !== undefined) {
        const hintedIdentity = await opts.findIdentityByEmail(input.email, ctx.tenant.tenantId)
        if (!hintedIdentity || hintedIdentity.id !== cred.identityId) {
          throw new AuthError('AUTH_PASSKEY_MISMATCH')
        }
      }

      // Bind credential.identityId to response.userHandle when present.
      const responseInner = (input.response as { response?: { userHandle?: string } }).response
      if (responseInner?.userHandle) {
        const decoded = decodeUserHandle(responseInner.userHandle)
        if (decoded !== null && decoded !== userHandleFor(cred.identityId)) {
          throw new AuthError('AUTH_PASSKEY_MISMATCH')
        }
      }

      const meta = parsePasskeyMetadata(cred.metadata)
      if (meta === null) {
        throw new AuthError('AUTH_PASSKEY_MISMATCH')
      }

      const verification = await webauthn.verifyAuthenticationResponse({
        response: input.response,
        expectedChallenge,
        expectedOrigin: opts.expectedOrigins,
        expectedRPID: opts.rpID,
        credential: {
          id: cred.id,
          publicKey: base64UrlDecode(meta.publicKey),
          counter: meta.counter,
          ...(meta.transports !== undefined && { transports: meta.transports }),
        },
        requireUserVerification: uv === 'required',
      })
      if (!verification.verified) {
        throw new AuthError('AUTH_PASSKEY_MISMATCH')
      }

      // Counter rollback detection (WebAuthn L2 section 6.1.3). `newCounter === 0`
      // means the authenticator does not track a counter; allowed.
      // Number.isFinite gates against NaN/Infinity that would short-circuit
      // both `!== 0` and `<= oldCounter` comparisons.
      const newCounter = verification.authenticationInfo.newCounter
      const oldCounter = meta.counter
      if (!Number.isFinite(newCounter) || !Number.isFinite(oldCounter)) {
        throw new AuthError('AUTH_PASSKEY_MISMATCH')
      }
      if (newCounter !== 0 && newCounter <= oldCounter) {
        await ctx.events.emit('suspicious', {
          identityId: cred.identityId,
          signal: 'passkey-counter-rollback',
          score: 1,
          meta: { credentialId: cred.id, oldCounter, newCounter },
        })
        throw new AuthError('AUTH_PASSKEY_MISMATCH')
      }
      if (newCounter > oldCounter) {
        await ctx.stores.credentials.patchMetadata(cred.id, { counter: newCounter }, ctx.tenant)
      }

      return [
        {
          type: 'startSession',
          identityId: cred.identityId,
          factors: [{ method: 'passkey', completedAt: new Date() }],
          aal: 2,
        },
      ]
    },
  }
}

/** Issue a registration ceremony. */
export async function beginPasskeyRegistration(
  opts: Passkey.Options,
  input: { identityId: string; userName: string; userDisplayName?: string; sessionId: string },
): Promise<Passkey.RegistrationOptions> {
  const challengeStore = opts.challengeStore ?? new MemoryPasskeyChallengeStore()
  const challengeTtlMs = opts.challengeTtlMs ?? DEFAULT_PASSKEY_CONFIG.challengeTtlMs
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
      userVerification: opts.userVerification ?? DEFAULT_PASSKEY_CONFIG.userVerification,
    },
  })
  await challengeStore.put(`reg:${input.sessionId}`, options.challenge, challengeTtlMs)
  return options
}

/**
 * Verify the browser response from `navigator.credentials.create()`
 * and persist the new public key as a `authPasskey` credential.
 */
export async function completePasskeyRegistration(
  opts: Passkey.Options,
  input: {
    identityId: string
    sessionId: string
    response: unknown
    credentialStore: Credential.Store
    tenant: { tenantId?: string }
  },
): Promise<string> {
  const challengeStore = opts.challengeStore ?? new MemoryPasskeyChallengeStore()
  const expectedChallenge = await challengeStore.take(`reg:${input.sessionId}`)
  if (!expectedChallenge) {
    throw new AuthError('AUTH_PASSKEY_MISMATCH')
  }
  const webauthn = await loadWebAuthn(opts.webauthnModule)
  const verification = await webauthn.verifyRegistrationResponse({
    response: input.response,
    expectedChallenge,
    expectedOrigin: opts.expectedOrigins,
    expectedRPID: opts.rpID,
    requireUserVerification: (opts.userVerification ?? DEFAULT_PASSKEY_CONFIG.userVerification) === 'required',
  })
  if (!verification.verified || !verification.registrationInfo) {
    throw new AuthError('AUTH_PASSKEY_MISMATCH')
  }
  const info: Passkey.RegistrationInfo = verification.registrationInfo
  const persisted = await input.credentialStore.upsert(
    toCredentialUpsert({
      identityId: input.identityId,
      kind: 'passkey',
      secret: info.credential.id,
      metadata: {
        publicKey: base64UrlEncode(info.credential.publicKey),
        counter: info.credential.counter,
        transports: info.credential.transports ?? [],
        aaguid: info.aaguid,
        deviceType: info.credentialDeviceType,
        backedUp: info.credentialBackedUp,
      } satisfies Passkey.CredentialMetadata,
    }),
    input.tenant,
  )
  return persisted.id
}

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url')
}

function base64UrlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'))
}

/** Parser for a authPasskey credential's `metadata`; `null` on missing publicKey or unparseable counter. */
function parsePasskeyMetadata(meta: Credential.Me['metadata']): Passkey.CredentialMetadata | null {
  if (typeof meta !== 'object' || meta === null || Array.isArray(meta)) return null
  const publicKey = Reflect.get(meta, 'publicKey')
  if (typeof publicKey !== 'string' || publicKey.length === 0) return null
  const counterRaw: unknown = Reflect.get(meta, 'counter')
  const counter = counterRaw === undefined ? 0 : isFiniteNumber(counterRaw) ? counterRaw : null
  if (counter === null) return null
  const transportsRaw: unknown = Reflect.get(meta, 'transports')
  let transports: string[] | undefined
  if (Array.isArray(transportsRaw)) {
    transports = []
    for (const t of transportsRaw) {
      if (typeof t === 'string') transports.push(t)
    }
  }
  const out: Passkey.CredentialMetadata = { publicKey, counter }
  if (transports !== undefined) out.transports = transports
  return out
}
