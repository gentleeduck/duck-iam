import { createHash } from 'node:crypto'
import { orNull } from '~/core/answer'
import { isCredentialExpired, isRevoked, toCredentialCreate } from '~/core/credentials/credentials'
import type { Credential } from '~/core/credentials/credentials.types'
import { AuthError } from '~/core/errors'
import { refuseRateLimited } from '~/core/events/events.lockout'
import { canonicalEmail } from '~/core/identities'
import type { Identities } from '~/core/identities/identities.types'
import { isFiniteNumber } from '~/core/predicates/predicates'
import type { Provider } from '~/core/provider/provider.types'
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

/** sha-256 of the identity id, a stable 32-byte WebAuthn `user.id`. The spec allows 1-64 bytes, and a
 *  long id would otherwise be truncated into a collision. */
function userIdBytes(identityId: string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(identityId, 'utf8').digest())
}

/** Canonical base64url encoding of the user handle for an identity. */
function userHandleFor(identityId: string): string {
  return Buffer.from(userIdBytes(identityId)).toString('base64url')
}

/** A browser may send base64, base64url or already-decoded bytes, so this normalises to base64url and
 *  comparisons stay stable. Anything undecodable normalises to a value that matches no identity, since
 *  `Buffer.from` drops the characters it cannot read rather than refusing the string. */
function decodeUserHandle(wireValue: string): string {
  return Buffer.from(wireValue, 'base64url').toString('base64url')
}

/** The `passkey` sign-in provider. Sign-up goes through {@link beginPasskeyRegistration} and
 *  {@link completePasskeyRegistration}, which are separate exports. */
export class PasskeyImpl<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>
  implements Provider.Me<Passkey.BeginInput, Passkey.CompleteInput, Profile>
{
  readonly id = 'passkey'
  readonly kind = 'passkey' as const
  private readonly challengeStore: Passkey.ChallengeStore
  private readonly challengeTtlMs: number
  private readonly uv: NonNullable<Passkey.Options['userVerification']>
  private readonly prefix: string
  /** Read by `strict()` for the `webauthnAttestationDirect` compliance check, which otherwise has only
   *  the operator's word for it. A boolean the holder computed; it carries nothing else. */
  readonly __requestsDirectAttestation: boolean

  constructor(private readonly opts: Passkey.Options) {
    this.challengeStore = opts.challengeStore ?? new MemoryPasskeyChallengeStore()
    this.challengeTtlMs = opts.challengeTtlMs ?? DEFAULT_PASSKEY_CONFIG.challengeTtlMs
    this.uv = opts.userVerification ?? DEFAULT_PASSKEY_CONFIG.userVerification
    this.prefix = opts.limiterKeyPrefix ?? DEFAULT_PASSKEY_CONFIG.limiterKeyPrefix
    this.__requestsDirectAttestation = (opts.attestationType ?? DEFAULT_PASSKEY_CONFIG.attestationType) === 'direct'
  }

  private async _resolveAllowList(
    email: string | undefined,
    ctx: Provider.Context<Profile>,
  ): Promise<Array<{ id: string; type: 'public-key' }>> {
    if (!email) return []
    const identity = await orNull(this.opts.findIdentityByEmail(email, ctx.tenant.tenantId))
    if (!identity) return []
    const creds = await ctx.stores.credentials.listByIdentity(identity.id, 'passkey', ctx.tenant)
    // `isRevoked` fails closed, where `!revokedAt` would let a `revokedAt: 0` through. Expiry is checked
    // on this offer path too, so the browser is never prompted for an authenticator `complete` will refuse.
    return creds
      .filter((c) => !isRevoked(c) && !isCredentialExpired(c))
      .map((c) => ({ id: c.secret, type: 'public-key' as const }))
  }

  /** Answers the WebAuthn challenge, for registering a passkey or for signing in with one. */
  async begin(ctx: Provider.Context<Profile>, input: Passkey.BeginInput): Promise<Provider.Intent[]> {
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
    // Keyed on the address where one is given: `allowCredentials` comes back populated for an account
    // that exists and empty for one that does not, so an unbounded caller reads that difference off
    // address after address. With no address there is nothing caller-independent at this layer, so the
    // session id bounds the challenge writes a single flow can make.
    const emailCanonical = input.email === undefined ? '' : (canonicalEmail(input.email) ?? '')
    const limited = await ctx.limiter.consume(
      `${this.prefix}${emailCanonical === '' ? `session:${input.sessionId}` : `email:${emailCanonical}`}`,
    )
    // No subject: `findIdentityByEmail` is host code on an unauthenticated endpoint, and a spent bucket
    // refuses a challenge rather than locking anyone out. The call magic-link makes too.
    if (!limited.ok) await refuseRateLimited(ctx.events, limited, null)

    const webauthn = await loadWebAuthn(this.opts.webauthnModule)
    const allowCredentials = await this._resolveAllowList(input.email, ctx)
    const options: Passkey.AuthenticationOptions = await webauthn.generateAuthenticationOptions({
      rpID: this.opts.rpID,
      allowCredentials,
      userVerification: this.uv,
    })
    await this.challengeStore.put(`auth:${input.sessionId}`, options.challenge, this.challengeTtlMs)
    return [{ type: 'json', status: 200, body: options }]
  }

  /** Verifies the authenticator's response and answers the intents that open the session. */
  async complete(ctx: Provider.Context<Profile>, input: Passkey.CompleteInput): Promise<Provider.InternalIntent[]> {
    if (typeof input.sessionId !== 'string' || input.sessionId.length === 0 || input.sessionId.length > 256) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'passkey.complete requires sessionId (string, 1-256 chars)',
      })
    }
    const expectedChallenge = await orNull(this.challengeStore.take(`auth:${input.sessionId}`))
    if (!expectedChallenge) {
      throw new AuthError('AUTH_PASSKEY_MISMATCH')
    }
    const webauthn = await loadWebAuthn(this.opts.webauthnModule)

    const responseObj = input.response as { id?: string }
    const credentialId = responseObj.id
    // A WebAuthn credential id is base64url random bytes, under 255 raw bytes by spec and so ~340 chars
    // at most; 1024 is generous and still refuses a multi-MB id.
    if (typeof credentialId !== 'string' || credentialId.length === 0 || credentialId.length > 1024) {
      throw new AuthError('AUTH_PASSKEY_MISMATCH')
    }
    const cred = await orNull(ctx.stores.credentials.findByHashedSecret(credentialId, 'passkey', ctx.tenant))
    // `isRevoked` fails closed, as on the offer path above: a `revokedAt: 0` from a store that keeps
    // timestamps as epoch ints is falsy, and this is the branch that mints the session.
    // SECURITY: and `isCredentialExpired`, which this branch omitted. An elapsed `expiresAt` is what
    // `ApiKeyImpl.verify` treats as revocation, so a passkey outlived the deadline written on it here.
    if (cred?.kind !== 'passkey' || isRevoked(cred) || isCredentialExpired(cred)) {
      throw new AuthError('AUTH_PASSKEY_MISMATCH')
    }

    // `email` is a security assertion, so the credential is bound to it and a stolen credentialId
    // cannot impersonate the owner.
    if (input.email !== undefined) {
      const hintedIdentity = await orNull(this.opts.findIdentityByEmail(input.email, ctx.tenant.tenantId))
      if (!hintedIdentity || hintedIdentity.id !== cred.identityId) {
        throw new AuthError('AUTH_PASSKEY_MISMATCH')
      }
    }

    // `credential.identityId` is bound to `response.userHandle` when one is present.
    const userHandle: unknown = (input.response as { response?: { userHandle?: unknown } }).response?.userHandle
    // SECURITY: a handle that is not a string is refused, not waved through. `Buffer.from` throws on a
    // number or an object, the decoder answered `null` for the throw, and this read `null` as "no handle
    // was sent" - so `userHandle: 1` switched the binding off from the request itself.
    if (userHandle) {
      if (typeof userHandle !== 'string' || decodeUserHandle(userHandle) !== userHandleFor(cred.identityId)) {
        throw new AuthError('AUTH_PASSKEY_MISMATCH')
      }
    }

    const meta = parsePasskeyMetadata(cred.metadata)
    if (meta === null) {
      throw new AuthError('AUTH_PASSKEY_MISMATCH')
    }

    const verification = await webauthn
      .verifyAuthenticationResponse({
        response: input.response,
        expectedChallenge,
        expectedOrigin: this.opts.expectedOrigins,
        expectedRPID: this.opts.rpID,
        credential: {
          // The credential id the browser knows, which registration stored verbatim - not the storage row
          // id, which is a uuid this library never issued. It only echoes the value back today, so the
          // two behave identically at runtime and the wrong one went unnoticed.
          id: cred.secret,
          publicKey: base64UrlDecode(meta.publicKey),
          counter: meta.counter,
          ...(meta.transports !== undefined && { transports: meta.transports }),
        },
        requireUserVerification: this.uv === 'required',
      })
      .catch(() => {
        // The verifier signals every failure of its own by throwing a plain Error, and the counter one
        // names the stored count. Nothing between here and the consumer's handler catches it, so it left
        // as an unmapped 500; every other refusal on this path is AUTH_PASSKEY_MISMATCH and so is this.
        throw new AuthError('AUTH_PASSKEY_MISMATCH')
      })
    if (!verification.verified) {
      throw new AuthError('AUTH_PASSKEY_MISMATCH')
    }

    // Counter-rollback detection, WebAuthn L2 section 6.1.3. `Number.isFinite` gates the NaN and Infinity
    // that would short-circuit both `!== 0` and `<= oldCounter`.
    const newCounter = verification.authenticationInfo.newCounter
    const oldCounter = meta.counter
    if (!Number.isFinite(newCounter) || !Number.isFinite(oldCounter)) {
      throw new AuthError('AUTH_PASSKEY_MISMATCH')
    }
    // SECURITY: the pair, as section 6.1.3 puts it - "if either ... is nonzero".
    let rollback = (newCounter !== 0 || oldCounter !== 0) && newCounter <= oldCounter
    // The compare-and-set makes reading the count and recording it a single step. Unconditional, they are
    // two steps, and two assertions that both read before either wrote both clear the same count - which
    // is the cloned authenticator, waved through for arriving alongside the real one rather than after it.
    if (!rollback && newCounter > oldCounter) {
      try {
        await ctx.stores.credentials.patchMetadata(cred.id, { counter: newCounter }, ctx.tenant, cred.version)
      } catch (err) {
        if (!(err instanceof AuthError && err.code === 'AUTH_STALE_WRITE')) throw err
        rollback = true
      }
    }
    if (rollback) {
      await ctx.events.emit('suspicious', {
        identityId: cred.identityId,
        signal: 'passkey-counter-rollback',
        score: 1,
        meta: { credentialId: cred.id, oldCounter, newCounter },
      })
      throw new AuthError('AUTH_PASSKEY_MISMATCH')
    }

    return [
      {
        type: 'startSession',
        identityId: cred.identityId,
        factors: [{ method: 'passkey', completedAt: new Date() }],
        aal: 2,
      },
    ]
  }
}

/** The passkey provider, ready to hand to `providers`. */
export function passkey<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  opts: Passkey.Options,
): Provider.Me<Passkey.BeginInput, Passkey.CompleteInput, Profile> {
  return new PasskeyImpl(opts)
}

/** Issues a registration ceremony. */
export async function beginPasskeyRegistration(
  opts: Passkey.Options,
  input: {
    identityId: string
    userName: string
    userDisplayName?: string
    sessionId: string
    credentialStore: Credential.Store
    tenant: { tenantId?: string }
  },
): Promise<Passkey.RegistrationOptions> {
  const challengeStore = opts.challengeStore ?? new MemoryPasskeyChallengeStore()
  const challengeTtlMs = opts.challengeTtlMs ?? DEFAULT_PASSKEY_CONFIG.challengeTtlMs
  const webauthn = await loadWebAuthn(opts.webauthnModule)
  // A revoked passkey is one the user asked to be rid of, so it is not excluded: re-enrolling the same
  // authenticator is the documented way back.
  const existing = await input.credentialStore.listByIdentity(input.identityId, 'passkey', input.tenant)
  const excludeCredentials = existing.filter((c) => !isRevoked(c)).map(toExcludedCredential)
  const options = await webauthn.generateRegistrationOptions({
    rpName: opts.rpName,
    rpID: opts.rpID,
    userID: userIdBytes(input.identityId),
    userName: input.userName,
    userDisplayName: input.userDisplayName,
    attestationType: opts.attestationType ?? DEFAULT_PASSKEY_CONFIG.attestationType,
    excludeCredentials,
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: opts.userVerification ?? DEFAULT_PASSKEY_CONFIG.userVerification,
    },
  })
  await challengeStore.put(`reg:${input.sessionId}`, options.challenge, challengeTtlMs)
  return options
}

/** Verifies the response from `navigator.credentials.create()` and persists the new public key as an
 *  `authPasskey` credential. */
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
  const expectedChallenge = await orNull(challengeStore.take(`reg:${input.sessionId}`))
  if (!expectedChallenge) {
    throw new AuthError('AUTH_PASSKEY_MISMATCH')
  }
  const webauthn = await loadWebAuthn(opts.webauthnModule)
  const verification = await webauthn
    .verifyRegistrationResponse({
      response: input.response,
      expectedChallenge,
      expectedOrigin: opts.expectedOrigins,
      expectedRPID: opts.rpID,
      requireUserVerification: (opts.userVerification ?? DEFAULT_PASSKEY_CONFIG.userVerification) === 'required',
    })
    .catch(() => {
      // As on the authentication side: a throw from the verifier is a refusal, not a server fault.
      throw new AuthError('AUTH_PASSKEY_MISMATCH')
    })
  if (!verification.verified || !verification.registrationInfo) {
    throw new AuthError('AUTH_PASSKEY_MISMATCH')
  }
  const info: Passkey.RegistrationInfo = verification.registrationInfo
  const persisted = await input.credentialStore.create(
    toCredentialCreate({
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

/**
 * A stored passkey row as the browser names it. `secret` is the credential id
 * verbatim; transports come from the metadata when the authenticator reported
 * them, and are omitted rather than guessed when it did not.
 */
function toExcludedCredential(row: Credential.Me): { id: string; type: 'public-key'; transports?: string[] } {
  const transports = parsePasskeyMetadata(row.metadata)?.transports
  return { id: row.secret, type: 'public-key', ...(transports?.length && { transports }) }
}

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url')
}

function base64UrlDecode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'))
}

/** `null` when `publicKey` is missing or the counter will not parse. */
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

/** Constructs {@link PasskeyImpl} directly, for a caller wiring the facet by hand. */
export function passkeyImpl(...args: ConstructorParameters<typeof PasskeyImpl>): PasskeyImpl {
  return new PasskeyImpl(...args)
}
