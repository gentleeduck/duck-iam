import { createHash } from 'node:crypto'
import { type Answer, answer, orNull } from '~/core/answer'
import { isCredentialExpired, isRevoked, toCredentialCreate, toPublicCredential } from '~/core/credentials/credentials'
import type { Credential } from '~/core/credentials/credentials.types'
import { AuthError } from '~/core/errors'
import { refuseRateLimited } from '~/core/events/events.lockout'
import { canonicalEmail } from '~/core/identities'
import type { Identities } from '~/core/identities/identities.types'
import { isFiniteNumber, isRecord } from '~/core/predicates/predicates'
import type { Provider } from '~/core/provider/provider.types'
import type { TenantContext } from '~/core/tenant'
import { MemoryPasskeyChallengeStore } from './internal/challenge-store'
import { DEFAULT_PASSKEY_CONFIG } from './passkey.constants'
import type { Passkey } from './passkey.types'

/** The `challengeStore` default for the two registration helpers. Shared, because `begin` and
 *  `complete` are separate calls: one store per call writes the challenge where the other will not
 *  look, so the documented in-memory default could not complete a registration at all. */
const DEFAULT_CHALLENGE_STORE = new MemoryPasskeyChallengeStore()

/** Lazy, so an app that never uses WebAuthn pays no peerDep cost. WebAuthn MFA loads it here too. */
export async function loadWebAuthn(
  override?: Passkey.SimpleWebAuthnServerModule,
): Promise<Passkey.SimpleWebAuthnServerModule> {
  if (override) return override
  try {
    const mod: Passkey.SimpleWebAuthnServerModule = await import('@simplewebauthn/server')
    return mod
  } catch {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail:
        'WebAuthn requires the @simplewebauthn/server peerDep. ' +
        'Install via `bun add @simplewebauthn/server` (or `npm install @simplewebauthn/server`).',
    })
  }
}

/** sha-256 of the identity id, a stable 32-byte WebAuthn `user.id`. The spec allows 1-64 bytes, and a
 *  long id would otherwise be truncated into a collision. */
function userIdBytes(identityId: string): Uint8Array<ArrayBuffer> {
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
  /** Read by `strict()`, which holds the provider and never the store. A boolean the holder computed;
   *  a foreign `ChallengeStore` publishes no brand and is not judged. */
  readonly __inProcessChallengeStore: boolean

  constructor(private readonly opts: Passkey.Options) {
    this.challengeStore = opts.challengeStore ?? new MemoryPasskeyChallengeStore()
    this.challengeTtlMs = opts.challengeTtlMs ?? DEFAULT_PASSKEY_CONFIG.challengeTtlMs
    if (!Number.isFinite(this.challengeTtlMs) || this.challengeTtlMs <= 0) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `passkey: challengeTtlMs must be a finite positive number (got ${this.challengeTtlMs})`,
      })
    }
    this.uv = opts.userVerification ?? DEFAULT_PASSKEY_CONFIG.userVerification
    this.prefix = opts.limiterKeyPrefix ?? DEFAULT_PASSKEY_CONFIG.limiterKeyPrefix
    this.__requestsDirectAttestation = (opts.attestationType ?? DEFAULT_PASSKEY_CONFIG.attestationType) === 'direct'
    this.__inProcessChallengeStore = Reflect.get(this.challengeStore, '__isInProcessChallengeStore') === true
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

    // A response that is not an object is refused, not left to throw a TypeError.
    if (!isRecord(input.response)) {
      throw new AuthError('AUTH_PASSKEY_MISMATCH')
    }
    const credentialId = input.response.id
    if (
      typeof credentialId !== 'string' ||
      credentialId.length === 0 ||
      credentialId.length > DEFAULT_PASSKEY_CONFIG.maxCredentialIdChars
    ) {
      throw new AuthError('AUTH_PASSKEY_MISMATCH')
    }
    const cred = await orNull(ctx.stores.credentials.findByHashedSecret(credentialId, 'passkey', ctx.tenant))
    // SECURITY: both predicates, as on the offer path above. `isRevoked` fails closed on a `revokedAt: 0`
    // that a store keeping epoch ints makes falsy, and `isCredentialExpired` - omitted here - is what let
    // a passkey outlive the deadline written on it. This is the branch that mints the session.
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
    const assertion = input.response.response
    const userHandle = isRecord(assertion) ? assertion.userHandle : undefined
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
          // 0 turns off the verifier's own count check, which throws before the signature is checked and so
          // cannot report; the check below runs on a verified signature and reports the rollback.
          counter: 0,
          ...(meta.transports !== undefined && { transports: meta.transports }),
        },
        requireUserVerification: this.uv === 'required',
      })
      .catch(() => {
        // The verifier signals every failure of its own by throwing a plain Error, which left as an
        // unmapped 500; every other refusal on this path is AUTH_PASSKEY_MISMATCH and so is this.
        throw new AuthError('AUTH_PASSKEY_MISMATCH')
      })
    if (!verification.verified) {
      throw new AuthError('AUTH_PASSKEY_MISMATCH')
    }

    // Counter-rollback detection, WebAuthn L2 section 6.1.3. `parsePasskeyMetadata` already refused a stored
    // count that is not finite; a reported NaN or Infinity would short-circuit both `!== 0` and `<= oldCounter`.
    const newCounter = verification.authenticationInfo.newCounter
    const oldCounter = meta.counter
    if (!Number.isFinite(newCounter)) {
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
        // SECURITY: two factors only when the authenticator verified the user. Presence alone, which
        // `userVerification: 'preferred'` accepts from a security key with no PIN, is possession.
        aal: verification.authenticationInfo.userVerified ? 2 : 1,
      },
    ]
  }

  /** The identity's passkeys that are not revoked. */
  async list(identityId: string, credentials: Credential.Store, ctx: TenantContext = {}): Promise<Credential.Public[]> {
    const rows = await credentials.listByIdentity(identityId, 'passkey', ctx)
    return rows.filter((r) => !isRevoked(r)).map(toPublicCredential)
  }

  /** Revoke one passkey, answering it as it stands revoked. A row that is not a passkey this identity
   *  holds rejects as absent, so an id read off another account revokes nothing. */
  revoke(
    identityId: string,
    credentialId: string,
    credentials: Credential.Store,
    ctx: TenantContext = {},
  ): Answer.Me<Credential.Public> {
    return answer(async () => {
      const existing = await credentials.findById(credentialId, ctx)
      if (existing.kind !== 'passkey' || existing.identityId !== identityId) {
        throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')
      }
      return toPublicCredential(await credentials.revoke(credentialId, ctx))
    })
  }

  /** Revoke every live passkey the identity holds in one write, answering them as they stand revoked. */
  async revokeAll(
    identityId: string,
    credentials: Credential.Store,
    ctx: TenantContext = {},
  ): Promise<Credential.Public[]> {
    return (await credentials.revokeByKind(identityId, 'passkey', ctx)).map(toPublicCredential)
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
  const challengeStore = opts.challengeStore ?? DEFAULT_CHALLENGE_STORE
  const challengeTtlMs = opts.challengeTtlMs ?? DEFAULT_PASSKEY_CONFIG.challengeTtlMs
  if (!Number.isFinite(challengeTtlMs) || challengeTtlMs <= 0) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `passkey: challengeTtlMs must be a finite positive number (got ${challengeTtlMs})`,
    })
  }
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
    supportedAlgorithmIDs: DEFAULT_PASSKEY_CONFIG.supportedAlgorithmIDs,
    excludeCredentials,
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: opts.userVerification ?? DEFAULT_PASSKEY_CONFIG.userVerification,
    },
  })
  await challengeStore.put(`reg:${input.sessionId}`, options.challenge, challengeTtlMs)
  return options
}

/** Verifies the response from `navigator.credentials.create()`, stores it as a `passkey` credential and
 *  answers the row's id. */
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
  const challengeStore = opts.challengeStore ?? DEFAULT_CHALLENGE_STORE
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
      // SECURITY: WebAuthn 7.1 takes only a key algorithm registration offered. Left out, the verifier took
      // any it knows, SHA-1 RSA among them.
      supportedAlgorithmIDs: DEFAULT_PASSKEY_CONFIG.supportedAlgorithmIDs,
    })
    .catch(() => {
      // As on the authentication side: a throw from the verifier is a refusal, not a server fault.
      throw new AuthError('AUTH_PASSKEY_MISMATCH')
    })
  if (!verification.verified || !verification.registrationInfo) {
    throw new AuthError('AUTH_PASSKEY_MISMATCH')
  }
  const info: Passkey.RegistrationInfo = verification.registrationInfo
  // WebAuthn 7.1 fails an id past the cap, which sign-in could never present.
  if (info.credential.id.length > DEFAULT_PASSKEY_CONFIG.maxCredentialIdChars) {
    throw new AuthError('AUTH_PASSKEY_MISMATCH')
  }
  // SECURITY: the credential id is the authenticator's to choose, and sign-in answers the newest row that
  // carries it, so an account registering an id read off another's `allowCredentials` locked that owner
  // out. WebAuthn 7.1 refuses a credential id already registered.
  if (await orNull(input.credentialStore.findByHashedSecret(info.credential.id, 'passkey', input.tenant))) {
    throw new AuthError('AUTH_PASSKEY_MISMATCH')
  }
  const persisted = await input.credentialStore.create(
    toCredentialCreate({
      identityId: input.identityId,
      kind: 'passkey',
      secret: info.credential.id,
      metadata: {
        publicKey: base64UrlEncode(info.credential.publicKey),
        counter: info.credential.counter,
        transports: knownTransports(info.credential.transports),
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
function toExcludedCredential(row: Credential.Me): {
  id: string
  type: 'public-key'
  transports?: Passkey.Transport[]
} {
  const transports = parsePasskeyMetadata(row.metadata)?.transports
  return { id: row.secret, type: 'public-key', ...(transports?.length && { transports }) }
}

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url')
}

function base64UrlDecode(s: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array(Buffer.from(s, 'base64url'))
}

const TRANSPORTS: readonly Passkey.Transport[] = ['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb']

/** The known transports in `raw`, once each and in the order sent. The library passes on whatever JSON the
 *  registering client sent. */
export function knownTransports(raw: unknown): Passkey.Transport[] {
  if (!Array.isArray(raw)) return []
  return [...new Set(raw.flatMap((sent) => TRANSPORTS.filter((known) => known === sent)))]
}

/** `null` when `publicKey` is missing or the counter will not parse. Read by WebAuthn MFA too, whose rows
 *  carry the same three fields. */
export function parsePasskeyMetadata(meta: Credential.Me['metadata']): Passkey.CredentialMetadata | null {
  if (typeof meta !== 'object' || meta === null || Array.isArray(meta)) return null
  const publicKey = Reflect.get(meta, 'publicKey')
  if (typeof publicKey !== 'string' || publicKey.length === 0) return null
  const counterRaw: unknown = Reflect.get(meta, 'counter')
  const counter = counterRaw === undefined ? 0 : isFiniteNumber(counterRaw) ? counterRaw : null
  if (counter === null) return null
  const transports: unknown = Reflect.get(meta, 'transports')
  const out: Passkey.CredentialMetadata = { publicKey, counter }
  if (Array.isArray(transports)) out.transports = knownTransports(transports)
  return out
}

/** Constructs {@link PasskeyImpl} directly, for a caller wiring the facet by hand. */
export function passkeyImpl(...args: ConstructorParameters<typeof PasskeyImpl>): PasskeyImpl {
  return new PasskeyImpl(...args)
}
