import { orNull } from '~/core/answer'
import { resolveCompliance } from '~/core/compliance'
import { isCredentialExpired, isRevoked, toCredentialCreate } from '~/core/credentials/credentials'
import type { Credential } from '~/core/credentials/credentials.types'
import { AuthError } from '~/core/errors'
import { refuseRateLimited } from '~/core/events/events.lockout'
import { canonicalEmail, type Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import type { TenantContext } from '~/core/tenant'
import {
  COMMON_PASSWORDS,
  DEFAULT_PASSWORDS_CONFIG,
  NO_CREDENTIAL_REFRENCE,
  NO_IDENTITY_SENTINEL,
} from './passwords.constants'
import type { Passwords } from './passwords.types'

/** Password provider: verifies a plaintext against the stored hash and rehashes when parameters move. */
export class PasswordsImpl<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>
  implements Provider.Me<Passwords.BeginInput, Passwords.CompleteInput, Profile>
{
  readonly id = 'password'
  readonly kind = 'password' as const
  readonly cfg: Omit<Passwords.Cfg, 'compliance'>
  // A lazy reference hash for `verify`'s no-credential branch, so the hasher does its scrypt or argon2
  // work and the timing matches the existing-user path, against wall-clock enumeration.
  private _referenceHash: string | null = null
  /** What `this.cfg.hasher` answered about the `fipsValidatedHasher` compliance check, or `undefined` for
   *  a hasher that publishes no answer. `AuthEngine.strict()` omits the check entirely in that case, so a
   *  host's own FIPS-validated implementation is attested for rather than refused. */
  readonly __fipsValidatedHasher: boolean | undefined
  /** Whether `this.cfg.hasher` reports parameters below its own defaults, for `strict()` to refuse in
   *  production. `undefined` for a hasher that publishes no answer. */
  readonly __weakHasherParams: boolean | undefined

  constructor(readonly _cfg?: Partial<Passwords.Cfg>) {
    const floor = _cfg?.compliance ? resolveCompliance(_cfg.compliance).passwords.minLength : 0
    this.cfg = {
      limiterKeyPrefix: _cfg?.limiterKeyPrefix ?? DEFAULT_PASSWORDS_CONFIG.limiterKeyPrefix,
      autoRehash: _cfg?.autoRehash ?? DEFAULT_PASSWORDS_CONFIG.autoRehash,
      minLength: Math.max(_cfg?.minLength ?? DEFAULT_PASSWORDS_CONFIG.minLength, floor),
      maxLength: _cfg?.maxLength ?? DEFAULT_PASSWORDS_CONFIG.maxLength,
      rejectCommon: _cfg?.rejectCommon ?? DEFAULT_PASSWORDS_CONFIG.rejectCommon,
      hasher: _cfg?.hasher ?? DEFAULT_PASSWORDS_CONFIG.hasher,
    }
    const brand: unknown = Reflect.get(this.cfg.hasher, '__fipsParams')
    this.__fipsValidatedHasher = typeof brand === 'boolean' ? brand : undefined
    const weak: unknown = Reflect.get(this.cfg.hasher, '__weakHasherParams')
    this.__weakHasherParams = typeof weak === 'boolean' ? weak : undefined
  }

  /** A cached encoded hash to feed `hasher.verify` in the no-credential branch. The plaintext is fixed and
   *  irrelevant; what matters is that the output is a real hash string the hasher will work against. */
  private async _ensureReferenceHash(): Promise<string> {
    if (this._referenceHash !== null) return this._referenceHash
    this._referenceHash = await this.cfg.hasher.hash(NO_CREDENTIAL_REFRENCE)
    return this._referenceHash
  }

  /** Throws `AUTH_INVALID_CREDENTIALS` for a weak password, never naming the rule it broke. */
  private _validateStrength(plaintext: string): void {
    if (plaintext.length < this.cfg.minLength) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
    // An upper bound against a CPU and memory DoS through argon2 or scrypt: 1024 chars is well above any
    // human-typed password and far below where the memory cost amplifies.
    if (plaintext.length > this.cfg.maxLength) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
    if (this.cfg.rejectCommon && COMMON_PASSWORDS.has(plaintext.toLowerCase())) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
  }

  /** Re-hashes under the current params on a successful verify that reported `needsRehash`, so a
   *  parameter upgrade rolls out as people sign in. */
  async rehash(
    identityId: string,
    plaintext: string,
    credentials: Credential.Store,
    ctx: TenantContext = {},
  ): Promise<void> {
    if (plaintext.length > this.cfg.maxLength) return
    // Hashed before the row is read, so the version below is not held across the hasher's whole cost:
    // `verify`'s own `lastUsedAt` rotate lands inside the hash and the compare-and-set below loses to it.
    const newSecret = await this.cfg.hasher.hash(plaintext)
    const rows = await credentials.listByIdentity(identityId, 'password', ctx)
    // The same row `verify` accepts, expiry included, so a rehash cannot rewrite one a sign-in refused.
    const row = rows.find((c) => !isRevoked(c) && !isCredentialExpired(c))
    if (!row) return
    await credentials.rotate(row.id, newSecret, row.version, ctx)
  }

  /** For the signUp and reset flows. */
  async set(
    identityId: string,
    plaintext: string,
    credentials: Credential.Store,
    ctx: TenantContext = {},
  ): Promise<void> {
    if (typeof identityId !== 'string' || identityId.length === 0 || identityId.length > 256) {
      throw new AuthError('AUTH_UNAUTHENTICATED')
    }
    this._validateStrength(plaintext)
    const secret = await this.cfg.hasher.hash(plaintext)
    // Delete the previous row, then create: two operations, because the adapter contract has no
    // single-call "replace by kind". The window is short, and `SessionsImpl.rotateOrCreate` covers it.
    await credentials.deleteByKind(identityId, 'password', ctx)
    await credentials.create(
      toCredentialCreate({
        identityId,
        kind: 'password',
        secret,
        metadata: { algorithm: this.cfg.hasher.id },
      }),
      ctx,
    )
  }

  /** Answers `{ ok: true, needsRehash }` on a match, `needsRehash` meaning the stored hash used weaker
   *  params than the current ones.
   *  SECURITY: the hasher runs even with no credential, so the exists and does-not-exist branches take
   *  the same time. */
  async verify(
    identityId: string,
    plaintext: string,
    credentials: Credential.Store,
    ctx: TenantContext = {},
  ): Promise<{ ok: true; needsRehash: boolean } | { ok: false }> {
    // Capped before hashing, so a multi-MB input cannot DoS the argon2 or scrypt verify path.
    if (plaintext.length > this.cfg.maxLength) {
      return { ok: false }
    }
    const rows = await credentials.listByIdentity(identityId, 'password', ctx)
    // SECURITY: `expiresAt` beside `revokedAt`. It is a column on every credential and `ApiKeysFacet`
    // already refuses an elapsed one, so a password carrying a rotation deadline signed in for ever past
    // it, while `isStandingFactor` counted that same row as no way into the account at all.
    const row = rows.find((c) => !isRevoked(c) && !isCredentialExpired(c)) ?? null
    // A real reference hash here, so both branches pay the full hasher cost and neither can be told
    // from the other by timing.
    const reference = row?.secret ?? (await this._ensureReferenceHash())
    const ok = await this.cfg.hasher.verify(plaintext, reference)
    if (!row || !ok) return { ok: false }
    // Opportunistic, and an adapter error is ignored.
    void credentials.rotate(row.id, row.secret, row.version, ctx).catch(() => {})
    return { ok: true, needsRehash: this.cfg.hasher.needsRehash(row.secret) }
  }

  /** No begin step: a password is presented outright, not negotiated. */
  async begin(_ctx: Provider.Context<Profile>, _input: Passwords.BeginInput): Promise<Provider.Intent[]> {
    return []
  }

  /** Verifies the password and answers the intents that open the session. */
  async complete(ctx: Provider.Context<Profile>, input: Passwords.CompleteInput): Promise<Provider.InternalIntent[]> {
    const { email, password: pw } = input
    // The email cap is RFC 5321's 254, and the password cap is the configured `maxLength`, 1024 by
    // default. Uncapped, a huge input reaches the hasher and the store.
    if (
      typeof email !== 'string' ||
      typeof pw !== 'string' ||
      email.length === 0 ||
      email.length > 254 ||
      pw.length === 0 ||
      pw.length > this.cfg.maxLength
    ) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }

    // Canonical, so the rate-limit bucket and the identity lookup share one key. With a `findByEmail`
    // that does not case-fold internally, a raw `email` lets `A@x.com` and `a@x.com` be two accounts.
    const emailCanonical = canonicalEmail(email) ?? ''
    // NOTE: above the limiter, unlike everywhere else, so a refusal can name whose account is being
    // ground: an event with no subject is a page an operator cannot act on. It costs a refused request
    // one indexed read, a fraction of the argon2 verify the guard exists to stop, and the happy path is
    // unchanged.
    const identity = await orNull(ctx.stores.identities.find({ email }))
    const limitKey = `${this.cfg.limiterKeyPrefix}${emailCanonical}`
    const limited = await ctx.limiter.consume(limitKey)
    if (!limited.ok) await refuseRateLimited(ctx.events, limited, identity?.id ?? null)

    // Always run verify, matching identity or not, to keep the timing constant.
    const verifyResult = identity
      ? await this.verify(identity.id, pw, ctx.stores.credentials, ctx.tenant)
      : await this.verify(NO_IDENTITY_SENTINEL, pw, ctx.stores.credentials, ctx.tenant)

    if (!identity || !verifyResult.ok) {
      await ctx.events.emit('signin.failed', { providerId: 'password', reason: 'invalid-credentials' })
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }

    if (this.cfg.autoRehash && verifyResult.ok && verifyResult.needsRehash) {
      void this.rehash(identity.id, pw, ctx.stores.credentials, ctx.tenant).catch(() => {})
    }

    return [
      {
        type: 'startSession',
        identityId: identity.id,
        factors: [{ method: 'password', completedAt: new Date() }],
        aal: 1,
      },
    ]
  }
}

/** The password provider, ready to hand to `providers`. */
export function passwords<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  cfg?: Partial<Passwords.Cfg>,
): Provider.Me<Passwords.BeginInput, Passwords.CompleteInput, Profile> {
  return new PasswordsImpl(cfg)
}

/** Constructs {@link PasswordsImpl} directly, for a caller wiring the facet by hand. */
export function passwordsImpl(...args: ConstructorParameters<typeof PasswordsImpl>): PasswordsImpl {
  return new PasswordsImpl(...args)
}
