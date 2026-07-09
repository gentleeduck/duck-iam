import type { TenantContext } from '~/core'
import { resolveCompliance } from '~/core/compliance'
import { isRevoked, toCredentialUpsert } from '~/core/credentials/credentials'
import type { Credential } from '~/core/credentials/credentials.types'
import { AuthError } from '~/core/errors'
import type { Identity } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import {
  COMMON_PASSWORDS,
  DEFAULT_PASSWORDS_CONFIG,
  NO_CREDENTIAL_REFRENCE,
  NO_IDENTITY_SENTINEL,
} from './passwords.constants'
import type { Passwords } from './passwords.types'

export class PasswordsImpl<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>
  implements Provider.Me<Passwords.BeginInput, Passwords.CompleteInput, Profile>
{
  readonly id = 'password'
  readonly kind = 'password' as const
  readonly cfg: Omit<Passwords.Config, 'compliance'>
  // Lazy reference hash used by verify() in the no-credential branch
  // so the hasher runs scrypt/argon2 work and matches the existing-user
  // timing - defeats username enumeration via wall-clock probes.
  private _referenceHash: string | null = null

  constructor(readonly _cfg?: Partial<Passwords.Config>) {
    const floor = _cfg?.compliance ? resolveCompliance(_cfg.compliance).passwords.minLength : 0
    this.cfg = {
      limiterKeyPrefix: _cfg?.limiterKeyPrefix ?? DEFAULT_PASSWORDS_CONFIG.limiterKeyPrefix,
      autoRehash: _cfg?.autoRehash ?? DEFAULT_PASSWORDS_CONFIG.autoRehash,
      minLength: Math.max(_cfg?.minLength ?? DEFAULT_PASSWORDS_CONFIG.minLength, floor),
      maxLength: _cfg?.maxLength ?? DEFAULT_PASSWORDS_CONFIG.maxLength,
      rejectCommon: _cfg?.rejectCommon ?? DEFAULT_PASSWORDS_CONFIG.rejectCommon,
      hasher: _cfg?.hasher ?? DEFAULT_PASSWORDS_CONFIG.hasher,
    }
  }

  /**
   * produce (and cache) a valid encoded
   * hash to feed `hasher.verify` in the no-credential branch. The
   * dummy plaintext is fixed; what matters is the OUTPUT is a real
   * scrypt/argon2 string the hasher will execute against.
   */
  private async _ensureReferenceHash(): Promise<string> {
    if (this._referenceHash !== null) return this._referenceHash
    this._referenceHash = await this.cfg.hasher.hash(NO_CREDENTIAL_REFRENCE)
    return this._referenceHash
  }

  /** Throws AUTH/INVALID_CREDENTIALS for weak passwords; never reveals the rule. */
  private _validateStrength(plaintext: string): void {
    if (plaintext.length < this.cfg.minLength) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
    // cap upper bound to prevent CPU/memory DoS via huge passwords
    // sent to argon2/scrypt. 1024 chars is well above any realistic
    // human-typed password while staying far below memory-cost amplifiers.
    if (plaintext.length > this.cfg.maxLength) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
    if (this.cfg.rejectCommon && COMMON_PASSWORDS.has(plaintext.toLowerCase())) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
  }

  /**
   * Re-hash an existing password under current params. Called on successful
   * verify when {@link verify} returns `needsRehash: true`, so a slow
   * parameter upgrade rolls out as users sign in.
   */
  async rehash(
    identityId: string,
    plaintext: string,
    credentials: Credential.Store,
    ctx: TenantContext = {},
  ): Promise<void> {
    if (plaintext.length > this.cfg.maxLength) return
    const rows = await credentials.listByIdentity(identityId, 'password', ctx)
    const row = rows.find((c) => !isRevoked(c))
    if (!row) return
    const newSecret = await this.cfg.hasher.hash(plaintext)
    await credentials.rotate(row.id, newSecret, row.version, ctx)
  }

  /** Set/replace the password credential for an identity. Used by signUp + reset flows. */
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
    // Atomicity: delete previous password row, then upsert. Two ops because
    // adapter contract doesn't expose a single-call "replace by kind"; the
    // window is short and protected by SessionsFacet.rotateOrCreate downstream.
    await credentials.deleteByKind(identityId, 'password', ctx)
    await credentials.upsert(
      toCredentialUpsert({
        identityId,
        kind: 'password',
        secret,
        metadata: { algorithm: this.cfg.hasher.id },
      }),
      ctx,
    )
  }

  /**
   * Verify a password against the stored credential. Always runs the hasher
   * (even on missing credential) to keep timing constant across the
   * exists/doesn't-exist branch - defeats user enumeration via timing.
   *
   * Returns `{ ok: true, needsRehash }` when the password matches; `needsRehash`
   * is true if the stored hash was produced with weaker params than current.
   */
  async verify(
    identityId: string,
    plaintext: string,
    credentials: Credential.Store,
    ctx: TenantContext = {},
  ): Promise<{ ok: true; needsRehash: boolean } | { ok: false }> {
    // Cap plaintext before hashing so a multi-MB input cannot DoS
    // the argon2/scrypt verify path.
    if (plaintext.length > this.cfg.maxLength) {
      return { ok: false }
    }
    const rows = await credentials.listByIdentity(identityId, 'password', ctx)
    const row = rows.find((c) => !isRevoked(c)) ?? null
    // Use a real reference hash on the no-credential branch so both
    // branches pay the full hasher cost (defeats timing enumeration).
    const reference = row?.secret ?? (await this._ensureReferenceHash())
    const ok = await this.cfg.hasher.verify(plaintext, reference)
    if (!row || !ok) return { ok: false }
    // Touch lastUsedAt opportunistically; ignore adapter errors.
    void credentials.rotate(row.id, row.secret, row.version, ctx).catch(() => {})
    return { ok: true, needsRehash: this.cfg.hasher.needsRehash(row.secret) }
  }

  //==============================================================================================
  //===== FLOW CODE ==============================================================================
  //==============================================================================================

  async begin(_ctx: Provider.Context<Profile>, _input: Passwords.BeginInput): Promise<Provider.Intent[]> {
    console.debug('[AUTH] password.begin, no-op, returning empty intents')
    return []
  }

  async complete(ctx: Provider.Context<Profile>, input: Passwords.CompleteInput): Promise<Provider.InternalIntent[]> {
    const { email, password: pw } = input
    // email cap per RFC 5321 (254); authPassword cap matches the
    // PasswordsFacet maxLength (default 1024). Without caps, an
    // attacker can DoS via huge inputs reaching the hasher / store.
    if (
      typeof email !== 'string' ||
      typeof pw !== 'string' ||
      email.length === 0 ||
      email.length > 254 ||
      pw.length === 0 ||
      pw.length > 1024
    ) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }

    // Canonical (trim + lowercase) email so the rate-limit bucket AND
    // the identity lookup share one key. If the operator wires
    // findByEmail without internal case-folding, raw `email`
    // would let `A@x.com` and `a@x.com` register/sign-in as distinct
    // accounts.
    const emailCanonical = email.trim().toLowerCase()
    const limitKey = `${this.cfg.limiterKeyPrefix}${emailCanonical}`
    const limited = await ctx.limiter.consume(limitKey)
    if (!limited.ok) {
      throw new AuthError('AUTH_RATE_LIMITED', {
        retryAfter: Math.max(0, Math.ceil((limited.resetAt.getTime() - Date.now()) / 1000)),
      })
    }

    const identity = await ctx.stores.identities.findByEmail(emailCanonical)
    // ALWAYS run verify (even with no matching identity) to keep timing constant.
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

/** Factory around {@link PasswordsImpl} for functional-style config. */
export function passwords<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  cfg?: Partial<Passwords.Config>,
): Provider.Me<Passwords.BeginInput, Passwords.CompleteInput, Profile> {
  return new PasswordsImpl(cfg)
}
