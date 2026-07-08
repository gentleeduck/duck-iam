import { isRevoked, toCredentialUpsert } from '../../core/credential-utils'
import { AuthError } from '../../core/errors'
import type { Credential } from '../../core/types/identity'
import type { Hasher, TenantContext } from '../../core/types/infra'
import { COMMON_PASSWORDS, DEFAULT_PASSWORDS_CONFIG } from './password.constants'
import type { Password } from './password.types'

/**
 * Passwords facet - credential CRUD + verify, with constant-time discipline.
 * Plaintext never leaves a method call; storage always goes through {@link Hasher.Hasher}.
 */
export class PasswordsFacet {
  // Lazy reference hash used by verify() in the no-credential branch
  // so the hasher runs scrypt/argon2 work and matches the existing-user
  // timing - defeats username enumeration via wall-clock probes.
  private _referenceHash: string | null = null

  constructor(
    private readonly _credentials: Credential.Store,
    private readonly _hasher: Hasher.IHasher,
    private readonly _cfg: Password.Config = DEFAULT_PASSWORDS_CONFIG,
  ) {}

  /**
   * produce (and cache) a valid encoded
   * hash to feed `hasher.verify` in the no-credential branch. The
   * dummy plaintext is fixed; what matters is the OUTPUT is a real
   * scrypt/argon2 string the hasher will execute against.
   */
  private async _ensureReferenceHash(): Promise<string> {
    if (this._referenceHash !== null) return this._referenceHash
    this._referenceHash = await this._hasher.hash('duck-auth:no-credential-reference')
    return this._referenceHash
  }

  /** Throws AUTH/INVALID_CREDENTIALS for weak passwords; never reveals the rule. */
  private _validateStrength(plaintext: string): void {
    if (plaintext.length < this._cfg.minLength) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
    // cap upper bound to prevent CPU/memory DoS via huge passwords
    // sent to argon2/scrypt. 1024 chars is well above any realistic
    // human-typed password while staying far below memory-cost amplifiers.
    if (plaintext.length > this._cfg.maxLength) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
    if (this._cfg.rejectCommon && COMMON_PASSWORDS.has(plaintext.toLowerCase())) {
      throw new AuthError('AUTH_INVALID_CREDENTIALS')
    }
  }

  /** Hash plaintext with the configured hasher. Useful for transaction-scoped credential writes. */
  async hash(plaintext: string): Promise<string> {
    this._validateStrength(plaintext)
    return this._hasher.hash(plaintext)
  }

  /** Hasher algorithm id — needed when writing credentials outside of `set()`. */
  get hasherId(): string {
    return this._hasher.id
  }

  /** Set/replace the password credential for an identity. Used by signUp + reset flows. */
  async set(identityId: string, plaintext: string, ctx: TenantContext = {}): Promise<void> {
    if (typeof identityId !== 'string' || identityId.length === 0 || identityId.length > 256) {
      throw new AuthError('AUTH_UNAUTHENTICATED')
    }
    this._validateStrength(plaintext)
    const secret = await this._hasher.hash(plaintext)
    // Atomicity: delete previous password row, then upsert. Two ops because
    // adapter contract doesn't expose a single-call "replace by kind"; the
    // window is short and protected by SessionsFacet.rotateOrCreate downstream.
    await this._credentials.deleteByKind(identityId, 'password', ctx)
    await this._credentials.upsert(
      toCredentialUpsert({
        identityId,
        kind: 'password',
        secret,
        metadata: { algorithm: this._hasher.id },
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
    ctx: TenantContext = {},
  ): Promise<{ ok: true; needsRehash: boolean } | { ok: false }> {
    // Cap plaintext before hashing so a multi-MB input cannot DoS
    // the argon2/scrypt verify path.
    if (plaintext.length > this._cfg.maxLength) {
      return { ok: false }
    }
    const rows = await this._credentials.listByIdentity(identityId, 'password', ctx)
    const row = rows.find((c) => !isRevoked(c)) ?? null
    // Use a real reference hash on the no-credential branch so both
    // branches pay the full hasher cost (defeats timing enumeration).
    const reference = row?.secret ?? (await this._ensureReferenceHash())
    const ok = await this._hasher.verify(plaintext, reference)
    if (!row || !ok) return { ok: false }
    // Touch lastUsedAt opportunistically; ignore adapter errors.
    void this._credentials.rotate(row.id, row.secret, row.version, ctx).catch(() => {})
    return { ok: true, needsRehash: this._hasher.needsRehash(row.secret) }
  }

  /**
   * Re-hash an existing password under current params. Called on successful
   * verify when {@link verify} returns `needsRehash: true`, so a slow
   * parameter upgrade rolls out as users sign in.
   */
  async rehash(identityId: string, plaintext: string, ctx: TenantContext = {}): Promise<void> {
    if (plaintext.length > this._cfg.maxLength) return
    const rows = await this._credentials.listByIdentity(identityId, 'password', ctx)
    const row = rows.find((c) => !isRevoked(c))
    if (!row) return
    const newSecret = await this._hasher.hash(plaintext)
    await this._credentials.rotate(row.id, newSecret, row.version, ctx)
  }
}
