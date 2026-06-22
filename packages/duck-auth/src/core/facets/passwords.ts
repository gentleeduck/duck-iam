import { isRevoked } from '../credential-utils'
import { AuthErrorObject } from '../errors'
import type { AuthTenantContext } from '../types/context'
import type { AuthCredential } from '../types/credential'
import type { AuthHasher } from '../types/hasher'

export const DEFAULT_PASSWORDS_CONFIG: PasswordsFacet.IConfig = {
  minLength: 8,
  maxLength: 1024,
  rejectCommon: true,
}

const COMMON_PASSWORDS = new Set([
  'password',
  'password1',
  '12345678',
  '123456789',
  'qwerty12',
  'iloveyou',
  'admin123',
  'welcome1',
  'letmein1',
])

/**
 * Passwords facet - credential CRUD + verify, with constant-time discipline.
 * Plaintext never leaves a method call; storage always goes through {@link AuthHasher.IHasher}.
 */
export class PasswordsFacet {
  // Lazy reference hash used by verify() in the no-credential branch
  // so the hasher runs scrypt/argon2 work and matches the existing-user
  // timing - defeats username enumeration via wall-clock probes.
  private _referenceHash: string | null = null

  constructor(
    private readonly _credentials: AuthCredential.IStore,
    private readonly _hasher: AuthHasher.IHasher,
    private readonly _cfg: PasswordsFacet.IConfig = DEFAULT_PASSWORDS_CONFIG,
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
      throw new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
    }
    // cap upper bound to prevent CPU/memory DoS via huge passwords
    // sent to argon2/scrypt. 1024 chars is well above any realistic
    // human-typed password while staying far below memory-cost amplifiers.
    if (plaintext.length > this._cfg.maxLength) {
      throw new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
    }
    if (this._cfg.rejectCommon && COMMON_PASSWORDS.has(plaintext.toLowerCase())) {
      throw new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
    }
  }

  /** Set/replace the password credential for an identity. Used by signUp + reset flows. */
  async set(identityId: string, plaintext: string, ctx: AuthTenantContext = {}): Promise<void> {
    if (typeof identityId !== 'string' || identityId.length === 0 || identityId.length > 256) {
      throw new AuthErrorObject('AUTH/UNAUTHENTICATED')
    }
    this._validateStrength(plaintext)
    const secret = await this._hasher.hash(plaintext)
    // Atomicity: delete previous password row, then upsert. Two ops because
    // adapter contract doesn't expose a single-call "replace by kind"; the
    // window is short and protected by SessionsFacet.rotateOrCreate downstream.
    await this._credentials.deleteByKind(identityId, 'password', ctx)
    await this._credentials.upsert(
      {
        identityId,
        kind: 'password',
        secret,
        metadata: { algorithm: this._hasher.id },
      },
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
    ctx: AuthTenantContext = {},
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
  async rehash(identityId: string, plaintext: string, ctx: AuthTenantContext = {}): Promise<void> {
    if (plaintext.length > this._cfg.maxLength) return
    const rows = await this._credentials.listByIdentity(identityId, 'password', ctx)
    const row = rows.find((c) => !isRevoked(c))
    if (!row) return
    const newSecret = await this._hasher.hash(plaintext)
    await this._credentials.rotate(row.id, newSecret, row.version, ctx)
  }
}

export namespace PasswordsFacet {
  export interface IConfig {
    /**
     * Minimum password length. Default 8. Apps should override to >=10 for
     * any production deployment; compliance presets force >=12.
     */
    minLength: number
    /**
     * Maximum password length in characters. Default 1024. SEC: caps
     * the input fed to argon2id / scrypt so an attacker cannot DoS the
     * verify path with multi-megabyte plaintext. Set lower (e.g. 256)
     * if you want to refuse pathological-but-plausible inputs.
     */
    maxLength: number
    /** Reject obvious junk. Default true. */
    rejectCommon: boolean
  }
}
