import { AuthErrorObject } from '../errors'
import type { TenantContext } from '../types/context'
import type { Credential } from '../types/credential'
import type { Hasher } from '../types/hasher'

export interface PasswordsFacetConfig {
  /**
   * Minimum password length. Default 8. Apps should override to ≥10 for
   * any production deployment; compliance presets force ≥12.
   */
  minLength: number
  /** Reject obvious junk. Default true. */
  rejectCommon: boolean
}

export const DEFAULT_PASSWORDS_CONFIG: PasswordsFacetConfig = {
  minLength: 8,
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
 * Passwords facet — credential CRUD + verify, with constant-time discipline.
 * Plaintext never leaves a method call; storage always goes through {@link Hasher.IHasher}.
 */
export class PasswordsFacet {
  constructor(
    private readonly _credentials: Credential.IStore,
    private readonly _hasher: Hasher.IHasher,
    private readonly _cfg: PasswordsFacetConfig = DEFAULT_PASSWORDS_CONFIG,
  ) {}

  /** Throws AUTH/INVALID_CREDENTIALS for weak passwords; never reveals the rule. */
  private _validateStrength(plaintext: string): void {
    if (plaintext.length < this._cfg.minLength) {
      throw new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
    }
    if (this._cfg.rejectCommon && COMMON_PASSWORDS.has(plaintext.toLowerCase())) {
      throw new AuthErrorObject('AUTH/INVALID_CREDENTIALS')
    }
  }

  /** Set/replace the password credential for an identity. Used by signUp + reset flows. */
  async set(identityId: string, plaintext: string, ctx: TenantContext = {}): Promise<void> {
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
   * exists/doesn't-exist branch — defeats user enumeration via timing.
   *
   * Returns `{ ok: true, needsRehash }` when the password matches; `needsRehash`
   * is true if the stored hash was produced with weaker params than current.
   */
  async verify(
    identityId: string,
    plaintext: string,
    ctx: TenantContext = {},
  ): Promise<{ ok: true; needsRehash: boolean } | { ok: false }> {
    const rows = await this._credentials.listByIdentity(identityId, 'password', ctx)
    const row = rows.find((c) => !c.revokedAt) ?? null
    // Reference hash for the no-credential branch — keeps timing constant.
    const reference = row?.secret ?? '$$reference$$'
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
    const rows = await this._credentials.listByIdentity(identityId, 'password', ctx)
    const row = rows.find((c) => !c.revokedAt)
    if (!row) return
    const newSecret = await this._hasher.hash(plaintext)
    await this._credentials.rotate(row.id, newSecret, row.version, ctx)
  }
}
