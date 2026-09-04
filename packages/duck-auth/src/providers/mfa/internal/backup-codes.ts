/**
 * Backup-codes facet. Issues a set of single-use recovery codes that
 * substitute for the user's MFA factor when their TOTP / passkey
 * device is unavailable. Codes are stored hashed (sha-256) against
 * `Credential.kind = 'recovery'`; plaintext is returned to the caller
 * exactly once at generation time.
 *
 * `recovery` is shared by six unrelated token families - see
 * {@link RECOVERY_PURPOSES} - so every read and every delete here is filtered on
 * `metadata.purpose`. Without that filter this facet wiped the user's pending
 * password reset every time it minted codes, and offered their verification and
 * trusted-device tokens to `verify` as candidate second factors.
 */

import { randomBytes } from 'node:crypto'
import {
  deleteCredentialsByPurpose,
  getCredentialPurpose,
  isRevoked,
  RECOVERY_PURPOSES,
  toCredentialUpsert,
} from '~/core/credentials/credentials'
import type { Credential } from '~/core/credentials/credentials.types'
import { timingSafeEqual } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import type { TenantContext } from '~/core/tenant/tenant.types'

export namespace BackupCodesFacet {
  export type Cfg = {
    /** Number of codes minted per call to `generate`. Default 10. */
    count: number
    /** Code length in bytes (4 -> 8 hex chars; 5 -> 10; etc). Default 5. */
    byteLength: number
    /**
     * Format applied to the plaintext (groups of 4 separated by `-`).
     * Default true; UI-friendly. The stored hash is computed AFTER
     * formatting so verify must apply the same normalization.
     */
    groupFour: boolean
  }
}

/**
 * Crockford-style 32-char alphabet - skips 0/O/I/1 + ambiguous chars.
 * Used by `generateBackupCode` below.
 */
const BACKUP_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

/** CSPRNG-rejection-sampling backup code (no modulo bias) over a 32-char readable alphabet. */
function generateBackupCode(_crypto: { authRandomToken(b: number): string }, length: number): string {
  void _crypto
  let out = ''
  while (out.length < length) {
    // Over-sample so we rarely loop more than once even with rejection.
    const buf = randomBytes(length * 2)
    for (const b of buf) {
      if (out.length === length) break
      if (b >= 224) continue // reject biased upper tail
      out += BACKUP_CODE_ALPHABET[b % 32]
    }
  }
  return out
}

/**
 * The `metadata.purpose` every row this facet writes carries, and the filter
 * every row it reads has to pass. Shared with `MfaImpl`, which mints backup
 * codes of its own against the same column.
 */
const BACKUP_CODE_PURPOSE = RECOVERY_PURPOSES.mfaBackupCode

export const DEFAULT_BACKUP_CODES_CONFIG: BackupCodesFacet.Cfg = {
  count: 10,
  byteLength: 5,
  groupFour: true,
}

/**
 * Backup-codes facet. Talks to `Credential.IStore` for persistence and
 * the supplied crypto helpers for token gen + hashing. Caller wires it
 * directly; not auto-mounted on `AuthEngine` because the lib does not
 * assume the application surfaces this MFA fallback.
 */
export class BackupCodesFacet {
  constructor(
    private readonly _credentials: Credential.Store,
    private readonly _crypto: {
      authRandomToken(bytes: number): string
      authSha256(s: string): string
    },
    private readonly _cfg: BackupCodesFacet.Cfg = DEFAULT_BACKUP_CODES_CONFIG,
  ) {}

  /**
   * Generate + persist `count` fresh backup codes for `identityId`.
   * Returns the plaintext array exactly once. Calling generate again
   * REPLACES any prior set - and only that set. This used to be a
   * `deleteByKind(identityId, 'recovery')`, which also took out any reset,
   * verification, deletion, signup or trusted-device token the identity was
   * holding at the time.
   */
  async generate(identityId: string, ctx: TenantContext = {}): Promise<{ codes: string[] }> {
    await deleteCredentialsByPurpose(this._credentials, identityId, 'recovery', BACKUP_CODE_PURPOSE, ctx)
    const codes: string[] = []
    for (let i = 0; i < this._cfg.count; i++) {
      const mapped = generateBackupCode(this._crypto, 8)
      const formatted = this._cfg.groupFour ? `${mapped.slice(0, 4)}-${mapped.slice(4)}` : mapped
      codes.push(formatted)
      await this._credentials.upsert(
        toCredentialUpsert({
          identityId,
          kind: 'recovery',
          secret: this._crypto.authSha256(formatted),
          metadata: { purpose: BACKUP_CODE_PURPOSE, issuedAt: Date.now() },
        }),
        ctx,
      )
    }
    return { codes }
  }

  /**
   * Count of unused codes remaining for `identityId`. Useful for UI
   * "you have N backup codes left" prompts.
   */
  async remaining(identityId: string, ctx: TenantContext = {}): Promise<number> {
    const rows = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    return rows.filter((r) => getCredentialPurpose(r) === BACKUP_CODE_PURPOSE && !isRevoked(r)).length
  }

  /**
   * Verify + consume a backup code. Returns true when the supplied
   * code matches an unused row + deletes that row atomically. Returns
   * false on miss; throws AUTH/RECOVERY_TOKEN_INVALID when the input
   * shape is obviously malformed (empty, too short).
   *
   * The code argument is normalized (uppercased, hyphens stripped if
   * the storage path stored hyphenated) before hashing so the user's
   * input format is forgiving.
   */
  async verify(identityId: string, code: string, ctx: TenantContext = {}): Promise<boolean> {
    if (!code || code.length < 4) {
      throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    }
    const normalized = this._normalize(code)
    const hash = this._crypto.authSha256(normalized)
    const matches = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    // Loop to completion + constant-time compare each hash; early `return true`
    // would leak which row matched (and if any did) via timing.
    let matchedId: string | null = null
    for (const cred of matches) {
      const hit =
        getCredentialPurpose(cred) === BACKUP_CODE_PURPOSE && !isRevoked(cred) && timingSafeEqual(cred.secret, hash)
      if (hit && matchedId === null) matchedId = cred.id
    }
    if (matchedId === null) return false
    // Soft-revoke so reuse attempts surface as known-consumed rows.
    await this._credentials.revoke(matchedId, ctx)
    return true
  }

  /**
   * Wipe every backup code for an identity. Caller invokes during MFA
   * reset / account wipe. Backup codes only - an MFA reset is not a reason to
   * cancel the reset token the user is holding in their inbox.
   */
  async revokeAll(identityId: string, ctx: TenantContext = {}): Promise<void> {
    await deleteCredentialsByPurpose(this._credentials, identityId, 'recovery', BACKUP_CODE_PURPOSE, ctx)
  }

  /** Match the format generate() emits so verify() finds the hash. */
  private _normalize(code: string): string {
    const upper = code.trim().toUpperCase()
    if (this._cfg.groupFour && upper.length === 8 && !upper.includes('-')) {
      return `${upper.slice(0, 4)}-${upper.slice(4)}`
    }
    return upper
  }
}

/** Factory around {@link BackupCodesFacet}, for callers who prefer functions to `new`. */
export function backupCodesFacet(...args: ConstructorParameters<typeof BackupCodesFacet>): BackupCodesFacet {
  return new BackupCodesFacet(...args)
}
