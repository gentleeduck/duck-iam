/**
 * @packageDocumentation
 * Backup-codes facet. Issues a set of single-use recovery codes that
 * substitute for the user's MFA factor when their TOTP / passkey
 * device is unavailable. Codes are stored hashed (sha-256) against
 * `Credential.kind = 'recovery'`; plaintext is returned to the caller
 * exactly once at generation time.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../errors'
import type { TenantContext } from '../types/context'
import type { Credential } from '../types/credential'

/**
 * Config knobs for `BackupCodesFacet`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface BackupCodesFacetConfig {
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

export const DEFAULT_BACKUP_CODES_CONFIG: BackupCodesFacetConfig = {
  count: 10,
  byteLength: 5,
  groupFour: true,
}

/**
 * Backup-codes facet. Talks to `Credential.IStore` for persistence and
 * the supplied crypto helpers for token gen + hashing. Caller wires it
 * directly; not auto-mounted on `AuthRoot` because the lib does not
 * assume the application surfaces this MFA fallback.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class BackupCodesFacet {
  constructor(
    private readonly _credentials: Credential.IStore,
    private readonly _crypto: {
      randomToken(bytes: number): string
      sha256(s: string): string
    },
    private readonly _cfg: BackupCodesFacetConfig = DEFAULT_BACKUP_CODES_CONFIG,
  ) {}

  /**
   * Generate + persist `count` fresh backup codes for `identityId`.
   * Returns the plaintext array exactly once. Calling generate again
   * REPLACES any prior set - the existing codes are wiped via
   * `deleteByKind`.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async generate(identityId: string, ctx: TenantContext = {}): Promise<{ codes: string[] }> {
    await this._credentials.deleteByKind(identityId, 'recovery', ctx)
    const codes: string[] = []
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789' // skip 0/O/I/1 for human readability
    for (let i = 0; i < this._cfg.count; i++) {
      // randomToken returns base64url; map to the readable alphabet so
      // the codes are unambiguous when transcribed from a screen.
      const raw = this._crypto.randomToken(this._cfg.byteLength)
      let mapped = ''
      for (const ch of raw) {
        if (mapped.length === 8) break
        mapped += alphabet[ch.charCodeAt(0) % alphabet.length]
      }
      while (mapped.length < 8) mapped += alphabet[Math.floor(Math.random() * alphabet.length)]
      const formatted = this._cfg.groupFour ? `${mapped.slice(0, 4)}-${mapped.slice(4)}` : mapped
      codes.push(formatted)
      await this._credentials.upsert(
        {
          identityId,
          kind: 'recovery',
          secret: this._crypto.sha256(formatted),
          metadata: { issuedAt: Date.now() },
        },
        ctx,
      )
    }
    return { codes }
  }

  /**
   * Count of unused codes remaining for `identityId`. Useful for UI
   * "you have N backup codes left" prompts.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async remaining(identityId: string, ctx: TenantContext = {}): Promise<number> {
    const rows = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    return rows.filter((r) => !r.revokedAt).length
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
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async verify(identityId: string, code: string, ctx: TenantContext = {}): Promise<boolean> {
    if (!code || code.length < 4) {
      throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
    }
    const normalized = this._normalize(code)
    const hash = this._crypto.sha256(normalized)
    const matches = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    for (const cred of matches) {
      if (cred.secret === hash && !cred.revokedAt) {
        await this._credentials.delete(cred.id, ctx)
        return true
      }
    }
    return false
  }

  /**
   * Wipe every backup code for an identity. Caller invokes during MFA
   * reset / account wipe.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async revokeAll(identityId: string, ctx: TenantContext = {}): Promise<void> {
    await this._credentials.deleteByKind(identityId, 'recovery', ctx)
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

/**
 * Namespace merge for `BackupCodesFacet`. Co-locates the config alongside
 * the class via TS class+namespace merging.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace BackupCodesFacet {
  /** Alias for `BackupCodesFacetConfig`. */
  export type IConfig = BackupCodesFacetConfig
}
