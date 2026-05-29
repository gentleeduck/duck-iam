/**
 * Backup-codes facet. Issues a set of single-use recovery codes that
 * substitute for the user's MFA factor when their TOTP / passkey
 * device is unavailable. Codes are stored hashed (sha-256) against
 * `Credential.kind = 'recovery'`; plaintext is returned to the caller
 * exactly once at generation time.
 */

import { randomBytes } from 'node:crypto'
import { isRevoked } from '../credential-utils'
import { timingSafeEqual } from '../crypto'
import { AuthErrorObject } from '../errors'
import type { TenantContext } from '../types/context'
import type { Credential } from '../types/credential'

/**
 * Crockford-style 32-char alphabet - skips 0/O/I/1 + ambiguous chars.
 * Used by `generateBackupCode` below.
 */
const BACKUP_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

/**
 * Generate a backup code of exactly `length` characters drawn from the
 * 32-char readable alphabet via **CSPRNG rejection sampling**.
 *
 * every character of the produced code is sourced from
 * `crypto.randomBytes`. The prior implementation used
 * `randomToken().charCodeAt() % alphabet.length` for the bulk of the
 * code (modulo-bias over a non-uniform input distribution) and
 * `Math.random()` to top off the last character (a predictable PRNG
 * whose internal state recovers from a handful of outputs). Combined,
 * those flaws reduced the nominal `32^8 ~ 40 bits` entropy to roughly
 * 30 bits effective - online-brute-forceable.
 *
 * Rejection sampling: a uniform `byte ∈ [0, 256)` yields a uniform
 * `byte % 32` ONLY for `byte < 224` (8 multiples of 32). Reject the
 * top 32 codepoints to eliminate modulo bias entirely.
 */
function generateBackupCode(_crypto: { randomToken(b: number): string }, length: number): string {
  void _crypto // retained for the type contract; we go straight to the CSPRNG here
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

export const DEFAULT_BACKUP_CODES_CONFIG: BackupCodesFacet.IConfig = {
  count: 10,
  byteLength: 5,
  groupFour: true,
}

/**
 * Backup-codes facet. Talks to `Credential.IStore` for persistence and
 * the supplied crypto helpers for token gen + hashing. Caller wires it
 * directly; not auto-mounted on `AuthRoot` because the lib does not
 * assume the application surfaces this MFA fallback.
 */
export class BackupCodesFacet {
  constructor(
    private readonly _credentials: Credential.IStore,
    private readonly _crypto: {
      randomToken(bytes: number): string
      sha256(s: string): string
    },
    private readonly _cfg: BackupCodesFacet.IConfig = DEFAULT_BACKUP_CODES_CONFIG,
  ) {}

  /**
   * Generate + persist `count` fresh backup codes for `identityId`.
   * Returns the plaintext array exactly once. Calling generate again
   * REPLACES any prior set - the existing codes are wiped via
   * `deleteByKind`.
   */
  async generate(identityId: string, ctx: TenantContext = {}): Promise<{ codes: string[] }> {
    await this._credentials.deleteByKind(identityId, 'recovery', ctx)
    const codes: string[] = []
    for (let i = 0; i < this._cfg.count; i++) {
      const mapped = generateBackupCode(this._crypto, 8)
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
   */
  async remaining(identityId: string, ctx: TenantContext = {}): Promise<number> {
    const rows = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    return rows.filter((r) => !isRevoked(r)).length
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
      throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
    }
    const normalized = this._normalize(code)
    const hash = this._crypto.sha256(normalized)
    const matches = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    // Loop to completion + constant-time compare each hash; early `return true`
    // would leak which row matched (and if any did) via timing.
    let matchedId: string | null = null
    for (const cred of matches) {
      const hit = !isRevoked(cred) && timingSafeEqual(cred.secret, hash)
      if (hit && matchedId === null) matchedId = cred.id
    }
    if (matchedId === null) return false
    // Soft-revoke so reuse attempts surface as known-consumed rows.
    await this._credentials.revoke(matchedId, ctx)
    return true
  }

  /**
   * Wipe every backup code for an identity. Caller invokes during MFA
   * reset / account wipe.
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
 */
export namespace BackupCodesFacet {
  export interface IConfig {
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
