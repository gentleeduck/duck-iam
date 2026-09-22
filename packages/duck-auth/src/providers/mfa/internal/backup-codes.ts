/**
 * Single-use recovery codes standing in for the user's MFA factor when their device is unavailable.
 * Stored as sha-256 against `Credential.kind = 'recovery'`; the plaintext is answered exactly once.
 *
 * WARN: `recovery` is shared by six token families ({@link RECOVERY_PURPOSES}), so every read and
 * delete here filters on `metadata.purpose`. Unfiltered, minting codes wipes a pending password reset
 * and offers verification tokens to `verify` as second factors.
 */

import { randomBytes } from 'node:crypto'
import {
  getCredentialPurpose,
  isCredentialExpired,
  isRevoked,
  toCredentialCreate,
} from '~/core/credentials/credentials'
import { RECOVERY_PURPOSES } from '~/core/credentials/credentials.constants'
import type { Credential } from '~/core/credentials/credentials.types'
import { timingSafeEqual } from '~/core/crypto'
import { AuthError } from '~/core/errors'
import type { TenantContext } from '~/core/tenant/tenant.types'

export namespace BackupCodesFacet {
  export type Cfg = {
    /** Number of codes minted per call to `generate`. Default 10. */
    count: number
    /** Entropy per code, in bytes. The alphabet carries 5 bits a character, so 5 bytes is 8 characters
     *  and 10 is 16. Default 5. */
    byteLength: number
    /** Group the plaintext in fours separated by `-`. Default true. The hash is computed after
     *  formatting, so `verify` must normalise the same way. */
    groupFour: boolean
  }
}

/** Crockford-style 32 characters, skipping the ambiguous 0, O, I and 1. */
const BACKUP_CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'

/** The alphabet is 32 characters, so each one carries exactly 5 bits. */
function codeLengthFor(byteLength: number): number {
  return Math.ceil((byteLength * 8) / 5)
}

/** Every four characters, so a 16-character code reads as four groups rather than one of four and one
 *  of twelve. */
function groupInFours(s: string): string {
  return (s.match(/.{1,4}/g) ?? [s]).join('-')
}

/** CSPRNG-rejection-sampling backup code (no modulo bias) over a 32-char readable alphabet. */
function generateBackupCode(length: number): string {
  let out = ''
  while (out.length < length) {
    // Over-sampled, so rejection rarely costs a second pass.
    const buf = randomBytes(length * 2)
    for (const b of buf) {
      if (out.length === length) break
      if (b >= 224) continue // reject biased upper tail
      out += BACKUP_CODE_ALPHABET[b % 32]
    }
  }
  return out
}

/** Defaults applied when backup-code config omits a field. */
export const DEFAULT_BACKUP_CODES_CONFIG: BackupCodesFacet.Cfg = {
  count: 10,
  byteLength: 5,
  groupFour: true,
}

/** Wired directly by the caller rather than auto-mounted on `AuthEngine`, since not every
 *  application surfaces this MFA fallback. */
export class BackupCodesFacet {
  constructor(
    private readonly _credentials: Credential.Store,
    private readonly _crypto: {
      authRandomToken(bytes: number): string
      authSha256(s: string): string
    },
    private readonly _cfg: BackupCodesFacet.Cfg = DEFAULT_BACKUP_CODES_CONFIG,
  ) {
    // SECURITY: the same two knobs `MfaImpl` guards, on the second implementation of this contract.
    // `generateBackupCode` loops `while (out.length < length)`, so a `byteLength` of 0, NaN or a negative
    // number exits before the first draw and mints ten empty strings without a word - measured. Five
    // bytes is eight characters over a 32-character alphabet, which is this facet's own default.
    if (!Number.isInteger(this._cfg.count) || this._cfg.count < 1 || this._cfg.count > 64) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `backupCodes: count must be a whole number between 1 and 64, got ${String(this._cfg.count)}`,
      })
    }
    if (!Number.isInteger(this._cfg.byteLength) || this._cfg.byteLength < 5 || this._cfg.byteLength > 64) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `backupCodes: byteLength must be a whole number between 5 and 64, got ${String(this._cfg.byteLength)}`,
      })
    }
  }

  /** Generate and persist `count` fresh codes, answering with the plaintext exactly once. Replaces any
   *  prior set, and only that set, never the identity's reset, verification or signup tokens. */
  async generate(identityId: string, ctx: TenantContext = {}): Promise<{ codes: string[] }> {
    await this._credentials.deleteByKindAndPurpose(identityId, 'recovery', RECOVERY_PURPOSES.mfaBackupCode, ctx)
    const codes: string[] = []
    for (let i = 0; i < this._cfg.count; i++) {
      const mapped = generateBackupCode(codeLengthFor(this._cfg.byteLength))
      const formatted = this._cfg.groupFour ? groupInFours(mapped) : mapped
      codes.push(formatted)
      await this._credentials.create(
        toCredentialCreate({
          identityId,
          kind: 'recovery',
          secret: this._crypto.authSha256(formatted),
          metadata: { purpose: RECOVERY_PURPOSES.mfaBackupCode, issuedAt: Date.now() },
        }),
        ctx,
      )
    }
    return { codes }
  }

  /** For a "you have N backup codes left" prompt. */
  async remaining(identityId: string, ctx: TenantContext = {}): Promise<number> {
    const rows = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    return rows.filter(
      (r) => getCredentialPurpose(r) === RECOVERY_PURPOSES.mfaBackupCode && !isRevoked(r) && !isCredentialExpired(r),
    ).length
  }

  /** Verify and consume a backup code, claiming the matched row so one code buys one success. `false`
   *  on a miss or a lost race; `AUTH_RECOVERY_TOKEN_INVALID` when the input is obviously malformed. The
   *  code is uppercased and de-hyphenated before hashing, so the user's formatting is forgiven. */
  async verify(identityId: string, code: string, ctx: TenantContext = {}): Promise<boolean> {
    // Capped as well as floored: without it a multi-megabyte string is uppercased and sha-256'd on
    // every attempt. A 16-character code with its hyphens is 19.
    if (!code || code.length < 4 || code.length > 128) {
      throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    }
    const normalized = this._normalize(code)
    const hash = this._crypto.authSha256(normalized)
    const matches = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    // Every row is compared, in constant time: an early `return true` leaks which one matched, and
    // whether any did, through timing.
    let matched: Credential.Me | null = null
    for (const cred of matches) {
      const hit =
        getCredentialPurpose(cred) === RECOVERY_PURPOSES.mfaBackupCode &&
        !isRevoked(cred) &&
        // Expiry as well, so `remaining()` above and this gate agree on which codes are still spendable.
        !isCredentialExpired(cred) &&
        timingSafeEqual(cred.secret, hash)
      if (hit && matched === null) matched = cred
    }
    if (matched === null) return false
    // The CAS claim is what makes a backup code single-use. `revoke` below is unconditional, so on its
    // own it lets two verifications that both read before either wrote match the same live row and both
    // answer true. Burning the secret in the claiming write also stops one that reads after it lands.
    const burnt = this._crypto.authSha256(this._crypto.authRandomToken(32))
    try {
      await this._credentials.rotate(matched.id, burnt, matched.version, ctx)
    } catch (err) {
      // Losing the race is a code someone else already spent, which is a miss like any other.
      if (err instanceof AuthError && err.code === 'AUTH_STALE_WRITE') return false
      throw err
    }
    // Soft-revoked, so a reuse attempt surfaces as a known-consumed row.
    await this._credentials.revoke(matched.id, ctx)
    return true
  }

  /** Wipes every backup code for an identity, for an MFA reset or an account wipe. Backup codes only:
   *  an MFA reset is no reason to cancel the reset token in the user's inbox. */
  async revokeAll(identityId: string, ctx: TenantContext = {}): Promise<void> {
    await this._credentials.deleteByKindAndPurpose(identityId, 'recovery', RECOVERY_PURPOSES.mfaBackupCode, ctx)
  }

  /** Matches what `generate()` emits, so `verify()` finds the hash. Strips the user's hyphens and
   *  re-applies the canonical grouping, so where they put them does not matter. */
  private _normalize(code: string): string {
    const bare = code.trim().toUpperCase().replace(/-/g, '')
    return this._cfg.groupFour ? groupInFours(bare) : bare
  }
}

/** Constructs a {@link BackupCodesFacet}. */
export function backupCodesFacet(...args: ConstructorParameters<typeof BackupCodesFacet>): BackupCodesFacet {
  return new BackupCodesFacet(...args)
}
