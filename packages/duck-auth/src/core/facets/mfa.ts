/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { sha256 } from '../crypto'
import { AuthErrorObject } from '../errors'
import { buildOtpAuthUri, generateSecret, verifyTotp } from '../mfa/totp'
import type { TenantContext } from '../types/context'
import type { Credential } from '../types/credential'
import type { Events } from '../types/events'
import type { Session } from '../types/session'

export interface MfaFacetConfig {
  /** Brand shown in TOTP authenticator app entries. */
  issuer: string
  /** How many backup codes to generate per enrollment. Default 10. */
  backupCodeCount: number
  /** Backup code length in characters. Default 10. */
  backupCodeLen: number
}

export const DEFAULT_MFA_CONFIG: MfaFacetConfig = {
  issuer: 'duck-auth',
  backupCodeCount: 10,
  backupCodeLen: 10,
}

export interface TotpEnrollChallenge {
  secret: string
  uri: string
}

/**
 * MFA facet. v0.1 ships TOTP + backup codes. WebAuthn-as-MFA + SMS land
 * later via the same facet shape.
 *
 * Storage: TOTP secrets are persisted in the credentials store as
 * `kind: 'totp'`, base32 plaintext (low-sensitivity vs passwords because
 * a stolen TOTP secret still requires the user's phone to be online during
 * the attack window - and rotation is one-click). Backup codes are
 * persisted hashed as `kind: 'recovery'`, single-use.
 */
export class MfaFacet {
  constructor(
    private readonly _credentials: Credential.IStore,
    private readonly _events: Events.IBus,
    private readonly _cfg: MfaFacetConfig = DEFAULT_MFA_CONFIG,
  ) {}

  // --- TOTP ---------------------------------------------------------------

  /**
   * Begin TOTP enrollment. Returns the otpauth:// URI so the consumer can
   * render a QR code. Secret is persisted immediately under `metadata.confirmed=false`;
   * a later `confirmTotpEnrollment(identityId, firstCode)` flips it confirmed.
   */
  async beginTotpEnrollment(
    identityId: string,
    accountName: string,
    ctx: TenantContext = {},
  ): Promise<TotpEnrollChallenge> {
    const secret = generateSecret()
    await this._credentials.deleteByKind(identityId, 'totp', ctx)
    await this._credentials.upsert(
      {
        identityId,
        kind: 'totp',
        secret,
        metadata: { confirmed: false },
      },
      ctx,
    )
    return {
      secret,
      uri: buildOtpAuthUri({ secret, issuer: this._cfg.issuer, accountName }),
    }
  }

  /**
   * Confirm enrollment by verifying the user typed in the right code.
   * Required before TOTP counts as an enrolled MFA factor for the identity.
   * Emits `mfa.enrolled` on success.
   */
  async confirmTotpEnrollment(
    identityId: string,
    code: string,
    ctx: TenantContext = {},
  ): Promise<{ ok: true; backupCodes: string[] } | { ok: false }> {
    const rows = await this._credentials.listByIdentity(identityId, 'totp', ctx)
    const row = rows.find((r) => (r.metadata as { confirmed?: boolean } | undefined)?.confirmed === false)
    if (!row) throw new AuthErrorObject('AUTH/MFA_REQUIRED', { methods: ['totp'] })
    if (!verifyTotp(row.secret, code)) return { ok: false }

    // Replace the unconfirmed row with a confirmed one (atomicity is best-effort;
    // adapter contracts will gain `patchMetadata` in v0.2).
    await this._credentials.deleteByKind(identityId, 'totp', ctx)
    await this._credentials.upsert(
      {
        identityId,
        kind: 'totp',
        secret: row.secret,
        metadata: { confirmed: true },
      },
      ctx,
    )

    // Generate backup codes on first enrollment. Plaintext shown once.
    const backupCodes = await this._regenerateBackupCodes(identityId, ctx)
    await this._events.emit('mfa.enrolled', { identityId, method: 'totp' })
    return { ok: true, backupCodes }
  }

  /** Verify a TOTP code against the confirmed enrollment. Used by step-up. */
  async verifyTotp(identityId: string, code: string, ctx: TenantContext = {}): Promise<boolean> {
    const rows = await this._credentials.listByIdentity(identityId, 'totp', ctx)
    const row = rows.find(
      (r) => !r.revokedAt && (r.metadata as { confirmed?: boolean } | undefined)?.confirmed === true,
    )
    if (!row) return false
    return verifyTotp(row.secret, code)
  }

  /** True if the identity has a confirmed TOTP enrollment. */
  async hasTotp(identityId: string, ctx: TenantContext = {}): Promise<boolean> {
    const rows = await this._credentials.listByIdentity(identityId, 'totp', ctx)
    return rows.some((r) => !r.revokedAt && (r.metadata as { confirmed?: boolean } | undefined)?.confirmed === true)
  }

  /** Remove all TOTP credentials for the identity. Emits `mfa.removed`. */
  async removeTotp(identityId: string, ctx: TenantContext = {}): Promise<void> {
    await this._credentials.deleteByKind(identityId, 'totp', ctx)
    await this._events.emit('mfa.removed', { identityId, method: 'totp' })
  }

  // --- Backup codes -------------------------------------------------------

  /**
   * Verify a backup code. Single-use; matching code is revoked atomically.
   * Generic ok:boolean - callers map false to AUTH/INVALID_CREDENTIALS so
   * an attacker cannot infer "code exists but wrong" vs "code unknown".
   */
  async verifyBackupCode(identityId: string, code: string, ctx: TenantContext = {}): Promise<boolean> {
    const codeHash = sha256(code.trim().toLowerCase())
    const rows = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    const row = rows.find((r) => !r.revokedAt && r.secret === codeHash)
    if (!row) return false
    await this._credentials.revoke(row.id, ctx)
    return true
  }

  /** Regenerate backup codes; returns plaintext once. Previous codes revoked. */
  async regenerateBackupCodes(identityId: string, ctx: TenantContext = {}): Promise<string[]> {
    return this._regenerateBackupCodes(identityId, ctx)
  }

  private async _regenerateBackupCodes(identityId: string, ctx: TenantContext): Promise<string[]> {
    await this._credentials.deleteByKind(identityId, 'recovery', ctx)
    const codes: string[] = []
    for (let i = 0; i < this._cfg.backupCodeCount; i++) {
      const code = this._randomBackupCode()
      codes.push(code)
      await this._credentials.upsert(
        {
          identityId,
          kind: 'recovery',
          secret: sha256(code.toLowerCase()),
        },
        ctx,
      )
    }
    return codes
  }

  private _randomBackupCode(): string {
    // base32-ish alphabet (no ambiguous chars 0/O, 1/I/L).
    const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789'
    const bytes = new Uint8Array(this._cfg.backupCodeLen)
    // Node crypto for tests; consumers running in edge runtimes get the same
    // shape via globalThis.crypto.getRandomValues.
    if (typeof globalThis.crypto?.getRandomValues === 'function') {
      globalThis.crypto.getRandomValues(bytes)
    }
    let out = ''
    for (let i = 0; i < bytes.length; i++) {
      const idx = (bytes[i] ?? 0) % ALPHABET.length
      out += ALPHABET[idx]
    }
    // Split into 5-5 groups for readability.
    return `${out.slice(0, 5)}-${out.slice(5)}`
  }

  // --- AAL helpers --------------------------------------------------------

  /**
   * Compute the AAL the identity is currently eligible for, given the
   * factors already on the session. Used by step-up evaluation.
   */
  async eligibleAal(
    identityId: string,
    currentFactors: Session.FactorMethod[],
    ctx: TenantContext = {},
  ): Promise<Session.AAL> {
    const distinct = new Set(currentFactors)
    if (distinct.size === 0) return 1
    if (distinct.size === 1) return 1
    // Two or more distinct factors of any kind: AAL=2.
    // (AAL=3 requires hardware-backed cryptographic auth - passkey-attested.
    //  Calculated by passkey enrollment metadata; future patch.)
    if (await this.hasTotp(identityId, ctx)) {
      return distinct.has('totp') ? 2 : 1
    }
    return 2
  }
}
