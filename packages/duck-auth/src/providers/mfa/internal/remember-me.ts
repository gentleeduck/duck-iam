/** Trusted-device tokens for a host's "remember this device": a long-lived random value, stored hashed
 *  under `Credential.kind='recovery'` with `metadata.purpose='trusted-device'`. Nothing in the package
 *  issues or reads one; the host decides what a verified device skips. A password reset and removing TOTP
 *  or WebAuthn MFA revoke every one the identity holds. */

import { type Answer, answer, orNull } from '~/core/answer'
import {
  getCredentialPurpose,
  isCredentialExpired,
  isRevoked,
  toCredentialCreate,
} from '~/core/credentials/credentials'
import { RECOVERY_PURPOSES } from '~/core/credentials/credentials.constants'
import type { Credential } from '~/core/credentials/credentials.types'
import { AuthError } from '~/core/errors'
import type { TenantContext } from '~/core/tenant/tenant.types'

export namespace RememberMeFacet {
  /** How long a remembered device stays trusted. */
  export type Cfg = {
    /** Cookie / token TTL in ms. Default 90 days. */
    ttlMs: number
    /** Random-byte length minted per token. Default 32 (256 bits). */
    byteLength: number
  }

  /** A new device token, answered once. */
  export type Issued = {
    /** The plaintext, answered once, for the host to keep on the device. */
    token: string
    /** Credential row id; useful for client-side device listings. */
    credentialId: string
    /** Absolute expiry, ms since epoch. */
    expiresAt: number
  }

  /** A device token that checked out, and whose it is. */
  export type Verified = {
    identityId: string
    credentialId: string
    /** Attached at issue; a label and a userAgent, typically. */
    metadata: Record<string, unknown> | null
  }
}

/** Defaults applied when remember-this-device config omits a field. */
export const DEFAULT_REMEMBER_ME_CONFIG: RememberMeFacet.Cfg = {
  ttlMs: 90 * 24 * 60 * 60 * 1000,
  byteLength: 32,
}

/** Built by the host over its credential store; the engine does not mount it. */
export class RememberMeFacet {
  constructor(
    private readonly _credentials: Credential.Store,
    private readonly _crypto: {
      authRandomToken(bytes: number): string
      authSha256(s: string): string
    },
    private readonly _cfg: RememberMeFacet.Cfg = DEFAULT_REMEMBER_ME_CONFIG,
  ) {
    // SECURITY: `authRandomToken(0)` answers `''`; 128 bytes is 171 characters, inside `verify`'s cap.
    if (!Number.isInteger(this._cfg.byteLength) || this._cfg.byteLength < 16 || this._cfg.byteLength > 128) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `rememberMe: byteLength must be a whole number between 16 and 128, got ${String(this._cfg.byteLength)}`,
      })
    }
    if (!Number.isFinite(this._cfg.ttlMs) || this._cfg.ttlMs < 1) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `rememberMe: ttlMs must be a positive number, got ${String(this._cfg.ttlMs)}`,
      })
    }
  }

  /** Mints and persists a token, handing back the plaintext exactly once. `metadata` is the caller's,
   *  usually `{ label, userAgent, ip }` for a devices list, except `purpose`, which is always this one. */
  async issue(
    identityId: string,
    opts: { metadata?: Record<string, unknown> } = {},
    ctx: TenantContext = {},
  ): Promise<RememberMeFacet.Issued> {
    const token = this._crypto.authRandomToken(this._cfg.byteLength)
    const hash = this._crypto.authSha256(token)
    const now = Date.now()
    const expiresAt = now + this._cfg.ttlMs
    const cred = await this._credentials.create(
      toCredentialCreate({
        identityId,
        kind: 'recovery',
        secret: hash,
        // Last, so a caller's key cannot make the row another purpose's token.
        metadata: { ...opts.metadata, purpose: RECOVERY_PURPOSES.trustedDevice },
        expiresAt: new Date(expiresAt),
      }),
      ctx,
    )
    return { token, credentialId: cred.id, expiresAt }
  }

  /** Rejects `AUTH_CREDENTIAL_NOT_FOUND` on a miss, an elapsed TTL or another purpose's row, which
   *  `orNull()` reads as null, and `AUTH_RECOVERY_TOKEN_INVALID` on malformed input, which it does not.
   *  A success does not consume the token, which is presented on every sign-in inside the TTL. */
  verify(token: string, ctx: TenantContext = {}): Answer.Me<RememberMeFacet.Verified> {
    return answer(async () => {
      // Capped before sha256.
      if (typeof token !== 'string' || token.length === 0 || token.length > 256) {
        throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
      }
      const hash = this._crypto.authSha256(token)
      const row = await orNull(this._credentials.findByHashedSecret(hash, 'recovery', ctx))
      if (!row || isRevoked(row)) throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')
      if (getCredentialPurpose(row) !== RECOVERY_PURPOSES.trustedDevice) {
        throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')
      }
      // Through `isCredentialExpired`, against a malformed `expiresAt` from a buggy adapter.
      if (isCredentialExpired(row)) {
        void this._credentials.delete(row.id, ctx).catch(() => {})
        throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')
      }

      return {
        identityId: row.identityId,
        credentialId: row.id,
        metadata: row.metadata,
      }
    })
  }

  /** The live trusted devices for an identity, as row ids plus the caller's metadata and never the secret. */
  async list(
    identityId: string,
    ctx: TenantContext = {},
  ): Promise<
    Array<{
      credentialId: string
      createdAt: Date
      expiresAt: Date | null
      metadata: Record<string, unknown> | null
    }>
  > {
    const rows = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    return rows
      .filter(
        (r) => getCredentialPurpose(r) === RECOVERY_PURPOSES.trustedDevice && !isRevoked(r) && !isCredentialExpired(r),
      )
      .map((r) => ({
        credentialId: r.id,
        createdAt: r.createdAt,
        expiresAt: r.expiresAt,
        metadata: r.metadata,
      }))
  }

  /** Revoke a specific trusted-device row. */
  async revoke(identityId: string, credentialId: string, ctx: TenantContext = {}): Promise<void> {
    const row = await orNull(this._credentials.findById(credentialId, ctx))
    if (!row || row.identityId !== identityId) return
    // SECURITY: the purpose as well as the owner. This id arrives on a "remove this device" request, and
    // owner-only left the endpoint deleting whichever of the caller's credentials it named - their TOTP
    // enrollment, their passkey, the reset token sitting in their inbox - silently, and without the
    // events the real removal paths emit. Every other read and delete over `recovery` filters on it.
    if (getCredentialPurpose(row) !== RECOVERY_PURPOSES.trustedDevice) return
    await this._credentials.delete(credentialId, ctx)
  }

  /** Wipe every trusted device for an identity in one write, an elapsed TTL included: `list` answers what
   *  is live, which is not the same set, and going through it left the expired rows behind for good. */
  async revokeAll(identityId: string, ctx: TenantContext = {}): Promise<void> {
    await this._credentials.deleteByKindAndPurpose(identityId, 'recovery', RECOVERY_PURPOSES.trustedDevice, ctx)
  }
}

/** Constructs a {@link RememberMeFacet}. */
export function rememberMeFacet(...args: ConstructorParameters<typeof RememberMeFacet>): RememberMeFacet {
  return new RememberMeFacet(...args)
}
