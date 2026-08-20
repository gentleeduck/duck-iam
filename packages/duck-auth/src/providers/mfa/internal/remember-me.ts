/**
 * Remember-me / trusted-device facet. Issues a long-lived random token
 * the framework adapter stores in an `__Host-duck-device` cookie. On
 * subsequent sign-in attempts the consumer can present the token to
 * skip MFA (and grant aal=2 implicitly) for the device the cookie was
 * minted on.
 *
 * Storage shape: hashed token under `Credential.kind='recovery'` with
 * `metadata.purpose='trusted-device'` + caller-supplied metadata.
 */

import {
  getCredentialPurpose,
  isCredentialExpired,
  isRevoked,
  toCredentialUpsert,
} from '~/core/credentials/credentials'
import type { Credential } from '~/core/credentials/credentials.types'
import { AuthError } from '~/core/errors'
import type { TenantContext } from '~/core/tenant/tenant.types'

export namespace RememberMeFacet {
  export type Cfg = {
    /** Cookie / token TTL in ms. Default 90 days. */
    ttlMs: number
    /** Random-byte length minted per token. Default 32 (256 bits). */
    byteLength: number
  }

  export type Issued = {
    /** Plaintext token to drop into `__Host-duck-device` cookie. */
    token: string
    /** Credential row id; useful for client-side device listings. */
    credentialId: string
    /** Absolute expiry, ms since epoch. */
    expiresAt: number
  }

  export type Verified = {
    identityId: string
    credentialId: string
    /** Caller-supplied metadata attached at issue (label, userAgent, etc.). */
    metadata: Record<string, unknown> | null
  }
}

export const DEFAULT_REMEMBER_ME_CONFIG: RememberMeFacet.Cfg = {
  ttlMs: 90 * 24 * 60 * 60 * 1000,
  byteLength: 32,
}

/**
 * Remember-me facet. Caller wires it next to the rest of the MFA
 * facets; the facet does not auto-mount because not every app wants a
 * remember-me path.
 */
export class RememberMeFacet {
  constructor(
    private readonly _credentials: Credential.Store,
    private readonly _crypto: {
      authRandomToken(bytes: number): string
      authSha256(s: string): string
    },
    private readonly _cfg: RememberMeFacet.Cfg = DEFAULT_REMEMBER_ME_CONFIG,
  ) {}

  /**
   * Mint + persist a remember-me token. Returns plaintext exactly once.
   * Caller-supplied `metadata` is opaque to the facet; common pairs
   * are { label, userAgent, ip } so the user-facing devices list can
   * surface them.
   */
  async issue(
    identityId: string,
    opts: { metadata?: Record<string, unknown> } = {},
    ctx: TenantContext = {},
  ): Promise<RememberMeFacet.Issued> {
    const token = this._crypto.authRandomToken(this._cfg.byteLength)
    const hash = this._crypto.authSha256(token)
    const now = Date.now()
    const expiresAt = now + this._cfg.ttlMs
    const cred = await this._credentials.upsert(
      toCredentialUpsert({
        identityId,
        kind: 'recovery',
        secret: hash,
        metadata: { purpose: 'trusted-device', ...(opts.metadata ?? {}) },
        expiresAt: new Date(expiresAt),
      }),
      ctx,
    )
    return { token, credentialId: cred.id, expiresAt }
  }

  /**
   * Verify a remember-me token. Returns null on miss / TTL expiry /
   * wrong-purpose row; throws `AUTH/RECOVERY_TOKEN_INVALID` only when
   * the input is structurally bogus (empty / non-string).
   *
   * Successful verifies do NOT consume the token (unlike backup codes
   * + magic links) - remember-me cookies are reused across many
   * sign-ins inside the TTL window.
   */
  async verify(token: string, ctx: TenantContext = {}): Promise<RememberMeFacet.Verified | null> {
    // cap token length at 256 chars to bound the sha256 cost.
    // Trusted-device tokens are 32 random bytes (~43 base64url chars).
    if (typeof token !== 'string' || token.length === 0 || token.length > 256) {
      throw new AuthError('AUTH_RECOVERY_TOKEN_INVALID')
    }
    const hash = this._crypto.authSha256(token)
    const row = await this._credentials.findByHashedSecret(hash, 'recovery', ctx)
    if (!row || isRevoked(row)) return null
    if (getCredentialPurpose(row) !== 'trusted-device') return null
    // defense against malformed `expiresAt` from a buggy adapter.
    // Centralized via `isCredentialExpired`.
    if (isCredentialExpired(row)) {
      void this._credentials.delete(row.id, ctx).catch(() => {})
      return null
    }
    return {
      identityId: row.identityId,
      credentialId: row.id,
      metadata: row.metadata,
    }
  }

  /**
   * List the live trusted devices for an identity. Returns the
   * credential row ids + caller-supplied metadata; never the secret.
   * Used to render a user-facing "devices" page.
   */
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
      .filter((r) => getCredentialPurpose(r) === 'trusted-device' && !isRevoked(r))
      .map((r) => ({
        credentialId: r.id,
        createdAt: r.createdAt,
        expiresAt: r.expiresAt,
        metadata: r.metadata,
      }))
  }

  /** Revoke a specific trusted-device row. */
  async revoke(identityId: string, credentialId: string, ctx: TenantContext = {}): Promise<void> {
    const row = await this._credentials.findById(credentialId, ctx)
    if (!row || row.identityId !== identityId) return
    await this._credentials.delete(credentialId, ctx)
  }

  /** Wipe every trusted device for an identity. */
  async revokeAll(identityId: string, ctx: TenantContext = {}): Promise<void> {
    const live = await this.list(identityId, ctx)
    for (const dev of live) {
      await this._credentials.delete(dev.credentialId, ctx)
    }
  }
}

/** Factory around {@link RememberMeFacet}, for callers who prefer functions to `new`. */
export function rememberMeFacet(...args: ConstructorParameters<typeof RememberMeFacet>): RememberMeFacet {
  return new RememberMeFacet(...args)
}
