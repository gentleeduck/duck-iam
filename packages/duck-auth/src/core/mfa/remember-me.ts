/**
 * @packageDocumentation
 * Remember-me / trusted-device facet. Issues a long-lived random token
 * the framework adapter stores in an `__Host-duck-device` cookie. On
 * subsequent sign-in attempts the consumer can present the token to
 * skip MFA (and grant aal=2 implicitly) for the device the cookie was
 * minted on.
 *
 * Storage shape: hashed token under `Credential.kind='recovery'` with
 * `metadata.purpose='trusted-device'` + caller-supplied metadata.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../errors'
import type { TenantContext } from '../types/context'
import type { Credential } from '../types/credential'

/**
 * Config knobs for `RememberMeFacet`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface RememberMeFacetConfig {
  /** Cookie / token TTL in ms. Default 90 days. */
  ttlMs: number
  /** Random-byte length minted per token. Default 32 (256 bits). */
  byteLength: number
}

export const DEFAULT_REMEMBER_ME_CONFIG: RememberMeFacetConfig = {
  ttlMs: 90 * 24 * 60 * 60 * 1000,
  byteLength: 32,
}

/**
 * Result of {@link RememberMeFacet.issue}. The plaintext token is
 * returned exactly once and persisted only in hashed form.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface RememberMeIssued {
  /** Plaintext token to drop into `__Host-duck-device` cookie. */
  token: string
  /** Credential row id; useful for client-side device listings. */
  credentialId: string
  /** Absolute expiry, ms since epoch. */
  expiresAt: number
}

/** Result of a successful {@link RememberMeFacet.verify}. */
export interface RememberMeVerified {
  identityId: string
  credentialId: string
  /** Caller-supplied metadata attached at issue (label, userAgent, etc.). */
  metadata: Record<string, unknown> | undefined
}

/**
 * Remember-me facet. Caller wires it next to the rest of the MFA
 * facets; the facet does not auto-mount because not every app wants a
 * remember-me path.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class RememberMeFacet {
  constructor(
    private readonly _credentials: Credential.IStore,
    private readonly _crypto: {
      randomToken(bytes: number): string
      sha256(s: string): string
    },
    private readonly _cfg: RememberMeFacetConfig = DEFAULT_REMEMBER_ME_CONFIG,
  ) {}

  /**
   * Mint + persist a remember-me token. Returns plaintext exactly once.
   * Caller-supplied `metadata` is opaque to the facet; common pairs
   * are { label, userAgent, ip } so the user-facing devices list can
   * surface them.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async issue(
    identityId: string,
    opts: { metadata?: Record<string, unknown> } = {},
    ctx: TenantContext = {},
  ): Promise<RememberMeIssued> {
    const token = this._crypto.randomToken(this._cfg.byteLength)
    const hash = this._crypto.sha256(token)
    const now = Date.now()
    const expiresAt = now + this._cfg.ttlMs
    const cred = await this._credentials.upsert(
      {
        identityId,
        kind: 'recovery',
        secret: hash,
        metadata: { purpose: 'trusted-device', ...(opts.metadata ?? {}) },
        expiresAt,
      },
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
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async verify(token: string, ctx: TenantContext = {}): Promise<RememberMeVerified | null> {
    if (typeof token !== 'string' || token.length === 0) {
      throw new AuthErrorObject('AUTH/RECOVERY_TOKEN_INVALID')
    }
    const hash = this._crypto.sha256(token)
    const row = await this._credentials.findByHashedSecret(hash, 'recovery', ctx)
    if (!row || row.revokedAt) return null
    const meta = row.metadata as { purpose?: string } | undefined
    if (meta?.purpose !== 'trusted-device') return null
    if (row.expiresAt !== undefined && row.expiresAt < Date.now()) {
      void this._credentials.delete(row.id, ctx).catch(() => {})
      return null
    }
    return {
      identityId: row.identityId,
      credentialId: row.id,
      metadata: row.metadata as Record<string, unknown> | undefined,
    }
  }

  /**
   * List the live trusted devices for an identity. Returns the
   * credential row ids + caller-supplied metadata; never the secret.
   * Used to render a user-facing "devices" page.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async list(
    identityId: string,
    ctx: TenantContext = {},
  ): Promise<
    Array<{
      credentialId: string
      createdAt: number
      expiresAt: number | undefined
      metadata: Record<string, unknown> | undefined
    }>
  > {
    const rows = await this._credentials.listByIdentity(identityId, 'recovery', ctx)
    return rows
      .filter((r) => {
        const m = r.metadata as { purpose?: string } | undefined
        return m?.purpose === 'trusted-device' && !r.revokedAt
      })
      .map((r) => ({
        credentialId: r.id,
        createdAt: r.createdAt,
        expiresAt: r.expiresAt,
        metadata: r.metadata as Record<string, unknown> | undefined,
      }))
  }

  /** Revoke a specific trusted-device row. */
  async revoke(credentialId: string, ctx: TenantContext = {}): Promise<void> {
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

/**
 * Namespace merge for `RememberMeFacet`. Co-locates config + result
 * shapes alongside the class.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace RememberMeFacet {
  /** Alias for `RememberMeFacetConfig`. */
  export type IConfig = RememberMeFacetConfig
  /** Alias for `RememberMeIssued`. */
  export type IIssued = RememberMeIssued
  /** Alias for `RememberMeVerified`. */
  export type IVerified = RememberMeVerified
}
