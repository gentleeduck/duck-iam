/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../errors'
import type { TenantContext } from '../types/context'
import type { Credential } from '../types/credential'
import type { Events } from '../types/events'

export interface ApiKeysFacetConfig {
  /** Token prefix; used to namespace by env. Default 'ak_live_'. */
  prefix: string
  /** Length of the random portion in bytes. Default 32 (43 base64url chars). */
  randomBytes: number
}

export const DEFAULT_APIKEYS_CONFIG: ApiKeysFacetConfig = {
  prefix: 'ak_live_',
  randomBytes: 32,
}

export interface ApiKey {
  id: string
  identityId: string
  name: string
  scopes: string[]
  createdAt: number
  lastUsedAt?: number
  expiresAt?: number
  revokedAt?: number
}

export interface CreatedApiKey {
  /** API key record (no plaintext). */
  key: ApiKey
  /** Plaintext token - returned ONCE; callers must surface to the user then drop. */
  plaintext: string
}

/**
 * API key facet - long-lived bearer tokens for service-to-service callers
 * that can't do mTLS. DESIGN section 35.
 *
 * Tokens are namespaced by prefix (`ak_live_` / `ak_test_`), scope-controlled
 * via iam policies (the scopes string set is projected into iam Subject
 * attributes by the bridge), and hashed at rest. Plaintext is returned
 * exactly once - at create - and never persisted.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class ApiKeysFacet {
  constructor(
    private readonly _credentials: Credential.IStore,
    private readonly _events: Events.IBus,
    private readonly _crypto: {
      randomToken(bytes: number): string
      sha256(s: string): string
    },
    private readonly _cfg: ApiKeysFacetConfig = DEFAULT_APIKEYS_CONFIG,
  ) {}

  /** Create a new API key. Returns plaintext exactly once. */
  async create(
    identityId: string,
    opts: { name: string; scopes: string[]; expiresAt?: number; tenantId?: string },
    ctx: TenantContext = {},
  ): Promise<CreatedApiKey> {
    const random = this._crypto.randomToken(this._cfg.randomBytes)
    const plaintext = `${this._cfg.prefix}${random}`
    const hash = this._crypto.sha256(plaintext)
    const cred = await this._credentials.upsert(
      {
        identityId,
        kind: 'api-key',
        secret: hash,
        metadata: { name: opts.name, scopes: opts.scopes },
        ...(opts.expiresAt !== undefined && { expiresAt: opts.expiresAt }),
        ...(opts.tenantId !== undefined && { tenantId: opts.tenantId }),
      },
      ctx,
    )
    const key: ApiKey = {
      id: cred.id,
      identityId,
      name: opts.name,
      scopes: opts.scopes,
      createdAt: cred.createdAt,
      ...(opts.expiresAt !== undefined && { expiresAt: opts.expiresAt }),
    }
    return { key, plaintext }
  }

  /** List the api keys belonging to an identity. No plaintext returned. */
  async list(identityId: string, ctx: TenantContext = {}): Promise<ApiKey[]> {
    const rows = await this._credentials.listByIdentity(identityId, 'api-key', ctx)
    return rows
      .filter((r) => !r.revokedAt)
      .map((r) => {
        const meta = r.metadata as { name?: string; scopes?: string[] } | undefined
        const k: ApiKey = {
          id: r.id,
          identityId: r.identityId,
          name: meta?.name ?? '',
          scopes: meta?.scopes ?? [],
          createdAt: r.createdAt,
        }
        if (r.lastUsedAt !== undefined) k.lastUsedAt = r.lastUsedAt
        if (r.expiresAt !== undefined) k.expiresAt = r.expiresAt
        return k
      })
  }

  /** Revoke an api key by row id. Used by UI "delete key" flow. */
  async revoke(keyId: string, ctx: TenantContext = {}): Promise<void> {
    await this._credentials.revoke(keyId, ctx)
  }

  /**
   * Rotate: issues a new plaintext, marks the old row revoked. Caller
   * tells consumers to swap. Returns the new plaintext exactly once.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async rotate(keyId: string, ctx: TenantContext = {}): Promise<CreatedApiKey> {
    const existing = await this._credentials.findById(keyId, ctx)
    if (!existing || existing.kind !== 'api-key') {
      throw new AuthErrorObject('AUTH/APIKEY_INVALID')
    }
    const meta = existing.metadata as { name?: string; scopes?: string[] } | undefined
    await this._credentials.revoke(keyId, ctx)
    return this.create(
      existing.identityId,
      {
        name: meta?.name ?? '',
        scopes: meta?.scopes ?? [],
        ...(existing.expiresAt !== undefined && { expiresAt: existing.expiresAt }),
      },
      ctx,
    )
  }

  /**
   * Verify a plaintext key. Returns the identity + scopes on success;
   * throws AUTH/APIKEY_INVALID / AUTH/APIKEY_REVOKED on failure.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async verify(
    plaintext: string,
    ctx: TenantContext = {},
  ): Promise<{ identityId: string; keyId: string; scopes: string[] }> {
    if (!plaintext.startsWith(this._cfg.prefix)) {
      throw new AuthErrorObject('AUTH/APIKEY_INVALID')
    }
    const hash = this._crypto.sha256(plaintext)
    const row = await this._credentials.findByHashedSecret(hash, 'api-key', ctx)
    if (!row) throw new AuthErrorObject('AUTH/APIKEY_INVALID')
    if (row.revokedAt) throw new AuthErrorObject('AUTH/APIKEY_REVOKED')
    if (row.expiresAt !== undefined && row.expiresAt < Date.now()) {
      throw new AuthErrorObject('AUTH/APIKEY_REVOKED')
    }
    // Best-effort lastUsedAt update; ignore failure.
    void this._credentials.rotate(row.id, row.secret, row.version, ctx).catch(() => {})
    const meta = row.metadata as { scopes?: string[] } | undefined
    return { identityId: row.identityId, keyId: row.id, scopes: meta?.scopes ?? [] }
  }

  /**
   * Helper for scope enforcement at the route. Throws AUTH/APIKEY_SCOPE_INSUFFICIENT
   * when the key lacks at least one required scope.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  requireScopes(have: string[], required: string[]): void {
    const missing = required.filter((s) => !have.includes(s))
    if (missing.length > 0) {
      throw new AuthErrorObject('AUTH/APIKEY_SCOPE_INSUFFICIENT', {
        required,
        have,
      })
    }
  }
}

/**
 * Namespace merge for ApiKeysFacet. Co-locates the config + input + output
 * shapes alongside the class via TS class+namespace merging. Consumers can
 * write either the flat name (e.g. ApiKeysFacetConfig) or the
 * namespaced form (ApiKeysFacet.IConfig); both
 * resolve to the same type.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace ApiKeysFacet {
  /** Alias for the flat `ApiKeysFacetConfig` type. */
  export type IConfig = ApiKeysFacetConfig
  /** Alias for the flat `ApiKey` type. */
  export type IApiKey = ApiKey
  /** Alias for the flat `CreatedApiKey` type. */
  export type ICreatedApiKey = CreatedApiKey
}
