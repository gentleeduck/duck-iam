import { isCredentialExpired } from '~/core/credential-utils'
import { AuthError } from '~/core/errors'
import type { Credential } from '~/core/types/identity'
import type { TenantContext } from '~/core/types/infra'
import type { Events } from '~/core/types/provider'
import { DEFAULT_APIKEYS_CONFIG } from './api-key.constants'
import type { ApiKeys } from './api-key.types'

/**
 * API key facet - long-lived bearer tokens for service-to-service callers
 * that can't do mTLS
 *
 * Tokens are namespaced by prefix (`ak_live_` / `ak_test_`), scope-controlled
 * via iam policies (the scopes string set is projected into iam Subject
 * attributes by the bridge), and hashed at rest. Plaintext is returned
 * exactly once - at create - and never persisted.
 */
export class ApiKeysFacet {
  readonly id = 'api-keys'
  readonly kind = 'api-key' as const

  constructor(
    private readonly _credentials: Credential.Store,
    readonly _events: Events.IBus,
    private readonly _crypto: {
      randomToken(bytes: number): string
      sha256(s: string): string
    },
    private readonly _cfg: ApiKeys.Config = DEFAULT_APIKEYS_CONFIG,
  ) {}

  /** Create a new API key. Returns plaintext exactly once. */
  async create(
    identityId: string,
    opts: { name: string; scopes: string[]; expiresAt?: number; tenantId?: string },
    ctx: TenantContext = {},
  ): Promise<ApiKeys.CreatedApiKey> {
    if (typeof opts.name !== 'string' || opts.name.length > 128) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'apikeys.create: name must be a string <=128 chars' })
    }
    if (!Array.isArray(opts.scopes) || opts.scopes.length > 64) {
      throw new AuthError('AUTH_MISCONFIGURED', { detail: 'apikeys.create: scopes must be array <=64' })
    }
    for (const s of opts.scopes) {
      if (typeof s !== 'string' || s.length === 0 || s.length > 128) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'apikeys.create: each scope must be a non-empty string <=128 chars',
        })
      }
    }
    const random = this._crypto.randomToken(this._cfg.randomBytes)
    const plaintext = `${this._cfg.prefix}${random}`
    const hash = this._crypto.sha256(plaintext)
    const cred = await this._credentials.upsert(
      {
        identityId,
        kind: 'api-key',
        secret: hash,
        metadata: { name: opts.name, scopes: opts.scopes },
        tenantId: opts.tenantId ?? null,
        expiresAt: opts.expiresAt != null ? new Date(opts.expiresAt) : null,
        lastUsedAt: null,
        revokedAt: null,
      },
      ctx,
    )
    const key: ApiKeys.ApiKey = {
      id: cred.id,
      identityId,
      name: opts.name,
      scopes: opts.scopes,
      createdAt: cred.createdAt,
      ...(opts.expiresAt !== undefined && { expiresAt: new Date(opts.expiresAt) }),
    }
    return { key, plaintext }
  }

  /** List the api keys belonging to an identity. No plaintext returned. */
  async list(identityId: string, ctx: TenantContext = {}): Promise<ApiKeys.ApiKey[]> {
    const rows = await this._credentials.listByIdentity(identityId, 'api-key', ctx)
    return rows
      .filter((r) => r.revokedAt == null)
      .map((r) => {
        const meta = parseApiKeyMetadata(r.metadata)
        const k: ApiKeys.ApiKey = {
          id: r.id,
          identityId: r.identityId,
          name: meta.name,
          scopes: meta.scopes,
          createdAt: r.createdAt,
        }
        if (r.lastUsedAt != null) k.lastUsedAt = r.lastUsedAt
        if (r.expiresAt != null) k.expiresAt = r.expiresAt
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
   */
  async rotate(keyId: string, ctx: TenantContext = {}): Promise<ApiKeys.CreatedApiKey> {
    const existing = await this._credentials.findById(keyId, ctx)
    if (existing?.kind !== 'api-key') {
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    const meta = parseApiKeyMetadata(existing.metadata)
    await this._credentials.revoke(keyId, ctx)
    return this.create(
      existing.identityId,
      {
        name: meta.name,
        scopes: meta.scopes,
        ...(existing.expiresAt != null && { expiresAt: existing.expiresAt.getTime() }),
      },
      ctx,
    )
  }

  /**
   * Verify a plaintext key. Returns the identity + scopes on success;
   * throws AUTH/APIKEY_INVALID / AUTH/APIKEY_REVOKED on failure.
   */
  async verify(
    plaintext: string,
    ctx: TenantContext = {},
  ): Promise<{ identityId: string; keyId: string; scopes: string[]; tenantId?: string }> {
    // 512-char cap before sha256 prevents multi-MB DoS via hashing.
    if (typeof plaintext !== 'string' || plaintext.length > 512) {
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    if (!plaintext.startsWith(this._cfg.prefix)) {
      // Synthetic sha256+lookup so prefix mismatch timing matches success path.
      this._crypto.sha256(plaintext)
      await this._credentials.findByHashedSecret('___invalid_prefix___', 'api-key', ctx).catch(() => null)
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    const hash = this._crypto.sha256(plaintext)
    const row = await this._credentials.findByHashedSecret(hash, 'api-key', ctx)
    if (!row) throw new AuthError('AUTH_APIKEY_INVALID')
    if (row.revokedAt != null) throw new AuthError('AUTH_APIKEY_REVOKED')
    if (isCredentialExpired(row)) throw new AuthError('AUTH_APIKEY_REVOKED')
    void this._credentials.rotate(row.id, row.secret, row.version, ctx).catch(() => {})
    const meta = parseApiKeyMetadata(row.metadata)
    return {
      identityId: row.identityId,
      keyId: row.id,
      scopes: meta.scopes,
      ...(row.tenantId != null && { tenantId: row.tenantId }),
    }
  }

  /**
   * Helper for scope enforcement at the route. Throws AUTH/APIKEY_SCOPE_INSUFFICIENT
   * when the key lacks at least one required scope.
   */
  requireScopes(have: string[], required: string[]): void {
    if (!Array.isArray(have) || !Array.isArray(required)) {
      throw new AuthError('AUTH_APIKEY_SCOPE_INSUFFICIENT', { required: [], have: [] })
    }
    const missing = required.filter((s) => !have.includes(s))
    if (missing.length > 0) {
      throw new AuthError('AUTH_APIKEY_SCOPE_INSUFFICIENT', {
        required,
        have,
      })
    }
  }
}

/** Parser for api-key `metadata`. Returns `{ name: '', scopes: [] }` on any malformed input. */
function parseApiKeyMetadata(meta: unknown): { name: string; scopes: string[] } {
  if (typeof meta !== 'object' || meta === null || Array.isArray(meta)) {
    return { name: '', scopes: [] }
  }
  const rawName: unknown = Reflect.get(meta, 'name')
  const name = typeof rawName === 'string' ? rawName : ''
  const rawScopes: unknown = Reflect.get(meta, 'scopes')
  if (!Array.isArray(rawScopes)) return { name, scopes: [] }
  const scopes: string[] = []
  for (const s of rawScopes) {
    if (typeof s === 'string') scopes.push(s)
  }
  return { name, scopes }
}
