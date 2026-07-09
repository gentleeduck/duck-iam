import { isCredentialExpired } from '~/core/credentials/credentials'
import { randomToken, sha256 } from '~/core/crypto'
import type { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import type { Events } from '~/core/events/events.types'
import type { Identity } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import type { Credential } from '~/core/types/identity'
import type { TenantContext } from '~/core/types/infra'
import { DEFAULT_APIKEYS_CONFIG, toApiKeysConfig } from './api-key.constants'
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

/**
 * `api-key` sign-in provider - bearer-style sign-in for service-to-service
 * callers. The provider verifies the plaintext token via `ApiKeysFacet`,
 * applies the configured per-key rate-limit, and emits a `startSession`
 * Intent with `kind: 'api-key'` + `aal: 1`.
 */
export class AuthApiKeyImpl<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>
  implements Provider.Me<ApiKeys.BeginInput, ApiKeys.CompleteInput, Profile>
{
  readonly id = 'api-key'
  readonly kind = 'api-key' as const
  private readonly prefix: string

  constructor(private readonly opts: ApiKeys.Options) {
    this.prefix = opts.limiterKeyPrefix ?? 'signin:api-key:'
  }

  async begin(): Promise<Provider.Intent[]> {
    return []
  }

  async complete(ctx: Provider.Context<Profile>, input: ApiKeys.CompleteInput): Promise<Provider.InternalIntent[]> {
    // typeof-guard prevents sha256(non-string) throwing TypeError before the
    // rate limiter can fire (caller would see 500 instead of 401, plus the
    // call would bypass the per-token brute-force quota).
    if (typeof input.token !== 'string' || input.token.length === 0 || input.token.length > 512) {
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    const keyHash = ctx.crypto.authSha256(input.token).slice(0, 16)
    const rl = await ctx.limiter.consume(`${this.prefix}${keyHash}`)
    if (!rl.ok) {
      throw new AuthError('AUTH_RATE_LIMITED', {
        retryAfter: Math.max(1, Math.ceil((rl.resetAt.getTime() - Date.now()) / 1000)),
      })
    }
    const verified = await this.opts.apiKeys.verify(input.token, ctx.tenant)
    // A tenant-bound api-key must NOT identify-confirm on a different (or empty)
    // tenant scope; otherwise the resulting session lacks the key's tenancy
    // while the caller still holds proof-of-key for that tenant.
    if (verified.tenantId !== undefined && ctx.tenant.tenantId !== verified.tenantId) {
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    if (this.opts.requireScopes && this.opts.requireScopes.length > 0) {
      this.opts.apiKeys.requireScopes(verified.scopes, this.opts.requireScopes)
    }
    return [
      {
        type: 'startSession',
        identityId: verified.identityId,
        factors: [{ method: 'api-key', completedAt: new Date() }],
        aal: 1,
      },
    ]
  }
}

/** Factory around {@link AuthApiKeyImpl} for functional-style config. */
export function authApiKey<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  opts: ApiKeys.Options,
): Provider.Me<ApiKeys.BeginInput, ApiKeys.CompleteInput, Profile> {
  return new AuthApiKeyImpl(opts)
}

/**
 * API-key capability. Owns the ApiKeysFacet, resolved via `auth.apiKeys`.
 * The bearer *sign-in* provider ({@link authApiKey}) is registered separately
 * by the app, since it binds to the mounted facet + app-specific scope rules.
 */
export function apiKeyProvider<
  Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(cfg?: ApiKeys.ConfigInput): (auth: AuthEngine<Profile, Tenant, OrgMeta>) => ApiKeysFacet {
  return (auth) =>
    new ApiKeysFacet(auth.config.stores.credentials, auth.events, { randomToken, sha256 }, toApiKeysConfig(cfg))
}
