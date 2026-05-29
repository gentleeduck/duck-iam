import { isCredentialExpired } from '../credential-utils'
import { AuthErrorObject } from '../errors'
import type { TenantContext } from '../types/context'
import type { Credential } from '../types/credential'
import type { Events } from '../types/events'

export const DEFAULT_APIKEYS_CONFIG: ApiKeysFacet.IConfig = {
  prefix: 'ak_live_',
  randomBytes: 32,
}

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
  constructor(
    private readonly _credentials: Credential.IStore,
    readonly _events: Events.IBus,
    private readonly _crypto: {
      randomToken(bytes: number): string
      sha256(s: string): string
    },
    private readonly _cfg: ApiKeysFacet.IConfig = DEFAULT_APIKEYS_CONFIG,
  ) {}

  /** Create a new API key. Returns plaintext exactly once. */
  async create(
    identityId: string,
    opts: { name: string; scopes: string[]; expiresAt?: number; tenantId?: string },
    ctx: TenantContext = {},
  ): Promise<ApiKeysFacet.ICreatedApiKey> {
    // Cap human-supplied fields so they don't bloat the credential row.
    // Empty name is allowed because rotate() carries over `meta.name` which
    // the parser coerces to '' on malformed legacy rows.
    if (typeof opts.name !== 'string' || opts.name.length > 128) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'apikeys.create: name must be a string <=128 chars' })
    }
    if (!Array.isArray(opts.scopes) || opts.scopes.length > 64) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', { detail: 'apikeys.create: scopes must be array <=64' })
    }
    for (const s of opts.scopes) {
      if (typeof s !== 'string' || s.length === 0 || s.length > 128) {
        throw new AuthErrorObject('AUTH/MISCONFIGURED', {
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
        ...(opts.expiresAt !== undefined && { expiresAt: opts.expiresAt }),
        ...(opts.tenantId !== undefined && { tenantId: opts.tenantId }),
      },
      ctx,
    )
    const key: ApiKeysFacet.IApiKey = {
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
  async list(identityId: string, ctx: TenantContext = {}): Promise<ApiKeysFacet.IApiKey[]> {
    const rows = await this._credentials.listByIdentity(identityId, 'api-key', ctx)
    return (
      rows
        // Explicit `=== undefined`: falsy would let `revokedAt: 0` slip past.
        .filter((r) => r.revokedAt === undefined)
        .map((r) => {
          // parseApiKeyMetadata fail-closes on malformed shapes; `as` would crash requireScopes.
          const meta = parseApiKeyMetadata(r.metadata)
          const k: ApiKeysFacet.IApiKey = {
            id: r.id,
            identityId: r.identityId,
            name: meta.name,
            scopes: meta.scopes,
            createdAt: r.createdAt,
          }
          if (r.lastUsedAt !== undefined) k.lastUsedAt = r.lastUsedAt
          if (r.expiresAt !== undefined) k.expiresAt = r.expiresAt
          return k
        })
    )
  }

  /** Revoke an api key by row id. Used by UI "delete key" flow. */
  async revoke(keyId: string, ctx: TenantContext = {}): Promise<void> {
    await this._credentials.revoke(keyId, ctx)
  }

  /**
   * Rotate: issues a new plaintext, marks the old row revoked. Caller
   * tells consumers to swap. Returns the new plaintext exactly once.
   */
  async rotate(keyId: string, ctx: TenantContext = {}): Promise<ApiKeysFacet.ICreatedApiKey> {
    const existing = await this._credentials.findById(keyId, ctx)
    if (!existing || existing.kind !== 'api-key') {
      throw new AuthErrorObject('AUTH/APIKEY_INVALID')
    }
    // structural parser; see list() comment.
    const meta = parseApiKeyMetadata(existing.metadata)
    await this._credentials.revoke(keyId, ctx)
    return this.create(
      existing.identityId,
      {
        name: meta.name,
        scopes: meta.scopes,
        ...(existing.expiresAt !== undefined && { expiresAt: existing.expiresAt }),
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
      throw new AuthErrorObject('AUTH/APIKEY_INVALID')
    }
    if (!plaintext.startsWith(this._cfg.prefix)) {
      // Synthetic sha256+lookup so prefix mismatch timing matches success path.
      this._crypto.sha256(plaintext)
      await this._credentials.findByHashedSecret('___invalid_prefix___', 'api-key', ctx).catch(() => null)
      throw new AuthErrorObject('AUTH/APIKEY_INVALID')
    }
    const hash = this._crypto.sha256(plaintext)
    const row = await this._credentials.findByHashedSecret(hash, 'api-key', ctx)
    if (!row) throw new AuthErrorObject('AUTH/APIKEY_INVALID')
    // `if (row.revokedAt)` treated `revokedAt: 0` as not-revoked;
    // also let through non-numeric values from buggy adapters. Compare
    // to `undefined` so any set value fails closed as revoked.
    if (row.revokedAt !== undefined) throw new AuthErrorObject('AUTH/APIKEY_REVOKED')
    // defense against malformed `expiresAt` from a buggy adapter.
    // Centralized via `isCredentialExpired`.
    if (isCredentialExpired(row)) {
      throw new AuthErrorObject('AUTH/APIKEY_REVOKED')
    }
    // Best-effort lastUsedAt update; ignore failure.
    void this._credentials.rotate(row.id, row.secret, row.version, ctx).catch(() => {})
    // Parser guarantees `string[]` scopes; `as` cast accepted type-confused rows.
    const meta = parseApiKeyMetadata(row.metadata)
    return {
      identityId: row.identityId,
      keyId: row.id,
      scopes: meta.scopes,
      ...(row.tenantId !== undefined && { tenantId: row.tenantId }),
    }
  }

  /**
   * Helper for scope enforcement at the route. Throws AUTH/APIKEY_SCOPE_INSUFFICIENT
   * when the key lacks at least one required scope.
   */
  requireScopes(have: string[], required: string[]): void {
    if (!Array.isArray(have) || !Array.isArray(required)) {
      // Fail-closed on shape mismatch; a buggy caller passing non-arrays
      // would otherwise crash with `.filter is not a function` or pass
      // type-confused values into the comparison.
      throw new AuthErrorObject('AUTH/APIKEY_SCOPE_INSUFFICIENT', { required: [], have: [] })
    }
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
 * shapes alongside the class via TS class+namespace merging.
 */
export namespace ApiKeysFacet {
  export interface IConfig {
    /** Token prefix; used to namespace by env. Default 'ak_live_'. */
    prefix: string
    /** Length of the random portion in bytes. Default 32 (43 base64url chars). */
    randomBytes: number
  }

  export interface IApiKey {
    id: string
    identityId: string
    name: string
    scopes: string[]
    createdAt: number
    lastUsedAt?: number
    expiresAt?: number
    revokedAt?: number
  }

  export interface ICreatedApiKey {
    /** API key record (no plaintext). */
    key: ApiKeysFacet.IApiKey
    /** Plaintext token - returned ONCE; callers must surface to the user then drop. */
    plaintext: string
  }
}

/**
 * structural parser for the API-key
 * credential's `metadata` field. Previously read via
 * `row.metadata as { name?: string; scopes?: string[] } | undefined` -
 * a lie. Concrete failures the cast masked:
 *
 *  - `metadata: { scopes: 'admin' }` (string, not array, from a buggy
 *    adapter or schema drift) - the cast happily typed it as `string[]`;
 *    downstream `requireScopes(have).filter(...)` throws TypeError
 *    because strings have no `.filter`. Surfaces as HTTP 500.
 *  - `metadata: { scopes: [1, 2, 3] }` (numbers) - type-confused
 *    `.includes('admin')` returns false (correct fail-closed for this
 *    case) but the typing lie propagated into iam Subject attributes,
 *    where a policy comparing `subject.scopes` to a known string set
 *    behaves unpredictably.
 *  - `metadata: { name: 42 }` - non-string name flowed into the public
 *    API surface; UIs serialize `key.name` into HTML, etc.
 *  - `metadata: null` - fine for the optional-chain, but `metadata: 'oops'`
 *    (string) - the cast forgave it and `meta?.scopes` returned `undefined`.
 *    Same end-state as null. No security issue here, just inconsistent.
 *
 * Returns concrete defaults (`{ name: '', scopes: [] }`) instead of
 * `undefined` so call sites are guaranteed-typed: the caller never
 * needs to write `meta?.scopes ?? []`. Scope entries that aren't
 * strings are filtered out individually - a `scopes: ['admin', 42]`
 * leaks `['admin']` and drops the bad value (defense in depth without
 * full rejection).
 */
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
