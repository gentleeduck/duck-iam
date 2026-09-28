import { type Answer, answer, orNull } from '~/core/answer'
import { isCredentialExpired } from '~/core/credentials/credentials'
import type { Credential } from '~/core/credentials/credentials.types'
import { randomToken, sha256 } from '~/core/crypto'
import type { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import { refuseRateLimited } from '~/core/events/events.lockout'
import type { Events } from '~/core/events/events.types'
import type { Identities } from '~/core/identities'
import type { Provider } from '~/core/provider/provider.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import type { TenantContext } from '~/core/tenant/tenant.types'
import { APIKEY_MAX_LENGTH, isScopeToken, toApiKeysCfg } from './api-key.constants'
import type { ApiKeys } from './api-key.types'

/** Project a credential row onto the public `ApiKey` shape: no secret, and the optional timestamps
 *  only when the row carries them. Shared by `list` and the revokes so they cannot drift. */
function toApiKey(row: Credential.Me): ApiKeys.ApiKey {
  const meta = parseApiKeyMetadata(row.metadata)
  const key: ApiKeys.ApiKey = {
    createdAt: row.createdAt,
    id: row.id,
    identityId: row.identityId,
    name: meta.name,
    scopes: meta.scopes,
    updatedAt: row.updatedAt,
  }
  if (row.tenantId != null) key.tenantId = row.tenantId
  if (row.lastUsedAt != null) key.lastUsedAt = row.lastUsedAt
  if (row.expiresAt != null) key.expiresAt = row.expiresAt
  // `revoke()` promises the key as it stands revoked, so this is the field that says so. `list()`
  // filters revoked rows out, so there it stays absent.
  if (row.revokedAt != null) key.revokedAt = row.revokedAt
  return key
}

/** Long-lived bearer keys for scripts and services, scoped and hashed at rest; the plaintext is answered
 *  exactly once, at create, and never persisted. */
export class ApiKeysFacet {
  readonly id = 'api-keys'
  readonly kind = 'api-key' as const
  private readonly _cfg: ApiKeys.Cfg

  constructor(
    private readonly _credentials: Credential.Store,
    readonly _events: Events.IBus,
    private readonly _crypto: {
      randomToken(bytes: number): string
      sha256(s: string): string
    },
    cfg?: ApiKeys.CfgInput,
    /** Optional so a direct `new ApiKeysFacet(...)` keeps working, though `apiKeyProvider()` always
     *  supplies it, and without it `verify` answers for a soft-deleted identity. Structural rather than
     *  `Identities.Store`, so the facet stays non-generic and names the one call it makes. */
    private readonly _identities?: ApiKeys.IdentityProbe,
    /** Where the sessions a key signed in live, so revoking the key ends them. */
    private readonly _sessions?: Sessions.Store,
  ) {
    // Resolved here, so a facet built by hand is checked as `apiKeyProvider` builds it.
    this._cfg = toApiKeysCfg(cfg)
  }

  /** Re-bind to a caller's transaction. Inside the class because `_credentials`, `_crypto` and `_cfg`
   *  are private. The probe comes off the same bound bag, so a key verified inside the transaction
   *  sees its deletions too. */
  withClient(stores: Provider.Stores, events: Events.IBus): ApiKeysFacet {
    return new ApiKeysFacet(stores.credentials, events, this._crypto, this._cfg, stores.identities, stores.sessions)
  }

  /** The plaintext comes back exactly once. */
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
      if (!isScopeToken(s)) {
        throw new AuthError('AUTH_MISCONFIGURED', {
          detail: 'apikeys.create: each scope must match the RFC 6749 scope-token grammar',
        })
      }
    }
    const random = this._crypto.randomToken(this._cfg.randomBytes)
    const plaintext = `${this._cfg.prefix}${random}`
    const hash = this._crypto.sha256(plaintext)
    const cred = await this._credentials.create(
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
      updatedAt: cred.updatedAt,
      ...(opts.expiresAt !== undefined && { expiresAt: new Date(opts.expiresAt) }),
    }
    return { key, plaintext }
  }

  /** No plaintext. */
  async list(identityId: string, ctx: TenantContext = {}): Promise<ApiKeys.ApiKey[]> {
    const rows = await this._credentials.listByIdentity(identityId, 'api-key', ctx)
    return rows.filter((r) => r.revokedAt == null).map(toApiKey)
  }

  /** Revoke an api key by row id, answering with it as it stands revoked so a caller can show which
   *  one went. A row that is not an api key is not one to revoke, and rejects as absent. */
  revoke(keyId: string, ctx: TenantContext = {}): Answer.Me<ApiKeys.ApiKey> {
    return answer(async () => {
      // SECURITY: the kind is checked before the write, as in `rotate`. Revoking first and rejecting
      // afterwards let this facet revoke a recovery or oauth row and report that it found nothing.
      const existing = await this._credentials.findById(keyId, ctx)
      if (existing.kind !== 'api-key') throw new AuthError('AUTH_CREDENTIAL_NOT_FOUND')

      const revoked = toApiKey(await this._credentials.revoke(keyId, ctx))
      await this._endKeySessions(existing.identityId)
      return revoked
    })
  }

  /** Revoke every live api key the identity holds in one write, answering them as they stand revoked. */
  async revokeAll(identityId: string, ctx: TenantContext = {}): Promise<ApiKeys.ApiKey[]> {
    const revoked = (await this._credentials.revokeByKind(identityId, 'api-key', ctx)).map(toApiKey)
    await this._endKeySessions(identityId)
    return revoked
  }

  /** Issues a new plaintext, exactly once, and marks the old row revoked; telling consumers to swap is
   *  the caller's job. */
  async rotate(keyId: string, ctx: TenantContext = {}): Promise<ApiKeys.CreatedApiKey> {
    const existing = await orNull(this._credentials.findById(keyId, ctx))
    if (existing?.kind !== 'api-key') {
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    // Refused as `verify` refuses it, or rotating a revoked key hands back a working one.
    if (existing.revokedAt != null || isCredentialExpired(existing)) {
      throw new AuthError('AUTH_APIKEY_REVOKED')
    }
    const meta = parseApiKeyMetadata(existing.metadata)
    await this._credentials.revoke(keyId, ctx)
    await this._endKeySessions(existing.identityId)
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

  /** Ends every session a key signed the identity in with, in any tenant: a session does not record which key
   *  opened it. */
  private async _endKeySessions(identityId: string): Promise<void> {
    if (!this._sessions) return
    const opened = (await this._sessions.listByIdentity(identityId)).filter((s) => s.kind === 'apikey')
    if (opened.length === 0) return
    for (const s of await this._sessions.deleteMany(opened.map((s) => s.id))) {
      await this._events.emit('session.revoked', { sessionId: s.id, identityId: s.identityId })
    }
  }

  /** Answers the identity and its scopes, or throws `AUTH_APIKEY_INVALID` or `AUTH_APIKEY_REVOKED`. */
  async verify(
    plaintext: string,
    ctx: TenantContext = {},
  ): Promise<{ identityId: string; keyId: string; scopes: string[]; tenantId?: string }> {
    // Capped before sha256, against a multi-MB hashing DoS.
    if (typeof plaintext !== 'string' || plaintext.length > APIKEY_MAX_LENGTH) {
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    if (!plaintext.startsWith(this._cfg.prefix)) {
      // A synthetic sha256 and lookup, so a prefix mismatch takes as long as the success path.
      this._crypto.sha256(plaintext)
      await this._credentials.findByHashedSecret('___invalid_prefix___', 'api-key', ctx).catch(() => null)
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    const hash = this._crypto.sha256(plaintext)
    const row = await orNull(this._credentials.findByHashedSecret(hash, 'api-key', ctx))
    if (!row) throw new AuthError('AUTH_APIKEY_INVALID')
    if (row.revokedAt != null) throw new AuthError('AUTH_APIKEY_REVOKED')
    if (isCredentialExpired(row)) throw new AuthError('AUTH_APIKEY_REVOKED')
    // SECURITY: a key outlives its owner otherwise. Nothing re-reads the identity here the way
    // `flows.signIn` does, and `M2MImpl.exchange` mints a session straight from the id.
    if (this._identities && !(await orNull(this._identities.find({ id: row.identityId })))) {
      // The same error as an unknown key: whether an id still exists is not for an unauthenticated
      // caller to probe.
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    void this._credentials.rotate(row.id, row.secret, row.version, ctx).catch(() => {})
    const meta = parseApiKeyMetadata(row.metadata)
    return {
      identityId: row.identityId,
      keyId: row.id,
      scopes: meta.scopes,
      ...(row.tenantId != null && { tenantId: row.tenantId }),
    }
  }

  /** For scope enforcement at the route. Throws `AUTH_APIKEY_SCOPE_INSUFFICIENT` when the key lacks any
   *  required scope. */
  requireScopes(have: string[], required: string[]): void {
    if (!Array.isArray(have) || !Array.isArray(required)) {
      throw new AuthError('AUTH_APIKEY_SCOPE_INSUFFICIENT', { required: [], missing: [] })
    }
    const missing = required.filter((s) => !have.includes(s))
    if (missing.length > 0) {
      // `missing` is a subset of `required`, which the caller supplied. The set the key actually
      // holds is not reported: an error body forwarded to a client, or written to a shared log,
      // would otherwise spread every scope the key has to whoever probed it with one.
      throw new AuthError('AUTH_APIKEY_SCOPE_INSUFFICIENT', { required, missing })
    }
  }
}

/** `{ name: '', scopes: [] }` on any malformed input. */
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

/** Bearer-style sign-in for service-to-service callers: verifies the plaintext token via
 *  `ApiKeysFacet`, applies the per-key rate limit and emits a `startSession` intent at
 *  `kind: 'apikey'`, `aal: 1`. */
export class AuthApiKeyImpl<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>
  implements Provider.Me<ApiKeys.BeginInput, ApiKeys.CompleteInput, Profile>
{
  readonly id = 'api-key'
  readonly kind = 'api-key' as const
  private readonly prefix: string

  constructor(private readonly opts: ApiKeys.Options) {
    this.prefix = opts.limiterKeyPrefix ?? 'signin:api-key:'
  }

  /** The facet is captured in `opts` rather than read from `ctx`, so re-binding the context is not
   *  enough: this swaps in a facet bound to the caller's client. */
  withClient(stores: Provider.Stores, events: Events.IBus): AuthApiKeyImpl<Profile> {
    return new AuthApiKeyImpl<Profile>({ ...this.opts, apiKeys: this.opts.apiKeys.withClient(stores, events) })
  }

  /** No begin step: an api key is presented outright, not negotiated. */
  async begin(): Promise<Provider.Intent[]> {
    return []
  }

  /** Verifies the presented key and answers the intents that open the session. */
  async complete(ctx: Provider.Context<Profile>, input: ApiKeys.CompleteInput): Promise<Provider.InternalIntent[]> {
    // Guarded, or `sha256` on a non-string throws TypeError before the rate limiter can fire: the caller
    // sees a 500 rather than a 401, and the call skips the per-token brute-force quota.
    if (typeof input.token !== 'string' || input.token.length === 0 || input.token.length > APIKEY_MAX_LENGTH) {
      throw new AuthError('AUTH_APIKEY_INVALID')
    }
    const keyHash = ctx.crypto.authSha256(input.token).slice(0, 16)
    const rl = await ctx.limiter.consume(`${this.prefix}${keyHash}`)
    // Through the shared refusal, like every other limiter guard. The version built here called
    // `.getTime()` on `resetAt` directly, and `Limiter.Me` is the host's to implement: one backed by
    // redis, or by anything with a JSON hop, hands back epoch milliseconds and that throws - a 500 out
    // of the guard whose whole job is to answer 429.
    if (!rl.ok) await refuseRateLimited(ctx.events, rl, null)
    const verified = await this.opts.apiKeys.verify(input.token, ctx.tenant)
    // A tenant-bound api-key must not identify-confirm on a different or empty tenant scope, or the
    // resulting session lacks the key's tenancy while the caller still holds proof-of-key for it.
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
        kind: 'apikey',
      },
    ]
  }
}

/** The api-key provider, ready to hand to `providers`. */
export function authApiKey<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  opts: ApiKeys.Options,
): Provider.Me<ApiKeys.BeginInput, ApiKeys.CompleteInput, Profile> {
  return new AuthApiKeyImpl(opts)
}

/** Owns the `ApiKeysFacet`, resolved via `auth.apiKeys`. The bearer sign-in provider
 *  ({@link authApiKey}) is registered separately, since it binds to the mounted facet. */
export function apiKeyProvider<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(cfg?: ApiKeys.CfgInput): (auth: AuthEngine<Profile, Tenant, OrgMeta>) => ApiKeysFacet {
  return (auth) =>
    new ApiKeysFacet(
      auth.cfg.stores.credentials,
      auth.events,
      { randomToken, sha256 },
      cfg,
      auth.cfg.stores.identities,
      auth.cfg.stores.sessions,
    )
}

/** Constructs an {@link ApiKeysFacet}. */
export function apiKeysFacet(...args: ConstructorParameters<typeof ApiKeysFacet>): ApiKeysFacet {
  return new ApiKeysFacet(...args)
}
