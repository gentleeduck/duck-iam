import { authRandomToken, authSha256, authTimingSafeEqual } from './crypto'
import { AuthErrorObject } from './errors'
import { AuthInMemoryEvents } from './events'
import { AnomalyFacet, DEFAULT_ANOMALY_CONFIG } from './facets/anomaly'
import { ApiKeysFacet, DEFAULT_APIKEYS_CONFIG } from './facets/apikeys'
import { DEFAULT_FLOWS_CONFIG, FlowsFacet } from './facets/flows'
import { HijackFacet } from './facets/hijack'
import { DEFAULT_IDEMPOTENCY_CONFIG, IdempotencyFacet, MemoryIdempotencyStore } from './facets/idempotency'
import { DEFAULT_IDENTITIES_CONFIG, IdentitiesFacet } from './facets/identities'
import { DEFAULT_MFA_CONFIG, MfaFacet } from './facets/mfa'
import { OperationsFacet } from './facets/operations'
import { OrgsFacet } from './facets/orgs'
import { DEFAULT_PASSWORDS_CONFIG, PasswordsFacet } from './facets/passwords'
import { ProvidersFacet } from './facets/providers'
import { DEFAULT_SESSION_CONFIG, resolveBySid, SessionsFacet } from './facets/sessions'
import { ScryptHasher } from './password/scrypt'
import { AuthPluginRegistry } from './plugin'
import type { AuthCredential } from './types/credential'
import type { AuthEvents } from './types/events'
import type { AuthHasher } from './types/hasher'
import type { AuthIdentity } from './types/identity'
import type { AuthLimiter, AuthLimiter as LimiterNs } from './types/limiter'
import type { AuthOrg } from './types/org'
import type { AuthProvider } from './types/provider'
import type { AuthSession } from './types/session'
import type { AuthTransport } from './types/transport'

/**
 * Faceted authentication root. Composition surface only - every operation
 * lives on a facet (sessions, identities, providers, mfa, flows, ...).
 * Facets are added one at a time as features land.
 */
export class AuthEngine<Profile = unknown, Tenant = string, OrgMeta = unknown> {
  readonly config: AuthEngine.IConfig<Profile, Tenant, OrgMeta>
  readonly events: AuthEvents.IBus
  readonly transport: AuthTransport.ITransport
  readonly sessions: SessionsFacet
  readonly identities: IdentitiesFacet<Profile>
  readonly passwords: PasswordsFacet
  readonly providers: ProvidersFacet<Profile>
  readonly mfa: MfaFacet
  readonly apiKeys: ApiKeysFacet
  readonly orgs: OrgsFacet<OrgMeta> | null
  readonly flows: FlowsFacet<Profile>
  readonly limiter: LimiterNs.ILimiter
  readonly plugins: AuthPluginRegistry<Profile, Tenant, OrgMeta>
  readonly operations: OperationsFacet
  readonly idempotency: IdempotencyFacet
  readonly hijack: HijackFacet
  readonly anomaly: AnomalyFacet

  constructor(config: AuthEngine.IConfig<Profile, Tenant, OrgMeta>) {
    this.config = config
    this.events = config.events ?? new AuthInMemoryEvents()
    this.transport = config.transport
    this.limiter = config.limiter ?? new AuthNoopLimiter()
    this.sessions = new SessionsFacet(config.stores.sessions, this.events, {
      ttlMs: config.session?.ttlMs ?? DEFAULT_SESSION_CONFIG.ttlMs,
      absoluteTtlMs: config.session?.absoluteTtlMs ?? DEFAULT_SESSION_CONFIG.absoluteTtlMs,
      freshnessMs: config.session?.freshnessMs ?? DEFAULT_SESSION_CONFIG.freshnessMs,
    })
    this.identities = new IdentitiesFacet<Profile>(config.stores.identities, this.events, {
      softDeleteGracePeriodMs:
        config.identities?.softDeleteGracePeriodMs ?? DEFAULT_IDENTITIES_CONFIG.softDeleteGracePeriodMs,
      profileMaxBytes: config.identities?.profileMaxBytes ?? DEFAULT_IDENTITIES_CONFIG.profileMaxBytes,
    })
    this.passwords = new PasswordsFacet(config.stores.credentials, config.passwords?.hasher ?? new ScryptHasher(), {
      minLength: config.passwords?.minLength ?? DEFAULT_PASSWORDS_CONFIG.minLength,
      maxLength: config.passwords?.maxLength ?? DEFAULT_PASSWORDS_CONFIG.maxLength,
      rejectCommon: config.passwords?.rejectCommon ?? DEFAULT_PASSWORDS_CONFIG.rejectCommon,
    })
    this.providers = new ProvidersFacet<Profile>(config.providers ?? [])
    this.mfa = new MfaFacet(config.stores.credentials, this.events, {
      issuer: config.mfa?.issuer ?? DEFAULT_MFA_CONFIG.issuer,
      backupCodeCount: config.mfa?.backupCodeCount ?? DEFAULT_MFA_CONFIG.backupCodeCount,
      backupCodeLen: config.mfa?.backupCodeLen ?? DEFAULT_MFA_CONFIG.backupCodeLen,
    })
    this.apiKeys = new ApiKeysFacet(
      config.stores.credentials,
      this.events,
      { authRandomToken, authSha256 },
      {
        prefix: config.apiKeys?.prefix ?? DEFAULT_APIKEYS_CONFIG.prefix,
        randomBytes: config.apiKeys?.randomBytes ?? DEFAULT_APIKEYS_CONFIG.randomBytes,
      },
    )
    this.orgs = config.stores.orgs ? new OrgsFacet<OrgMeta>(config.stores.orgs, this.events) : null
    this.plugins = new AuthPluginRegistry<Profile, Tenant, OrgMeta>()
    this.operations = new OperationsFacet(this.events)
    this.idempotency = new IdempotencyFacet(new MemoryIdempotencyStore(), DEFAULT_IDEMPOTENCY_CONFIG)
    this.hijack = new HijackFacet(this.events, config.hijack ?? {})
    this.anomaly = new AnomalyFacet(this.events, DEFAULT_ANOMALY_CONFIG)
    this.flows = new FlowsFacet<Profile>(
      this.sessions,
      this.identities,
      this.providers,
      this.transport,
      this.events,
      (tenantId) => ({
        stores: config.stores,
        tenant: tenantId !== undefined ? { tenantId } : {},
        baseUrl: config.baseUrl,
        limiter: this.limiter,
        events: this.events,
        crypto: {
          authRandomToken: (bytes) => authRandomToken(bytes),
          authSha256: (s) => authSha256(s),
          authTimingSafeEqual,
        },
      }),
      this.passwords,
      this.mfa,
      DEFAULT_FLOWS_CONFIG,
    )
  }

  /**
   * Resolve the current session from the request. Returns `null` when no
   * transport token is present or the token doesn't match a live session.
   *
   * Delegates to {@link AuthTransport.verify} when the transport can verify
   * stateless tokens (JWT); otherwise looks up via {@link AuthSession.IStore}.
   */
  async resolveSession(
    req: { headers: Headers },
    opts: { expectedTenantId?: string; requestSnapshot?: import('./types/anomaly').AuthAnomaly.RequestSnapshot } = {},
  ): Promise<{
    session: AuthSession.ISession
    identity: AuthIdentity.IIdentity<Profile> | null
    /**
     * Aggregate anomaly decision when at least one detector is
     * registered AND `opts.requestSnapshot` was supplied. Operators
     * branch on `anomaly.decision === 'deny'` / `'step-up'` /
     * `'allow'`; the field is absent when no detectors run.
     */
    anomaly?: import('./facets/anomaly').AnomalyFacet.IResult
  } | null> {
    const token = this.transport.extract(req)
    if (!token) return null

    const finalize = async (
      session: AuthSession.ISession,
      identity: AuthIdentity.IIdentity<Profile> | null,
    ): Promise<{
      session: AuthSession.ISession
      identity: AuthIdentity.IIdentity<Profile> | null
      anomaly?: import('./facets/anomaly').AnomalyFacet.IResult
    }> => {
      // Auto-evaluate anomaly detectors so routes branch on a single field.
      if (opts.requestSnapshot && identity && this.anomaly.list().length > 0) {
        try {
          const result = await this.anomaly.evaluate({ session, identity, req: opts.requestSnapshot })
          return { session, identity, anomaly: result }
        } catch {
          // Detector machinery already catches per-detector throws;
          // this catch defends against a bug in the aggregator itself.
          return { session, identity }
        }
      }
      return { session, identity }
    }

    if (this.transport.verify) {
      const verified = await this.transport.verify(token)
      if (verified) {
        // Cross-tenant guard; a token minted under tenant A must not
        // be honoured at a tenant-B endpoint.
        if (opts.expectedTenantId !== undefined && verified.tenantId !== opts.expectedTenantId) {
          return null
        }
        const ctx = { ...(verified.tenantId !== undefined && { tenantId: verified.tenantId }) }
        const identity = verified.identityId
          ? await this.config.stores.identities.findById(verified.identityId, ctx)
          : null
        return finalize(verified, identity)
      }
    }

    const resolved = await resolveBySid(token, this.config.stores.sessions, this.config.stores.identities, {})
    if (!resolved) return null
    // same cross-tenant guard as the JWT branch. Reject mismatches
    // AND undefined-vs-expected - see the JWT branch comment above.
    if (opts.expectedTenantId !== undefined && resolved.session.tenantId !== opts.expectedTenantId) {
      return null
    }
    return finalize(resolved.session, resolved.identity)
  }

  /** Install a plugin atomically (providers + events + facets) */
  async use(plugin: AuthPluginRegistry.IAuthPlugin<Profile, Tenant, OrgMeta>): Promise<void> {
    await this.plugins.install(this, plugin)
  }

  /** Boot-time strict validation; throws `AUTH/MISCONFIGURED` on any production footgun. */
  strict(opts: { env: 'development' | 'production' | 'test' }): void {
    if (opts.env !== 'production') return

    const errors: string[] = []

    // Reject AuthNoopLimiter via class brand (bundlers rename constructors).
    if (!this.config.limiter || (this.limiter as { __isNoopLimiter?: boolean }).__isNoopLimiter === true) {
      errors.push('AuthLimiter adapter required (brute-force protection); AuthNoopLimiter rejected in production')
    }

    // Memory adapter detection over every store; mixed deployments would otherwise
    // run session state in-process and break revocation/rotation across instances.
    const stores: Array<{ obj: unknown; label: string }> = [
      { obj: this.config.stores.identities, label: 'identities' },
      { obj: this.config.stores.sessions, label: 'sessions' },
      { obj: this.config.stores.credentials, label: 'credentials' },
    ]
    for (const { obj, label } of stores) {
      const name = (obj as { constructor?: { name?: string } }).constructor?.name ?? ''
      if (name === 'Object' || /Memory/i.test(name)) {
        errors.push(`Memory adapter (${label}) rejected in production; use redis/drizzle/prisma`)
      }
    }

    // AuthTransport secure-cookie check via the public `secure` getter so
    // we never reach into private state.
    const maybeSecureGetter = (this.config.transport as { secure?: boolean }).secure
    if (typeof maybeSecureGetter === 'boolean' && maybeSecureGetter === false) {
      errors.push('AuthCookieTransport secure=false rejected in production')
    }

    // baseUrl must use HTTPS in production so OAuth callback URLs, magic-link
    // URLs, and webhooks aren't issued over plaintext.
    if (typeof this.config.baseUrl === 'string') {
      try {
        const u = new URL(this.config.baseUrl)
        if (u.protocol !== 'https:') {
          errors.push(`baseUrl '${this.config.baseUrl}' must use https:// in production (got ${u.protocol})`)
        }
      } catch {
        errors.push(`baseUrl '${this.config.baseUrl}' is not a valid URL`)
      }
    }

    if ((this.config.providers ?? []).length === 0 && this.providers.list().length === 0) {
      errors.push('no provider registered; users cannot sign in')
    }

    // `lockout` listener via the public `listenerCount` introspection
    // helper. Bus implementations without the helper skip this check
    // (we cannot enforce against a foreign AuthEvents.IBus impl).
    const listenerCount = (this.events as { listenerCount?: (event: string) => number }).listenerCount
    if (typeof listenerCount === 'function' && listenerCount.call(this.events, 'lockout') === 0) {
      errors.push('no `lockout` event handler subscribed; operators must wire one (paging, audit, etc.)')
    }

    if (errors.length > 0) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: `production strict() checks failed:\n  - ${errors.join('\n  - ')}`,
      })
    }
  }
}

// Re-export SessionsFacet for consumers that want to type the facet directly.
// `SessionsFacet.IConfig`, `.ICreateInput`, `.IRotateInput` ride along via class+namespace merge.
export { SessionsFacet } from './facets/sessions'

// Used by other facets that need the hashing scheme. Kept private to the package.
export const __hashSid = authSha256

/**
 * No-op limiter used when no AuthLimiter adapter is configured. Always allows.
 * `strict({ env: 'production' })` rejects this - production must supply a real
 * AuthLimiter (redis/upstash) for brute-force protection.
 */
export class AuthNoopLimiter implements LimiterNs.ILimiter {
  /** Brand consumed by `AuthEngine.strict({ env: 'production' })` to
   * detect "explicit AuthNoopLimiter" - class-identity comparison breaks
   * across bundler rewrites (treeshaken duplicates / nested workspaces)
   * so we tag every instance and check the tag instead. */
  readonly __isNoopLimiter = true as const
  async consume(_key: string, _weight = 1): Promise<LimiterNs.IResult> {
    return { ok: true, remaining: Number.POSITIVE_INFINITY, resetAt: Date.now() + 60_000 }
  }
  async reset(_key: string): Promise<void> {}
}

export namespace AuthEngine {
  export interface IConfig<Profile = unknown, Tenant = string, OrgMeta = unknown> {
    baseUrl: string
    transport: AuthTransport.ITransport
    stores: {
      identities: AuthIdentity.IStore<Profile>
      sessions: AuthSession.IStore
      credentials: AuthCredential.IStore
      orgs?: AuthOrg.IStore<OrgMeta>
    }
    limiter?: AuthLimiter.ILimiter
    providers?: AuthProvider.IProvider<unknown, unknown, Profile>[]
    events?: AuthEvents.IBus
    session?: {
      ttlMs?: number
      absoluteTtlMs?: number
      freshnessMs?: number
    }
    identities?: {
      softDeleteGracePeriodMs?: number
      /** SEC: max serialized (JSON UTF-8) profile size, in bytes. Default 16 KiB. Set to `0` to disable. */
      profileMaxBytes?: number
    }
    passwords?: {
      /** Min length, default 8. AuthCompliance presets bump to 12+. */
      minLength?: number
      /** Max length, default 1024. SEC: caps argon2/scrypt DoS surface. */
      maxLength?: number
      rejectCommon?: boolean
      /** Pluggable hasher. Defaults to scrypt (Node built-in, zero deps). */
      hasher?: AuthHasher.IHasher
    }
    mfa?: {
      /** Brand shown in TOTP authenticator app entries. Default 'duck-auth'. */
      issuer?: string
      backupCodeCount?: number
      backupCodeLen?: number
    }
    apiKeys?: {
      prefix?: string
      randomBytes?: number
    }
    hijack?: HijackFacet.IPolicyConfig
    __tenantBrand?: Tenant
  }
}
