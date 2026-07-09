import type { ApiKeysFacet } from '~/providers/api-key/api-key.facet'
import type { MfaFacet } from '~/providers/mfa/mfa.facet'
import type { PasswordsFacet } from '~/providers/password/password.facet'
import { randomToken, sha256, timingSafeEqual } from '../crypto'
import { AuthError } from '../errors'
import { InMemoryEvents } from '../events'
import { AnomalyFacet, DEFAULT_ANOMALY_CONFIG } from '../facets/anomaly.facet'
import { DEFAULT_FLOWS_CONFIG, FlowsFacet } from '../facets/flows.facet'
import { HijackFacet } from '../facets/hijack.facet'
import { DEFAULT_IDEMPOTENCY_CONFIG, IdempotencyFacet, MemoryIdempotencyStore } from '../facets/idempotency.facet'
import { DEFAULT_IDENTITIES_CONFIG, IdentitiesFacet } from '../facets/identities.facet'
import { OperationsFacet } from '../facets/operations.facet'
import { OrgsFacet } from '../facets/orgs.facet'
import { ProvidersFacet } from '../facets/providers.facet'
import { PluginRegistry } from '../plugin'
import { DEFAULT_SESSION_CONFIG } from '../sessions/sessions.constants'
import { resolveBySid, SessionsFacet } from '../sessions/sessions.facet'
import type { Identity } from '../types/identity'
import type { Limiter as LimiterNs } from '../types/infra'
import type { Events, Provider } from '../types/provider'
import type { Session, Transport } from '../types/session'
import type { Engine } from './engine.types'

/**
 * Faceted authentication root. Composition surface only - every operation
 * lives on a facet (sessions, identities, providers, mfa, flows, ...).
 * Facets are added one at a time as features land.
 */
export class AuthEngine<
  Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
> {
  readonly config: Engine.Config<Profile, Tenant, OrgMeta>
  readonly events: Events.IBus
  readonly transport: Transport.ITransport
  readonly sessions: SessionsFacet
  readonly identities: IdentitiesFacet<Profile>
  readonly providers: ProvidersFacet<Profile>
  readonly orgs: OrgsFacet<OrgMeta> | null
  // Provider-owned facets. Mounted by their provider module's `attach` (mechanism A);
  // accessed through the throwing getters below, which fail loud when the owning
  // provider was never registered. Private + `T | null` keeps null explicit and cast-free.
  private _passwords: PasswordsFacet | null = null
  private _mfa: MfaFacet | null = null
  private _apiKeys: ApiKeysFacet | null = null

  /** Password facet. Throws `AUTH_PROVIDER_NOT_REGISTERED` when the password provider is absent. */
  get passwords(): PasswordsFacet {
    if (!this._passwords) throw this._providerMissing('password')
    return this._passwords
  }
  /** MFA facet. Throws `AUTH_PROVIDER_NOT_REGISTERED` when the mfa provider is absent. */
  get mfa(): MfaFacet {
    if (!this._mfa) throw this._providerMissing('mfa')
    return this._mfa
  }
  /** API-key facet. Throws `AUTH_PROVIDER_NOT_REGISTERED` when the api-key provider is absent. */
  get apiKeys(): ApiKeysFacet {
    if (!this._apiKeys) throw this._providerMissing('api-key')
    return this._apiKeys
  }
  /** Presence probe for strict()/introspection that must not throw. */
  get passwordsOrNull(): PasswordsFacet | null {
    return this._passwords
  }

  private _providerMissing(name: string): AuthError {
    return new AuthError('AUTH_PROVIDER_NOT_REGISTERED', {
      detail: `this operation needs the '${name}' provider; add ${name}Provider() to providers[]`,
    })
  }

  /** @internal — mounts the password facet; called by `passwordProvider().attach`. */
  setPasswords(facet: PasswordsFacet): void {
    if (this._passwords) throw new AuthError('AUTH_MISCONFIGURED', { detail: "provider 'password' registered twice" })
    this._passwords = facet
  }
  /** @internal — mounts the mfa facet; called by `mfaProvider().attach`. */
  setMfa(facet: MfaFacet): void {
    if (this._mfa) throw new AuthError('AUTH_MISCONFIGURED', { detail: "provider 'mfa' registered twice" })
    this._mfa = facet
  }
  /** @internal — mounts the api-key facet; called by `apiKeyProvider().attach`. */
  setApiKeys(facet: ApiKeysFacet): void {
    if (this._apiKeys) throw new AuthError('AUTH_MISCONFIGURED', { detail: "provider 'api-key' registered twice" })
    this._apiKeys = facet
  }
  readonly flows: FlowsFacet<Profile>
  readonly limiter: LimiterNs.Limiter
  readonly plugins: PluginRegistry<Profile, Tenant, OrgMeta>
  readonly operations: OperationsFacet
  readonly idempotency: IdempotencyFacet
  readonly hijack: HijackFacet
  readonly anomaly: AnomalyFacet

  constructor(config: Engine.Config<Profile, Tenant, OrgMeta>) {
    this.config = config
    this.events = config.events ?? new InMemoryEvents()
    this.transport = config.transport
    this.limiter = config.limiter ?? new NoopLimiter()
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
    this.providers = new ProvidersFacet<Profile>([])
    // Mechanism-A registration: normalize bare providers to modules, register any
    // sign-in provider, run any attach hook. Runs after core facets so `attach`
    // can read stores/events off the engine.
    const seen = new Set<string>()
    for (const entry of config.providers ?? []) {
      const mod: Provider.ProviderModule<Profile, Tenant, OrgMeta> = isProviderModule(entry)
        ? entry
        : { name: entry.id, provider: entry }
      if (seen.has(mod.name)) {
        throw new AuthError('AUTH_MISCONFIGURED', { detail: `provider '${mod.name}' registered twice` })
      }
      seen.add(mod.name)
      if (mod.provider) this.providers.register(mod.provider)
      mod.attach?.(this)
    }
    this.orgs = config.stores.orgs ? new OrgsFacet<OrgMeta>(config.stores.orgs, this.events) : null
    this.plugins = new PluginRegistry<Profile, Tenant, OrgMeta>()
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
          authRandomToken: (bytes) => randomToken(bytes),
          authSha256: (s) => sha256(s),
          authTimingSafeEqual: timingSafeEqual,
        },
      }),
      () => this.passwords,
      () => this.mfa,
      DEFAULT_FLOWS_CONFIG,
    )
  }

  /**
   * Resolve the current session from the request. Returns `null` when no
   * transport token is present or the token doesn't match a live session.
   *
   * Delegates to {@link Transport.verify} when the transport can verify
   * stateless tokens (JWT); otherwise looks up via {@link Session.Store}.
   */
  async resolveSession(
    req: { headers: Headers },
    opts: { expectedTenantId?: string; requestSnapshot?: import('../types/provider').Anomaly.RequestSnapshot } = {},
  ): Promise<{
    session: Session.Me
    identity: Identity.Me<Profile> | null
    /**
     * Aggregate anomaly decision when at least one detector is
     * registered AND `opts.requestSnapshot` was supplied. Operators
     * branch on `anomaly.decision === 'deny'` / `'step-up'` /
     * `'allow'`; the field is absent when no detectors run.
     */
    anomaly?: import('../facets/anomaly.facet').AnomalyFacet.Result
  } | null> {
    const token = this.transport.extract(req)
    if (!token) return null

    const finalize = async (
      session: Session.Me,
      identity: Identity.Me<Profile> | null,
    ): Promise<{
      session: Session.Me
      identity: Identity.Me<Profile> | null
      anomaly?: import('../facets/anomaly.facet').AnomalyFacet.Result
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
        const ctx = verified.tenantId ? { tenantId: verified.tenantId } : {}
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
  async use(plugin: PluginRegistry.Plugin<Profile, Tenant, OrgMeta>): Promise<void> {
    await this.plugins.install(this, plugin)
  }

  /** Boot-time strict validation; throws `AUTH/MISCONFIGURED` on any production footgun. */
  strict(opts: { env: 'development' | 'production' | 'test' }): void {
    if (opts.env !== 'production') return

    const errors: string[] = []

    // Reject AuthNoopLimiter via class brand (bundlers rename constructors).
    if (!this.config.limiter || (this.limiter as { __isNoopLimiter?: boolean }).__isNoopLimiter === true) {
      errors.push('Limiter adapter required (brute-force protection); AuthNoopLimiter rejected in production')
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

    // Transport secure-cookie check via the public `secure` getter so
    // we never reach into private state.
    const maybeSecureGetter = (this.config.transport as { secure?: boolean }).secure
    if (typeof maybeSecureGetter === 'boolean' && maybeSecureGetter === false) {
      errors.push('AuthCookieTransport secure=false rejected in production')
    }

    // baseUrl must use HTTPS in production so oauth callback URLs, magic-link
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
    // (we cannot enforce against a foreign Events.IBus impl).
    const listenerCount = (this.events as { listenerCount?: (event: string) => number }).listenerCount
    if (typeof listenerCount === 'function' && listenerCount.call(this.events, 'lockout') === 0) {
      errors.push('no `lockout` event handler subscribed; operators must wire one (paging, audit, etc.)')
    }

    if (errors.length > 0) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: `production strict() checks failed:\n  - ${errors.join('\n  - ')}`,
      })
    }
  }
}

/**
 * Distinguishes a capability module from a bare sign-in provider in `config.providers`.
 * A module carries a `name`; a `Provider.Me` carries `id`/`kind` and never `name`.
 */
function isProviderModule<Profile extends Identity.ProfileMetadataBase, Tenant, OrgMeta>(
  entry: Provider.Me<unknown, unknown, Profile> | Provider.ProviderModule<Profile, Tenant, OrgMeta>,
): entry is Provider.ProviderModule<Profile, Tenant, OrgMeta> {
  return 'name' in entry
}

// Re-export SessionsFacet for consumers that want to type the facet directly.
export { SessionsFacet } from '../sessions/sessions.facet'

// Used by other facets that need the hashing scheme. Kept private to the package.
export const __hashSid = sha256

/**
 * No-op limiter used when no Limiter adapter is configured. Always allows.
 * `strict({ env: 'production' })` rejects this - production must supply a real
 * Limiter (redis/upstash) for brute-force protection.
 */
export class NoopLimiter implements LimiterNs.Limiter {
  /** Brand consumed by `AuthEngine.strict({ env: 'production' })` to
   * detect "explicit AuthNoopLimiter" - class-identity comparison breaks
   * across bundler rewrites (treeshaken duplicates / nested workspaces)
   * so we tag every instance and check the tag instead. */
  readonly __isNoopLimiter = true as const
  async consume(_key: string, _weight = 1): Promise<LimiterNs.Result> {
    return { ok: true, remaining: Number.POSITIVE_INFINITY, resetAt: new Date(Date.now() + 60_000) }
  }
  async reset(_key: string): Promise<void> {}
}
