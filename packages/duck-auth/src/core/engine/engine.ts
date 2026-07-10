import type { Limiter } from '~/limiters'
import { MemoryLimiter } from '~/limiters/memory'
import { ApiKeysFacet } from '~/providers/api-key'
import { MfaFacet } from '~/providers/mfa'
import { PasswordsImpl } from '~/providers/passwords'
import { AnomalyFacet, DEFAULT_ANOMALY_CONFIG } from '../anomaly'
import type { Anomaly } from '../anomaly/anomaly.types'
import { randomToken, sha256, timingSafeEqual } from '../crypto'
import { AuthError } from '../errors'
import { type Events, InMemoryEvents } from '../events'
import { DEFAULT_FLOWS_CONFIG, FlowsImpl } from '../flows'
import { HijackFacet } from '../hijack'
import { IdempotencyImpl, MemoryIdempotency } from '../idempotency'
import { DEFAULT_IDENTITIES_CONFIG, type Identities, IdentitiesImpl } from '../identities'
import { OrgsImpl } from '../orgs'
import { Providers } from '../provider'
import type { Sessions } from '../sessions'
import { DEFAULT_SESSION_CONFIG, SessionsImpl } from '../sessions'
import type { Transport } from '../transport/transport.types'
import { resolveSession } from './engine.resolve-session'
import { assertStrict } from './engine.strict'
import type { Engine } from './engine.types'

/**
 * Faceted authentication root. Composition surface only - every operation
 * lives on a facet (sessions, identities, providers, mfa, flows, ...).
 * Facets are added one at a time as features land.
 */
export class AuthEngine<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
> {
  readonly cfg: Engine.Cfg<Profile, Tenant, OrgMeta>
  readonly events: Events.IBus
  readonly transport: Transport.ITransport
  readonly sessions: SessionsImpl
  readonly identities: IdentitiesImpl<Profile>
  readonly providers: Providers<Profile>
  readonly orgs: OrgsImpl<OrgMeta> | null
  readonly flows: FlowsImpl<Profile>
  readonly limiter: Limiter.Me
  readonly hijack: HijackFacet
  readonly anomaly: AnomalyFacet
  readonly idempotency: IdempotencyImpl

  // Provider-owned capabilities live in `this.providers`; the getters below
  // resolve them by type and fail loud (AUTH_PROVIDER_NOT_REGISTERED) when the
  // owning provider was never added to `providers`.
  get passwords(): PasswordsImpl {
    const p = this.providers.resolve(PasswordsImpl)
    if (!p) throw this._providerMissing('password')
    return p
  }

  /** MFA facet. Throws `AUTH_PROVIDER_NOT_REGISTERED` when mfaProvider() was not added. */
  get mfa(): MfaFacet {
    const f = this.providers.resolve(MfaFacet)
    if (!f) throw this._providerMissing('mfa')
    return f
  }

  /** API-key facet. Throws `AUTH_PROVIDER_NOT_REGISTERED` when apiKeyProvider() was not added. */
  get apiKeys(): ApiKeysFacet {
    const f = this.providers.resolve(ApiKeysFacet)
    if (!f) throw this._providerMissing('api-key')
    return f
  }

  private _providerMissing(name: string): AuthError {
    return new AuthError('AUTH_PROVIDER_NOT_REGISTERED', {
      detail: `this operation needs the '${name}' provider; add ${name}Provider() to providers[]`,
    })
  }

  constructor(cfg: Engine.Cfg<Profile, Tenant, OrgMeta>) {
    this.cfg = cfg
    this.events = cfg.events ?? new InMemoryEvents()
    this.transport = cfg.transport
    this.limiter = cfg.limiter ?? new MemoryLimiter()
    this.idempotency = cfg.idempotency ?? new IdempotencyImpl(new MemoryIdempotency())
    this.sessions = new SessionsImpl(cfg.stores.sessions, this.events, {
      ttlMs: cfg.session?.ttlMs ?? DEFAULT_SESSION_CONFIG.ttlMs,
      absoluteTtlMs: cfg.session?.absoluteTtlMs ?? DEFAULT_SESSION_CONFIG.absoluteTtlMs,
      freshnessMs: cfg.session?.freshnessMs ?? DEFAULT_SESSION_CONFIG.freshnessMs,
    })
    this.identities = new IdentitiesImpl<Profile>(cfg.stores.identities, this.events, {
      softDeleteGracePeriodMs:
        cfg.identities?.softDeleteGracePeriodMs ?? DEFAULT_IDENTITIES_CONFIG.softDeleteGracePeriodMs,
      profileMaxBytes: cfg.identities?.profileMaxBytes ?? DEFAULT_IDENTITIES_CONFIG.profileMaxBytes,
    })
    this.providers = new Providers<Profile>()
    for (const entry of cfg.providers ?? []) {
      if (!entry) continue
      // Thunks receive the constructed engine + channels so capabilities can
      // bind to stores/events (mfa, api-key) or channels (magic-link, otp).
      const cap = typeof entry === 'function' ? entry(this, cfg.channels) : entry
      if (!cap) continue
      this.providers.register(cap)
    }
    this.orgs = cfg.stores.orgs ? new OrgsImpl<OrgMeta>(cfg.stores.orgs, this.events) : null
    this.hijack = new HijackFacet(this.events, cfg.hijack ?? {})
    this.anomaly = new AnomalyFacet(this.events, DEFAULT_ANOMALY_CONFIG)
    this.flows = new FlowsImpl<Profile>(
      this.sessions,
      this.identities,
      this.providers,
      this.transport,
      this.events,
      (tenantId) => ({
        stores: cfg.stores,
        tenant: tenantId !== undefined ? { tenantId } : {},
        baseUrl: cfg.baseUrl,
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
   * stateless tokens (JWT); otherwise looks up via {@link Sessions.Store}.
   */
  async resolveSession(
    req: { headers: Headers },
    opts: {
      expectedTenantId?: string
      requestSnapshot?: Anomaly.RequestSnapshot
    } = {},
  ): Promise<{
    session: Sessions.Me
    identity: Identities.Me<Profile> | null
    /**
     * Aggregate anomaly decision when at least one detector is
     * registered AND `opts.requestSnapshot` was supplied. Operators
     * branch on `anomaly.decision === 'deny'` / `'step-up'` /
     * `'allow'`; the field is absent when no detectors run.
     */
    anomaly?: Anomaly.Result
  } | null> {
    return resolveSession(this, req, opts)
  }

  /** Boot-time strict validation; throws `AUTH/MISCONFIGURED` on any production footgun. */
  strict(opts: { env: 'development' | 'production' | 'test' }): void {
    assertStrict(this, opts)
  }
}
