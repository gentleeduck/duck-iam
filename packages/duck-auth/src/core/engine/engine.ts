import type { Limiter } from '~/limiters'
import { MemoryLimiter } from '~/limiters/memory'
import { ApiKeysFacet } from '~/providers/api-key'
import { MfaFacet } from '~/providers/mfa'
import { PasswordsImpl } from '~/providers/passwords'
import { setDefaultActorResolver } from '../actor'
import { AnomalyFacet, DEFAULT_ANOMALY_CONFIG } from '../anomaly'
import type { Anomaly } from '../anomaly/anomaly.types'
import { type Answer, answer } from '../answer'
import { type AuthCaptcha, AuthUnconfiguredCaptchaVerifier } from '../captcha'
import type { Compliance } from '../compliance/compliance.types'
import { randomToken, sha256, timingSafeEqual } from '../crypto'
import { AuthError } from '../errors'
import { type Events, InMemoryEvents, withAuditStamping } from '../events'
import { DEFAULT_FLOWS_CONFIG, FlowsImpl } from '../flows'
import { HijackFacet } from '../hijack'
import { type IdempotencyImpl, MemoryIdempotency, resolveIdempotency } from '../idempotency'
import { DEFAULT_IDENTITIES_CONFIG, type Identities, IdentitiesImpl } from '../identities'
import { ORGS_NOT_CONFIGURED, OrgsImpl } from '../orgs'
import { PluginRegistry } from '../plugin'
import { Providers } from '../provider'
import { DEFAULT_SESSION_CONFIG, SessionsImpl } from '../sessions'
import type { Transport } from '../transport/transport.types'
import { type Bound, buildBoundEngine } from './engine.bound'
import { resolveSession } from './engine.resolve-session'
import { assertStrict } from './engine.strict'
import type { Engine } from './engine.types'

/** The authentication root: a composition surface only, since every operation lives on a facet. */
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
  readonly flows: FlowsImpl<Profile>
  readonly limiter: Limiter.Me
  /** The configured captcha verifier, or one that refuses every call. Never throws: failure is in the
   *  result, so a caller answers 400 rather than 500. */
  readonly captcha: AuthCaptcha.IVerifier
  readonly hijack: HijackFacet
  readonly anomaly: AnomalyFacet
  readonly idempotency: IdempotencyImpl
  readonly plugins: PluginRegistry<Profile, Tenant, OrgMeta>
  /** Behind the `orgs` getter: null is "no org store was configured", which the getter turns into a
   *  throw so no caller has to null-check the facet. */
  private readonly _orgs: OrgsImpl<OrgMeta> | null

  // Provider-owned capabilities live in `this.providers`; the getters below resolve them by type.
  /** Password facet. Throws `AUTH_PROVIDER_NOT_REGISTERED` when passwords() was not added. */
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

  /** Orgs facet. Throws `AUTH_PROVIDER_NOT_REGISTERED` when no org store was configured - a capability
   *  wired through `stores`, so it does not go through `_providerMissing`, whose text names a provider. */
  get orgs(): OrgsImpl<OrgMeta> {
    if (!this._orgs) throw new AuthError('AUTH_PROVIDER_NOT_REGISTERED', { detail: ORGS_NOT_CONFIGURED })
    return this._orgs
  }

  private _providerMissing(name: string): AuthError {
    return new AuthError('AUTH_PROVIDER_NOT_REGISTERED', {
      detail: `this operation needs the '${name}' provider; add ${name}Provider() to providers[]`,
    })
  }

  constructor(cfg: Engine.Cfg<Profile, Tenant, OrgMeta>) {
    this.cfg = cfg
    // Installed before any facet exists, so the very first write an engine makes
    // is already attributable. Only when the caller asked for one: passing
    // `undefined` here would clear a resolver someone set directly.
    if (cfg.resolveActor !== undefined) setDefaultActorResolver(cfg.resolveActor)
    // Wrapped once here so every facet below emits through the stamper. Operator buses
    // included, so a facet never receives `cfg.events` unwrapped.
    this.events = withAuditStamping(cfg.events ?? new InMemoryEvents())
    this.transport = cfg.transport
    this.limiter = cfg.limiter ?? new MemoryLimiter()
    // Refusing, not passing. See `Engine.Cfg.captcha`.
    this.captcha = cfg.captcha ?? new AuthUnconfiguredCaptchaVerifier()
    // Dev-only fallback: under NODE_ENV=production `MemoryIdempotency` refuses to
    // build, so a deploy that forgot to configure a shared store fails at boot.
    this.idempotency = resolveIdempotency(cfg.idempotency ?? new MemoryIdempotency())
    this.sessions = new SessionsImpl(cfg.stores.sessions, this.events, {
      ttlMs: cfg.session?.ttlMs ?? DEFAULT_SESSION_CONFIG.ttlMs,
      absoluteTtlMs: cfg.session?.absoluteTtlMs ?? DEFAULT_SESSION_CONFIG.absoluteTtlMs,
      freshnessMs: cfg.session?.freshnessMs ?? DEFAULT_SESSION_CONFIG.freshnessMs,
    })
    this.identities = new IdentitiesImpl<Profile>(
      cfg.stores.identities,
      this.events,
      {
        softDeleteGracePeriodMs:
          cfg.identities?.softDeleteGracePeriodMs ?? DEFAULT_IDENTITIES_CONFIG.softDeleteGracePeriodMs,
        profileMaxBytes: cfg.identities?.profileMaxBytes ?? DEFAULT_IDENTITIES_CONFIG.profileMaxBytes,
      },
      cfg.stores.credentials,
    )
    this.providers = new Providers<Profile>()
    for (const entry of cfg.providers ?? []) {
      if (!entry) continue
      // A thunk receives the constructed engine and the channels, so a capability can bind to stores and
      // events, as mfa and api-key do, or to channels, as magic-link and otp do.
      const cap = typeof entry === 'function' ? entry(this, cfg.channels) : entry
      if (!cap) continue
      this.providers.register(cap)
    }
    this.plugins = new PluginRegistry<Profile, Tenant, OrgMeta>()
    this._orgs = cfg.stores.orgs ? new OrgsImpl<OrgMeta>(cfg.stores.orgs, this.events) : null
    this.hijack = new HijackFacet(this.events, cfg.hijack ?? {})
    this.anomaly = new AnomalyFacet(this.events, { ...DEFAULT_ANOMALY_CONFIG, ...cfg.anomaly })
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
   * A view of this engine whose stores run on `client`, a driver transaction handle, and whose events
   * buffer into `pending` rather than publishing at once. The client is opaque, handed straight to each
   * store's `withClient`. Throws `AUTH_MISCONFIGURED` naming a store that cannot join a transaction.
   */
  withTransaction(client: unknown): Bound.AuthEngine<Profile, OrgMeta> {
    return buildBoundEngine<Profile, OrgMeta>({
      client,
      events: this.events,
      identitiesCfg: {
        softDeleteGracePeriodMs:
          this.cfg.identities?.softDeleteGracePeriodMs ?? DEFAULT_IDENTITIES_CONFIG.softDeleteGracePeriodMs,
        profileMaxBytes: this.cfg.identities?.profileMaxBytes ?? DEFAULT_IDENTITIES_CONFIG.profileMaxBytes,
      },
      sessionsCfg: {
        ttlMs: this.cfg.session?.ttlMs ?? DEFAULT_SESSION_CONFIG.ttlMs,
        absoluteTtlMs: this.cfg.session?.absoluteTtlMs ?? DEFAULT_SESSION_CONFIG.absoluteTtlMs,
        freshnessMs: this.cfg.session?.freshnessMs ?? DEFAULT_SESSION_CONFIG.freshnessMs,
      },
      stores: this.cfg.stores,
      buildProviders: (bus, stores) => this.providers.withClient(stores, bus),
      buildFlows: ({ sessions, identities, providers, events, stores }) =>
        new FlowsImpl<Profile>(
          sessions,
          identities,
          providers,
          this.transport,
          events,
          (tenantId) => ({
            stores,
            tenant: tenantId !== undefined ? { tenantId } : {},
            baseUrl: this.cfg.baseUrl,
            // Deliberately the engine's own limiter: a rate-limit decision is a layer-2 guard and has to
            // survive a rollback, or a failed transaction refunds an attacker's attempts.
            limiter: this.limiter,
            events,
            crypto: {
              authRandomToken: (bytes) => randomToken(bytes),
              authSha256: (s) => sha256(s),
              authTimingSafeEqual: timingSafeEqual,
            },
          }),
          () => providers.resolve(PasswordsImpl) ?? this.passwords,
          () => providers.resolve(MfaFacet) ?? this.mfa,
          DEFAULT_FLOWS_CONFIG,
        ),
    })
  }

  /** The current session, verified statelessly where the transport can and otherwise read from
   *  `Sessions.Store`. Rejects `AUTH_SESSION_REVOKED` where the request carries no token or it matches no
   *  live session, which `orNull()` reads back as null - and `AUTH_SESSION_IDENTITY_ERASED`, which it does
   *  not, so a session outliving its identity stays loud however this is read. */
  resolveSession(
    req: { headers: Headers },
    opts: {
      expectedTenantId?: string
      requestSnapshot?: Anomaly.RequestSnapshot
    } = {},
  ): Answer.Me<Engine.ResolveResult<Profile>> {
    return answer(resolveSession(this, req, opts))
  }

  /** Install a plugin: its event handlers, its facet under `plugins.facets[id]`, its `install` hook,
   *  then its providers. All of it or none of it - providers go last because registering one cannot be
   *  undone, so nothing that can throw may follow. */
  async use(plugin: PluginRegistry.Plugin<Profile, Tenant, OrgMeta>): Promise<this> {
    await this.plugins.install(this, plugin)
    return this
  }

  /** Boot-time strict validation; throws `AUTH_MISCONFIGURED` on any production footgun. */
  strict(opts: { env: 'development' | 'production' | 'test'; compliance?: Partial<Compliance.Wired> }): void {
    assertStrict(this, opts)
  }
}

/** Constructs an {@link AuthEngine}. */
export function authEngine<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  Tenant = string,
  OrgMeta = unknown,
>(cfg: Engine.Cfg<Profile, Tenant, OrgMeta>): AuthEngine<Profile, Tenant, OrgMeta> {
  return new AuthEngine<Profile, Tenant, OrgMeta>(cfg)
}
