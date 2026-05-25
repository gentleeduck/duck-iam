import { randomToken, sha256, timingSafeEqual } from './crypto'
import { AuthErrorObject } from './errors'
import { InMemoryEvents } from './events'
import { DEFAULT_FLOWS_CONFIG, FlowsFacet } from './facets/flows'
import { DEFAULT_IDENTITIES_CONFIG, IdentitiesFacet } from './facets/identities'
import { DEFAULT_PASSWORDS_CONFIG, PasswordsFacet } from './facets/passwords'
import { ProvidersFacet } from './facets/providers'
import { DEFAULT_SESSION_CONFIG, resolveBySid, SessionsFacet } from './facets/sessions'
import { ScryptHasher } from './password/scrypt'
import type { Credential } from './types/credential'
import type { Events } from './types/events'
import type { Hasher } from './types/hasher'
import type { Identity } from './types/identity'
import type { Limiter, Limiter as LimiterNs } from './types/limiter'
import type { Org } from './types/org'
import type { Provider } from './types/provider'
import type { Session } from './types/session'
import type { Transport } from './types/transport'

export interface AuthRootConfig<Profile = unknown, Tenant = string, OrgMeta = unknown> {
  baseUrl: string
  transport: Transport.ITransport
  stores: {
    identities: Identity.IStore<Profile>
    sessions: Session.IStore
    credentials: Credential.IStore
    orgs?: Org.IStore<OrgMeta>
  }
  limiter?: Limiter.ILimiter
  providers?: Provider.IProvider<unknown, unknown, Profile>[]
  events?: Events.IBus
  session?: {
    ttlMs?: number
    absoluteTtlMs?: number
    freshnessMs?: number
  }
  identities?: {
    softDeleteGracePeriodMs?: number
  }
  passwords?: {
    /** Min length, default 8. Compliance presets bump to 12+. */
    minLength?: number
    rejectCommon?: boolean
    /** Pluggable hasher. Defaults to scrypt (Node built-in, zero deps). */
    hasher?: Hasher.IHasher
  }
  __tenantBrand?: Tenant
}

/**
 * Faceted authentication root. Composition surface only — every operation
 * lives on a facet (sessions, identities, providers, mfa, flows, …).
 * Facets are added one at a time as features land.
 */
export class AuthRoot<Profile = unknown, Tenant = string, OrgMeta = unknown> {
  readonly config: AuthRootConfig<Profile, Tenant, OrgMeta>
  readonly events: Events.IBus
  readonly transport: Transport.ITransport
  readonly sessions: SessionsFacet
  readonly identities: IdentitiesFacet<Profile>
  readonly passwords: PasswordsFacet
  readonly providers: ProvidersFacet<Profile>
  readonly flows: FlowsFacet<Profile>
  readonly limiter: LimiterNs.ILimiter

  constructor(config: AuthRootConfig<Profile, Tenant, OrgMeta>) {
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
    })
    this.passwords = new PasswordsFacet(config.stores.credentials, config.passwords?.hasher ?? new ScryptHasher(), {
      minLength: config.passwords?.minLength ?? DEFAULT_PASSWORDS_CONFIG.minLength,
      rejectCommon: config.passwords?.rejectCommon ?? DEFAULT_PASSWORDS_CONFIG.rejectCommon,
    })
    this.providers = new ProvidersFacet<Profile>(config.providers ?? [])
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
          randomToken: (bytes) => randomToken(bytes),
          sha256: (s) => sha256(s),
          timingSafeEqual,
        },
      }),
      DEFAULT_FLOWS_CONFIG,
    )
  }

  /**
   * Resolve the current session from the request. Returns `null` when no
   * transport token is present or the token doesn't match a live session.
   *
   * Delegates to {@link Transport.verify} when the transport can verify
   * stateless tokens (JWT); otherwise looks up via {@link Session.IStore}.
   */
  async resolveSession(req: { headers: Headers }): Promise<{
    session: Session.ISession
    identity: Identity.IIdentity<Profile> | null
  } | null> {
    const token = this.transport.extract(req)
    if (!token) return null

    if (this.transport.verify) {
      const verified = await this.transport.verify(token)
      if (verified) {
        const ctx = { ...(verified.tenantId !== undefined && { tenantId: verified.tenantId }) }
        const identity = verified.identityId
          ? await this.config.stores.identities.findById(verified.identityId, ctx)
          : null
        return { session: verified, identity }
      }
    }

    return resolveBySid(token, this.config.stores.sessions, this.config.stores.identities, {})
  }

  /**
   * Boot-time strict validation. Throws AUTH/MISCONFIGURED if a known
   * production footgun is detected.
   */
  strict(opts: { env: 'development' | 'production' | 'test' }): void {
    if (opts.env !== 'production') return
    if (!this.config.limiter) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'production: Limiter adapter required (brute-force protection)',
      })
    }
  }
}

export type {
  CreateSessionInput,
  RotateOrCreateInput,
  SessionsFacetConfig,
} from './facets/sessions'
// Re-export SessionsFacet types for consumers that want to type the facet directly.
export { SessionsFacet } from './facets/sessions'

// Used by other facets that need the hashing scheme. Kept private to the package.
export const __hashSid = sha256

/**
 * No-op limiter used when no Limiter adapter is configured. Always allows.
 * `strict({ env: 'production' })` rejects this — production must supply a real
 * Limiter (redis/upstash) for brute-force protection.
 */
export class NoopLimiter implements LimiterNs.ILimiter {
  async consume(_key: string, _weight = 1): Promise<LimiterNs.IResult> {
    return { ok: true, remaining: Number.POSITIVE_INFINITY, resetAt: Date.now() + 60_000 }
  }
  async reset(_key: string): Promise<void> {}
}
