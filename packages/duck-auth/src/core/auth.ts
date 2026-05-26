/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { randomToken, sha256, timingSafeEqual } from './crypto'
import { AuthErrorObject } from './errors'
import { InMemoryEvents } from './events'
import { ApiKeysFacet, DEFAULT_APIKEYS_CONFIG } from './facets/apikeys'
import { DEFAULT_FLOWS_CONFIG, FlowsFacet } from './facets/flows'
import { HijackFacet, type HijackPolicyConfig } from './facets/hijack'
import { DEFAULT_IDEMPOTENCY_CONFIG, IdempotencyFacet, MemoryIdempotencyStore } from './facets/idempotency'
import { DEFAULT_IDENTITIES_CONFIG, IdentitiesFacet } from './facets/identities'
import { DEFAULT_MFA_CONFIG, MfaFacet } from './facets/mfa'
import { OperationsFacet } from './facets/operations'
import { OrgsFacet } from './facets/orgs'
import { DEFAULT_PASSWORDS_CONFIG, PasswordsFacet } from './facets/passwords'
import { ProvidersFacet } from './facets/providers'
import { DEFAULT_SESSION_CONFIG, resolveBySid, SessionsFacet } from './facets/sessions'
import { ScryptHasher } from './password/scrypt'
import { type AuthPlugin, PluginRegistry } from './plugin'
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
  hijack?: HijackPolicyConfig
  __tenantBrand?: Tenant
}

/**
 * Faceted authentication root. Composition surface only - every operation
 * lives on a facet (sessions, identities, providers, mfa, flows, ...).
 * Facets are added one at a time as features land.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class AuthRoot<Profile = unknown, Tenant = string, OrgMeta = unknown> {
  readonly config: AuthRootConfig<Profile, Tenant, OrgMeta>
  readonly events: Events.IBus
  readonly transport: Transport.ITransport
  readonly sessions: SessionsFacet
  readonly identities: IdentitiesFacet<Profile>
  readonly passwords: PasswordsFacet
  readonly providers: ProvidersFacet<Profile>
  readonly mfa: MfaFacet
  readonly apiKeys: ApiKeysFacet
  readonly orgs: OrgsFacet<OrgMeta> | null
  readonly flows: FlowsFacet<Profile>
  readonly limiter: LimiterNs.ILimiter
  readonly plugins: PluginRegistry
  readonly operations: OperationsFacet
  readonly idempotency: IdempotencyFacet
  readonly hijack: HijackFacet

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
    this.mfa = new MfaFacet(config.stores.credentials, this.events, {
      issuer: config.mfa?.issuer ?? DEFAULT_MFA_CONFIG.issuer,
      backupCodeCount: config.mfa?.backupCodeCount ?? DEFAULT_MFA_CONFIG.backupCodeCount,
      backupCodeLen: config.mfa?.backupCodeLen ?? DEFAULT_MFA_CONFIG.backupCodeLen,
    })
    this.apiKeys = new ApiKeysFacet(
      config.stores.credentials,
      this.events,
      { randomToken, sha256 },
      {
        prefix: config.apiKeys?.prefix ?? DEFAULT_APIKEYS_CONFIG.prefix,
        randomBytes: config.apiKeys?.randomBytes ?? DEFAULT_APIKEYS_CONFIG.randomBytes,
      },
    )
    this.orgs = config.stores.orgs ? new OrgsFacet<OrgMeta>(config.stores.orgs, this.events) : null
    this.plugins = new PluginRegistry()
    this.operations = new OperationsFacet(this.events)
    this.idempotency = new IdempotencyFacet(new MemoryIdempotencyStore(), DEFAULT_IDEMPOTENCY_CONFIG)
    this.hijack = new HijackFacet(this.events, config.hijack ?? {})
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
      this.passwords,
      this.mfa,
      DEFAULT_FLOWS_CONFIG,
    )
  }

  /**
   * Resolve the current session from the request. Returns `null` when no
   * transport token is present or the token doesn't match a live session.
   *
   * Delegates to {@link Transport.verify} when the transport can verify
   * stateless tokens (JWT); otherwise looks up via {@link Session.IStore}.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
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

  /** Install a plugin atomically (providers + events + facets). DESIGN section 10. */
  async use(plugin: AuthPlugin<Profile, Tenant, OrgMeta>): Promise<void> {
    await this.plugins.install(this as unknown as AuthRoot, plugin as AuthPlugin)
  }

  /**
   * Boot-time strict validation. Throws `AUTH/MISCONFIGURED` if any
   * production footgun is detected. DESIGN section 11.
   *
   * Checks (production only):
   *  - Limiter wired (no NoopLimiter)
   *  - CookieTransport with secure: true
   *  - Memory adapter rejected (use redis/drizzle/prisma in prod)
   *  - At least one provider registered
   *  - When passwords provider registered, hasher must NOT be the default
   *    scrypt (compliance presets need Argon2id - emit warning in v0.1
   *    until Argon2 hasher ships; non-blocking yet)
   *  - Mailer required when magic-link / password-reset capabilities exist
   *    (caller decides based on registered providers; library can't see
   *    the channel registry from here, so this is documented for future
   *    composition with `auth.channels` facet - v0.2)
   *  - At least one `lockout` event handler subscribed
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  strict(opts: { env: 'development' | 'production' | 'test' }): void {
    if (opts.env !== 'production') return

    const errors: string[] = []

    if (!this.config.limiter) {
      errors.push('Limiter adapter required (brute-force protection)')
    }

    // Memory adapter heuristic: identifier in name.
    const adapterName = this.config.stores.identities.constructor.name
    if (adapterName === 'Object' || /Memory/i.test(adapterName)) {
      // Object shape (built by MemoryAuthAdapter) => memory adapter
      errors.push('Memory adapter rejected in production; use redis/drizzle/prisma')
    }

    // Transport secure-cookie check (only when CookieTransport used; can't
    // detect non-cookie transports here, but the cookie-secure footgun is
    // the most common).
    const transportName = this.config.transport.constructor.name
    if (transportName === 'CookieTransport') {
      const cookieTransport = this.config.transport as unknown as {
        _options: { secure?: boolean }
      }
      if (cookieTransport._options?.secure === false) {
        errors.push('CookieTransport secure=false rejected in production')
      }
    }

    if ((this.config.providers ?? []).length === 0 && this.providers.list().length === 0) {
      errors.push('no provider registered; users cannot sign in')
    }

    // `lockout` listener - required so operators are notified on brute-force lockouts.
    // The InMemoryEvents impl exposes _handlers; safer alt is a public `hasListener` API,
    // landing in v0.2. For now, soft-check via the InMemoryEvents-specific shape.
    const eventsAsInternal = this.events as unknown as {
      _handlers?: Map<string, Set<unknown>>
    }
    const lockoutHandlers = eventsAsInternal._handlers?.get('lockout')
    if (lockoutHandlers === undefined || lockoutHandlers.size === 0) {
      errors.push('no `lockout` event handler subscribed; operators must wire one (paging, audit, etc.)')
    }

    if (errors.length > 0) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: `production strict() checks failed:\n  - ${errors.join('\n  - ')}`,
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
 * `strict({ env: 'production' })` rejects this - production must supply a real
 * Limiter (redis/upstash) for brute-force protection.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class NoopLimiter implements LimiterNs.ILimiter {
  async consume(_key: string, _weight = 1): Promise<LimiterNs.IResult> {
    return { ok: true, remaining: Number.POSITIVE_INFINITY, resetAt: Date.now() + 60_000 }
  }
  async reset(_key: string): Promise<void> {}
}
