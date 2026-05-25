import { sha256 } from './crypto'
import { AuthErrorObject } from './errors'
import { InMemoryEvents } from './events'
import type { Credential } from './types/credential'
import type { Events } from './types/events'
import type { Identity } from './types/identity'
import type { Limiter } from './types/limiter'
import type { Org } from './types/org'
import type { Provider } from './types/provider'
import type { Session } from './types/session'
import type { Transport } from './types/transport'

/**
 * AuthRoot configuration. Strongly typed via `Profile`, `Tenant`, `Org` generics
 * so consumers get `session.identity.profile.email` end-to-end without `as` casts.
 *
 * DESIGN §2 — generics flow through bridge + client SDK.
 */
export interface AuthRootConfig<Profile = unknown, Tenant = string, Org = string> {
  baseUrl: string
  transport: Transport.ITransport
  stores: {
    identities: Identity.IStore<Profile>
    sessions: Session.IStore
    credentials: Credential.IStore
    orgs?: Org.IStore<Org>
  }
  limiter?: Limiter.ILimiter
  providers?: Provider.IProvider<unknown, unknown, Profile>[]
  events?: Events.IBus
  session?: {
    /** Sliding TTL in ms. Default 7 days. */
    ttlMs?: number
    /** Absolute hard cap. Default 30 days. */
    absoluteTtlMs?: number
    /** Freshness window — recent factors count as "fresh" within this window. Default 5 min. */
    freshnessMs?: number
    /** L1 cache for sessions.resolve() — DESIGN §P1. */
    cacheL1?: boolean
  }
  /** Marker placeholder for the generic Tenant. Resolved per-request via AsyncLocalStorage. */
  __tenantBrand?: Tenant
}

/**
 * Faceted authentication root. Wires facets only; every operation lives on a facet.
 * DESIGN §3.
 *
 * @example
 * ```ts
 * import { AuthRoot, CookieTransport, MemoryAuthAdapter } from '@gentleduck/auth/core'
 *
 * const auth = new AuthRoot({
 *   baseUrl: 'https://app.example.com',
 *   transport: new CookieTransport({ secure: true }),
 *   stores: new MemoryAuthAdapter(),
 * })
 * ```
 */
export class AuthRoot<Profile = unknown, Tenant = string, Org = string> {
  readonly config: AuthRootConfig<Profile, Tenant, Org>
  readonly events: Events.IBus
  readonly transport: Transport.ITransport

  constructor(config: AuthRootConfig<Profile, Tenant, Org>) {
    this.config = config
    this.events = config.events ?? new InMemoryEvents()
    this.transport = config.transport
    if (!config.providers || config.providers.length === 0) {
      // Not fatal — apps can register providers later via plugins.
    }
  }

  /**
   * Resolve the current session from the request. Returns `null` when no
   * transport token is present or the token doesn't match a live session.
   *
   * DESIGN §7 — caller-side hook into framework adapters; the iam-auth-bridge
   * wraps this with `withSession()` for lazy iam subject resolution.
   */
  async resolveSession(req: { headers: Headers }): Promise<{
    session: Session.ISession
    identity: Identity.IIdentity<Profile> | null
  } | null> {
    const token = this.transport.extract(req)
    if (!token) return null

    // Transport-verifiable (JWT) short-circuit; opaque transports fall through.
    const verified = await this.transport.verify?.(token)
    if (verified) {
      const identity = verified.identityId
        ? await this.config.stores.identities.findById(verified.identityId, {
            tenantId: verified.tenantId,
          })
        : null
      return { session: verified, identity }
    }

    const sidHash = sha256(token)
    const session = await this.config.stores.sessions.getByHash(sidHash)
    if (!session) return null
    if (session.expiresAt < Date.now()) {
      await this.config.stores.sessions.delete(session.id)
      return null
    }
    const identity = session.identityId
      ? await this.config.stores.identities.findById(session.identityId, {
          tenantId: session.tenantId,
        })
      : null
    return { session, identity }
  }

  /**
   * Boot-time strict validation. DESIGN §11. Throws AUTH/MISCONFIGURED if any
   * production footgun is detected.
   */
  strict(opts: { env: 'development' | 'production' | 'test' }): void {
    if (opts.env !== 'production') return
    if (!this.config.limiter) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'production: Limiter adapter required (brute-force protection)',
      })
    }
    // Additional production checks land here as facets fill in (memory-adapter
    // detection, JWT key-count, mailer presence, etc.). DESIGN §11.
  }
}
