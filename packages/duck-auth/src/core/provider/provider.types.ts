import type { Identity } from '~/core/identities/identities.types'
import type { Session } from '~/core/sessions/sessions.types'
import type { Credential } from '~/core/types/identity'
import type { Limiter, TenantContext } from '~/core/types/infra'
import type { Transport } from '~/core/types/session'

export namespace Provider {
  /** Cookie options surface for setCookie intents - duplicated here to avoid Transport-side cycles. */
  export interface CookieOptions extends Transport.CookieOptions {}

  /**
   * Adapter-safe intents: these are the only intents framework adapters
   * (NestJS, Express, Fastify, …) ever see. FlowsFacet consumes and strips
   * the internal `startSession` / `requireMfa` signals before returning.
   */
  export type Intent =
    | { type: 'redirect'; url: string; status?: 302 | 303 | 307 }
    | { type: 'setCookie'; name: string; value: string; options: CookieOptions }
    | { type: 'clearCookie'; name: string; options?: CookieOptions }
    | { type: 'json'; status: number; body: unknown }
    | { type: 'error'; code: string; status: number; detail?: string }

  /**
   * Full internal intent union returned by `IProvider.complete()`.
   * `startSession` and `requireMfa` are consumed by FlowsFacet; they
   * must never be forwarded to a framework adapter.
   */
  export type InternalIntent =
    | Intent
    | {
        type: 'startSession'
        identityId: string
        factors: Session.Factor[]
        aal: Session.AAL
      }
    | { type: 'requireMfa'; identityId: string; methods: string[] }

  /** Crypto helpers exposed to providers (so they don't import node:crypto themselves). */
  export type Crypto = {
    authRandomToken(bytes: number): string
    authSha256(s: string): string
    authTimingSafeEqual(a: string, b: string): boolean
  }

  /** Events surface - providers emit via the bus, never directly to console. */
  export type Events = {
    emit(event: string, payload: unknown): Promise<void>
  }

  export type Context<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase> = {
    stores: {
      identities: Identity.Store<Profile>
      sessions: Session.Store
      credentials: Credential.Store
    }
    tenant: TenantContext
    baseUrl: string
    limiter: Limiter.Limiter
    events: Events
    crypto: Crypto
  }

  export interface Me<
    BeginIn = unknown,
    CompleteIn = unknown,
    Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
  > {
    id: string
    /** Open string so custom providers declare their own kind without patching the type. */
    kind: string
    begin(ctx: Context<Profile>, input: BeginIn): Promise<Intent[]>
    complete(ctx: Context<Profile>, input: CompleteIn): Promise<InternalIntent[]>
  }

  /**
   * A capability module (mechanism A). Carries an optional sign-in provider
   * plus an `attach` hook that builds and mounts the capability's facet onto
   * the engine. Built by `passwordProvider()`, `mfaProvider()`, etc. Passing a
   * bare {@link Me} to `config.providers` is still accepted; the engine
   * normalizes it to `{ name: p.id, provider: p }`.
   */
  export interface ProviderModule<
    Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
    Tenant = string,
    OrgMeta = unknown,
  > {
    /** Stable capability name; the engine rejects a second module with the same name. */
    name: string
    /** Optional sign-in provider registered into ProvidersFacet at attach time. */
    provider?: Me<unknown, unknown, Profile>
    /** Builds this capability's facet from engine core + own config, then mounts it. */
    attach?(engine: import('../engine/engine').AuthEngine<Profile, Tenant, OrgMeta>): void
  }
}
