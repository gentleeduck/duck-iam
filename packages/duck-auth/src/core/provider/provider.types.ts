import type { Identity } from '~/core/identities/identities.types'
import type { Session } from '~/core/sessions/sessions.types'
import type { TenantContext } from '~/core/tenant/tenant.types'
import type { Credential } from '~/core/types/identity'
import type { Transport } from '~/core/types/session'
import type { Limiter } from '~/limiters'
// import type { AuthEngine } from '../engine'

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
    limiter: Limiter.Me
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
   * Anything the engine can hold in its provider registry. A sign-in
   * provider ({@link Me}) is a Capability that additionally exposes
   * `begin`/`complete`. Non-sign-in capabilities (MfaFacet, ApiKeysFacet)
   * carry only `id`/`kind` and are resolved by type via `Providers.resolve`.
   */
  export interface Capability {
    id: string
    kind: string
    begin?: Me['begin']
    complete?: Me['complete']
  }
}
