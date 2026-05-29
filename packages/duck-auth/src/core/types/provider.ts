import type { TenantContext } from './context'
import type { Credential } from './credential'
import type { Identity } from './identity'
import type { Limiter } from './limiter'
import type { Session } from './session'
import type { Transport } from './transport'

/**
 * A sign-in method. Providers are pure logic: they read stores, validate input,
 * and return Intents; the framework adapter executes the Intents against the
 * actual HTTP Request/Response. This keeps providers HTTP-free and unit-testable.
 */
export namespace Provider {
  /** Cookie options surface for setCookie intents - duplicated here to avoid Transport-side cycles. */
  export interface CookieOptions extends Transport.CookieOptions {}

  /** Anything a provider can ask the framework adapter to do. */
  export type Intent =
    | { type: 'redirect'; url: string; status?: 302 | 303 | 307 }
    | { type: 'setCookie'; name: string; value: string; options: CookieOptions }
    | { type: 'clearCookie'; name: string; options?: CookieOptions }
    | { type: 'json'; status: number; body: unknown }
    | {
        type: 'startSession'
        identityId: string
        factors: Session.Factor[]
        aal: Session.AAL
      }
    | { type: 'requireMfa'; identityId: string; methods: string[] }
    | { type: 'error'; code: string; status: number; detail?: string }

  /** Crypto helpers exposed to providers (so they don't import node:crypto themselves). */
  export interface ICrypto {
    randomToken(bytes: number): string
    sha256(s: string): string
    timingSafeEqual(a: string, b: string): boolean
  }

  /** Events surface - providers emit via the bus, never directly to console. */
  export interface IEvents {
    emit(event: string, payload: unknown): Promise<void>
  }

  export interface IContext<Profile = unknown> {
    stores: {
      identities: Identity.IStore<Profile>
      sessions: Session.IStore
      credentials: Credential.IStore
    }
    tenant: TenantContext
    baseUrl: string
    limiter: Limiter.ILimiter
    events: IEvents
    crypto: ICrypto
  }

  export interface IProvider<BeginIn = unknown, CompleteIn = unknown, Profile = unknown> {
    id: string
    kind: 'password' | 'passkey' | 'oauth' | 'magic-link' | 'api-key'
    begin(ctx: IContext<Profile>, input: BeginIn): Promise<Intent[]>
    complete(ctx: IContext<Profile>, input: CompleteIn): Promise<Intent[]>
  }
}
