import type { AuthTenantContext } from './context'
import type { AuthCredential } from './credential'
import type { AuthIdentity } from './identity'
import type { AuthLimiter } from './limiter'
import type { AuthSession } from './session'
import type { AuthTransport } from './transport'

/**
 * A sign-in method. Providers are pure logic: they read stores, validate input,
 * and return Intents; the framework adapter executes the Intents against the
 * actual HTTP Request/Response. This keeps providers HTTP-free and unit-testable.
 */
export namespace AuthProvider {
  /** Cookie options surface for setCookie intents - duplicated here to avoid AuthTransport-side cycles. */
  export interface CookieOptions extends AuthTransport.CookieOptions {}

  /** Anything a provider can ask the framework adapter to do. */
  export type Intent =
    | { type: 'redirect'; url: string; status?: 302 | 303 | 307 }
    | { type: 'setCookie'; name: string; value: string; options: CookieOptions }
    | { type: 'clearCookie'; name: string; options?: CookieOptions }
    | { type: 'json'; status: number; body: unknown }
    | {
        type: 'startSession'
        identityId: string
        factors: AuthSession.Factor[]
        aal: AuthSession.AAL
      }
    | { type: 'requireMfa'; identityId: string; methods: string[] }
    | { type: 'error'; code: string; status: number; detail?: string }

  /** Crypto helpers exposed to providers (so they don't import node:crypto themselves). */
  export interface ICrypto {
    authRandomToken(bytes: number): string
    authSha256(s: string): string
    authTimingSafeEqual(a: string, b: string): boolean
  }

  /** AuthEvents surface - providers emit via the bus, never directly to console. */
  export interface IEvents {
    emit(event: string, payload: unknown): Promise<void>
  }

  export interface IContext<Profile = unknown> {
    stores: {
      identities: AuthIdentity.IStore<Profile>
      sessions: AuthSession.IStore
      credentials: AuthCredential.IStore
    }
    tenant: AuthTenantContext
    baseUrl: string
    limiter: AuthLimiter.ILimiter
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
