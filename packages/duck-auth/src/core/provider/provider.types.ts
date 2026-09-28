import type { Credential } from '~/core/credentials/credentials.types'
import type { Events } from '~/core/events/events.types'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import type { TenantContext } from '~/core/tenant/tenant.types'
import type { Transport } from '~/core/transport/transport.types'
import type { Limiter } from '~/limiters'

/** The auth-provider contract: what a provider is handed, and the intents it answers with. */
export namespace Provider {
  /** The cookie options a setCookie intent carries, duplicated here to avoid a Transport-side cycle. */
  export interface CookieOptions extends Transport.CookieOptions {}

  /** The only intents a framework adapter ever sees. `FlowsImpl` consumes and strips the internal
   *  `startSession` and `requireMfa` signals first. */
  export type Intent =
    | { type: 'redirect'; url: string; status?: 302 | 303 | 307 }
    | { type: 'setCookie'; name: string; value: string; options: CookieOptions }
    | { type: 'clearCookie'; name: string; options?: CookieOptions }
    | { type: 'json'; status: number; body: unknown }
    | { type: 'error'; code: string; status: number; detail?: string }

  /** The full union `Me.complete()` answers with. WARN: `startSession` and `requireMfa` are for
   *  `FlowsImpl` and must never reach a framework adapter. */
  export type InternalIntent =
    | Intent
    | {
        type: 'startSession'
        identityId: string
        factors: Sessions.Factor[]
        aal: Sessions.AAL
        /** `'user'` when absent. */
        kind?: Sessions.Kind
        /** Ends every other session the identity holds once this one is open. */
        endOtherSessions?: boolean
      }
    | { type: 'requireMfa'; identityId: string; methods: string[] }

  /** So a provider need not import `node:crypto` itself. */
  export type Crypto = {
    /** `bytes` random bytes, base64url. */
    authRandomToken(bytes: number): string
    /** The hex sha256 of `s`. */
    authSha256(s: string): string
    /** Compares two strings in constant time. */
    authTimingSafeEqual(a: string, b: string): boolean
  }

  /** Providers emit through the bus, never to the console. */
  export type Events = {
    /** Emits on the engine's bus. */
    emit(event: string, payload: unknown): Promise<void>
  }

  /** The facets a provider may reach, whether it reads them off a {@link Context} or was re-bound onto them. */
  export type Stores<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> = {
    identities: Identities.Store<Profile>
    sessions: Sessions.Store
    credentials: Credential.Store
  }

  /** What the engine hands a provider on every call. */
  export type Context<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> = {
    stores: Stores<Profile>
    tenant: TenantContext
    baseUrl: string
    limiter: Limiter.Me
    events: Events
    crypto: Crypto
  }

  /** A sign-in provider: `begin` starts its flow and `complete` finishes it. */
  export interface Me<
    BeginIn = unknown,
    CompleteIn = unknown,
    Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
  > {
    id: string
    /** Open string so custom providers declare their own kind without patching the type. */
    kind: string
    /** Starts the flow; answers the intents the server adapter carries out. */
    begin(ctx: Context<Profile>, input: BeginIn): Promise<Intent[]>
    /** Finishes the flow; answers the intents that open the session. */
    complete(ctx: Context<Profile>, input: CompleteIn): Promise<InternalIntent[]>
  }

  /** Anything the engine holds in its provider registry. A sign-in provider ({@link Me}) adds `begin` and
   *  `complete`; the rest carry only `id` and `kind` and are found by type through `Providers.resolve`. */
  export interface Capability {
    id: string
    kind: string
    begin?: Me['begin']
    complete?: Me['complete']
    /**
     * Re-bind a capability that captured a store or bus at construction, so it joins the caller's transaction
     * and buffers its events. It gets the facets already bound to that transaction plus the buffering bus,
     * because a facet emits as well as reads. One that reads everything off {@link Context} need not implement
     * this, since the bound engine hands it a bound context; one that captures must. Answering `null` means it
     * holds something that cannot join a transaction, and `Providers.withClient` then keeps the original.
     */
    withClient?(stores: Stores, events: Events.IBus): Capability | null
  }
}
