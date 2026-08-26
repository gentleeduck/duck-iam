/** Vanilla client types: config plus the public `VanillaClient` namespace. */

import type { Envelope } from '~/core/errors/errors.types'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'

export namespace VanillaClient {
  /** Client configuration. */
  export type Cfg = {
    /** Mount point on the server. Default `/auth`. */
    baseUrl?: string
    /** Override the fetch impl (test stubs, retry wrappers, etc.). */
    fetch?: typeof globalThis.fetch
    /** Override how subscribed observers are notified. Default: synchronous. */
    notifyImmediately?: boolean
    /** Optional headers to merge into every request (e.g. tenant header). */
    headers?: Record<string, string>
    /** Cookie carrying the plaintext CSRF token. Default `__Host-duck-csrf`. */
    csrfCookieName?: string
    /** Header the token is echoed on. Default `x-csrf-token`. */
    csrfHeaderName?: string
  }

  export type SignInOptions = {
    providerId: string
    input: unknown
    /** Override the route path under baseUrl. Default `/signin`. */
    path?: string
  }

  export type SessionResult<Profile extends Identities.ProfileMetadataBase> = {
    session: Sessions.Me | null
    identity: Identities.Me<Profile> | null
  }

  export type SignUpOptions = {
    /** Override the route path under baseUrl. Default `/signup`. */
    path?: string
  }

  /** The framework-free client surface. */
  export type Client<Profile extends Identities.ProfileMetadataBase> = {
    /** POST /AUTH/signin → resolves to the resulting session envelope. */
    signIn(opts: VanillaClient.SignInOptions): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
    /**
     * POST /AUTH/signup. Registration is app-shaped (the profile fields are
     * yours), so `input` is opaque and the response `data` is echoed back. Does
     * not create a session, follow with `signIn` if desired.
     */
    signUp(input: unknown, opts?: VanillaClient.SignUpOptions): Promise<Envelope<unknown, string>>
    /** POST /AUTH/signout */
    signOut(): Promise<Envelope<Record<string, never>, string>>
    /** GET /AUTH/session */
    getSession(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
    /** POST /AUTH/providers/:id/begin */
    beginProvider(id: string, input?: unknown): Promise<Envelope<unknown, string>>
    /** Observe session changes. Returned function unsubscribes. */
    onChange(handler: (state: VanillaClient.SessionResult<Profile>) => void): () => void
    /** Force a session refetch + notify observers. */
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }
}
