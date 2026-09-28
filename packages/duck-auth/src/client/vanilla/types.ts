/** Vanilla client types: config plus the public `VanillaClient` namespace. */

import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'

/**
 * What every client method answers with. The failure arm is `AuthError.toJSON()` as the server wrote
 * it - the code, the status, and whatever meta that code carries - plus `cause`, which the client
 * fills in for a failure that never reached the server.
 */
export type Envelope<T, C extends string = string> =
  | { ok: true; code: C; data: T }
  | { ok: false; error: { code: C; status?: number; cause?: unknown } & Record<string, unknown> }

/** Client configuration and the wire shapes the server answers with. */
export namespace VanillaClient {
  /** Client configuration. */
  export type Cfg = {
    /** Mount point on the server. Default `/auth`. */
    baseUrl?: string
    /** Override the fetch impl (test stubs, retry wrappers, etc.). */
    fetch?: typeof globalThis.fetch
    /** Whether `onChange` replays the current state on subscribe. Default: yes, once there is one to
     *  replay - before the first read the client holds no state and notifies nothing. */
    notifyImmediately?: boolean
    /** Optional headers to merge into every request (e.g. tenant header). */
    headers?: Record<string, string>
    /** Cookie carrying the plaintext CSRF token. Default `__Host-duck-csrf`. */
    csrfCookieName?: string
    /** Header the token is echoed on. Default `x-csrf-token`. */
    csrfHeaderName?: string
  }

  /** What `signIn` posts. */
  export type SignInOptions = {
    /** The provider to sign in with. */
    providerId: string
    /** What that provider's `complete` takes. */
    input: unknown
    /** Override the route path under baseUrl. Default `/signin`. */
    path?: string
  }

  /**
   * A row type as it arrives over HTTP: `JSON.stringify` has already flattened every `Date` to an
   * ISO string. `Serialized<T>` is not assignable to `T`, so the only route to the row type is
   * `./revive`, which a plain cast at the fetch boundary would slip past.
   */
  export type Serialized<T> = T extends Date
    ? string
    : T extends readonly (infer Element)[]
      ? Serialized<Element>[]
      : T extends object
        ? { [K in keyof T]: Serialized<T[K]> }
        : T

  /** `profile` is exempt: it is the consumer's own shape, and `./revive` does not walk it. */
  export type SerializedIdentity<Profile extends Identities.ProfileMetadataBase> = Omit<
    Serialized<Identities.Me>,
    'profile'
  > & { profile: Profile }

  /** What `GET /session` puts on the wire; {@link SessionResult} is what a caller gets after revival. */
  export type SerializedSessionResult<Profile extends Identities.ProfileMetadataBase> = {
    /** The session, dates as ISO strings. */
    session: Serialized<Sessions.Public> | null
    /** Who it belongs to, dates as ISO strings. */
    identity: SerializedIdentity<Profile> | null
  }

  /** The session and identity `/session` answers; both null for a guest. */
  export type SessionResult<Profile extends Identities.ProfileMetadataBase> = {
    /** The session, without its `csrfHash`. */
    session: Sessions.Public | null
    /** Who it belongs to. */
    identity: Identities.Me<Profile> | null
  }

  /** What `signUp` posts. */
  export type SignUpOptions = {
    /** The route to post to, under baseUrl. Registration is yours to define, so no adapter mounts one
     *  and the `/signup` default is a placeholder: point this at your own route. */
    path?: string
  }

  /** The framework-free client surface. */
  export type Client<Profile extends Identities.ProfileMetadataBase> = {
    /** POST /auth/signin → resolves to the resulting session envelope. */
    signIn(opts: VanillaClient.SignInOptions): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
    /**
     * POST to your own registration route, `/signup` by default. Registration is app-shaped (the
     * profile fields are yours), so no adapter mounts a route for it and `input` is opaque, with the
     * response `data` echoed back. What this buys over a bare `fetch` is the rest of the client's
     * transport: same-origin credentials, the CSRF header, and the envelope. Does not create a
     * session; follow with `signIn` if desired.
     */
    signUp(input: unknown, opts?: VanillaClient.SignUpOptions): Promise<Envelope<unknown, string>>
    /** POST /auth/signout. Clears the local session whatever happens, and reports what the server did:
     *  a refused or unreachable signout leaves the session live, which the caller has to be able to see.
     *  `data` is `null` on success, because the route answers with a cookie and an empty body. */
    signOut(): Promise<Envelope<unknown, string>>
    /** GET /auth/session */
    getSession(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
    /** POST /auth/providers/:id/begin. A redirect flow (OAuth, SAML) answers `{ url }`, and in a browser
     *  the page is sent there; the others answer their own body, such as a passkey's options. */
    beginProvider(id: string, input?: unknown): Promise<Envelope<unknown, string>>
    /** Observe session changes. Returned function unsubscribes. */
    onChange(handler: (state: VanillaClient.SessionResult<Profile>) => void): () => void
    /** Force a session refetch + notify observers. */
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }
}
