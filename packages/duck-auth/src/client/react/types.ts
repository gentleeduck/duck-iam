import type { ReactNode } from 'react'
import type { Identities } from '~/core/identities'
import type { Sessions } from '~/core/sessions'
import type { Envelope, VanillaClient } from '../vanilla'

/** React provider props, hook results and the vanilla types a consumer needs. */
export namespace ReactClient {
  /** The vanilla types a React consumer actually needs, surfaced here. */
  export type Profile = Identities.ProfileMetadataBase
  /** An identity, as the server answers it. */
  export type Identity<P extends Profile = Profile> = Identities.Me<P>
  /** A session, as the server answers it. */
  export type Session = Sessions.Public
  /** The session and identity `/session` answers. */
  export type SessionResult<P extends Profile = Profile> = VanillaClient.SessionResult<P>
  /** What `useSignIn` posts. */
  export type SignInOptions = VanillaClient.SignInOptions
  /** What `useSignUp` posts. */
  export type SignUpOptions = VanillaClient.SignUpOptions
  /** The vanilla client's options. */
  export type Cfg = VanillaClient.Cfg
  /** The vanilla client. */
  export type Client<P extends Profile = Profile> = VanillaClient.Client<P>
  /** A client call's envelope: `{ ok: true, data }` or `{ ok: false, error }`. */
  export type Result<T> = Envelope<T, string>

  /** What `Provider` puts in context. */
  export type ContextValue<Profile extends Identities.ProfileMetadataBase> = {
    /** The client every hook calls through. */
    client: VanillaClient.Client<Profile>
    /** The last session read; both fields are `null` for a guest. */
    state: VanillaClient.SessionResult<Profile>
    /** `loading` until the first resolve settles, then `authed` or `guest`. */
    status: 'loading' | 'authed' | 'guest'
    /** Re-reads the session from the server. */
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }

  /** What `Provider` takes: the vanilla client's options, or a client of your own. */
  export interface IProviderProps<P extends Profile = Profile> extends VanillaClient.Cfg {
    /** The tree the hooks are used in. */
    children?: ReactNode
    /** Optional pre-built client; overrides cfg. */
    client?: VanillaClient.Client<P>
    /** Disable the initial automatic /session fetch on mount. */
    noInitialFetch?: boolean
  }

  /** What `useSession` answers. */
  export type UseSessionResult<Profile extends Identities.ProfileMetadataBase> = {
    /** The session and identity; both are `null` for a guest. */
    data: VanillaClient.SessionResult<Profile>
    /** `loading` until the first resolve settles, then `authed` or `guest`. */
    status: 'loading' | 'authed' | 'guest'
    /** Re-reads the session from the server. */
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }

  /** What a mutation hook answers: the call, and its loading and error state. */
  export type MutationResult<I, O> = {
    /** Runs the mutation. */
    mutate(input: I): Promise<O>
    /** Whether a call is in flight. */
    loading: boolean
    /** What the last call threw, cleared when the next starts. A refusal is an envelope, not a throw. */
    error: unknown
  }
}
