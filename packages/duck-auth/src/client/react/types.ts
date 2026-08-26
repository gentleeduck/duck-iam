/** React client types - context shape + the public `ReactClient` namespace. */
import type { ReactNode } from 'react'
import type { Envelope } from '~/core/errors/errors.types'
import type { Identities } from '~/core/identities'
import type { Sessions } from '~/core/sessions'
import type { VanillaClient } from '../vanilla'

export namespace ReactClient {
  /**
   * The vanilla types a React consumer actually needs, surfaced here.
   *
   * Without these an app using only the React entry still has to import from
   * `client/vanilla` to name the session it just received from `useSession`,
   * which makes the vanilla client part of its public API for no reason.
   */
  export type Profile = Identities.ProfileMetadataBase
  export type Identity<P extends Profile = Profile> = Identities.Me<P>
  export type Session = Sessions.Me
  export type SessionResult<P extends Profile = Profile> = VanillaClient.SessionResult<P>
  export type SignInOptions = VanillaClient.SignInOptions
  export type SignUpOptions = VanillaClient.SignUpOptions
  export type Cfg = VanillaClient.Cfg
  export type Client<P extends Profile = Profile> = VanillaClient.Client<P>
  export type Result<T> = Envelope<T, string>

  export type ContextValue<Profile extends Identities.ProfileMetadataBase> = {
    client: VanillaClient.Client<Profile>
    state: VanillaClient.SessionResult<Profile>
    status: 'loading' | 'authed' | 'guest'
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }

  export interface IProviderProps<P extends Profile = Profile> extends VanillaClient.Cfg {
    children?: ReactNode
    /** Optional pre-built client; overrides cfg. */
    client?: VanillaClient.Client<P>
    /** Disable the initial automatic /session fetch on mount. */
    noInitialFetch?: boolean
  }

  export type UseSessionResult<Profile extends Identities.ProfileMetadataBase> = {
    data: VanillaClient.SessionResult<Profile>
    status: 'loading' | 'authed' | 'guest'
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }

  export type MutationResult<I, O> = {
    mutate(input: I): Promise<O>
    loading: boolean
    error: unknown | null
  }
}
