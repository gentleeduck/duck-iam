/** React client types - context shape + the public `ReactClient` namespace. */
import type { ReactNode } from 'react'
import type { Identity } from '~/core/identities'
import type { Envelope } from '~/core/types/session'
import type { VanillaClient } from '../vanilla'

export namespace ReactClient {
  export type ContextValue<Profile extends Identity.ProfileMetadataBase> = {
    client: VanillaClient.Client<Profile>
    state: VanillaClient.SessionResult<Profile>
    status: 'loading' | 'authed' | 'guest'
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }

  export interface IProviderProps extends VanillaClient.Config {
    children?: ReactNode
    /** Optional pre-built client; overrides cfg. */
    client?: VanillaClient.Client<any>
    /** Disable the initial automatic /session fetch on mount. */
    noInitialFetch?: boolean
  }

  export type UseSessionResult<Profile extends Identity.ProfileMetadataBase> = {
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
