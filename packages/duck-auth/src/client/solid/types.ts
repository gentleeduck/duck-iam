/** Solid client types — context shape + the public `SolidClient` namespace. */
import type { JSX } from 'solid-js'
import type { Identity } from '~/core/identities/identities.types'
import type { Envelope } from '~/core/types/session'
import type { VanillaClient } from '../vanilla'

export namespace SolidClient {
  export type Context<Profile extends Identity.ProfileMetadataBase> = {
    client: VanillaClient.Client<Profile>
    state: () => VanillaClient.SessionResult<Profile>
    status: () => 'loading' | 'authed' | 'guest'
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }

  export interface IProviderProps<Profile extends Identity.ProfileMetadataBase> extends VanillaClient.Config {
    children?: JSX.Element
    /** Pre-built client; overrides config. */
    client?: VanillaClient.Client<Profile>
    /** Disable the initial automatic /session fetch on mount. */
    noInitialFetch?: boolean
  }

  export type UseSessionResult<Profile extends Identity.ProfileMetadataBase> = {
    data: () => VanillaClient.SessionResult<Profile>
    status: () => 'loading' | 'authed' | 'guest'
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }

  export type MutationResult<I, O> = {
    mutate(input: I): Promise<O>
    loading: () => boolean
    error: () => unknown | null
  }
}
