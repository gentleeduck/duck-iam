/** Solid client types — context shape + the public `SolidClient` namespace. */
import type { JSX } from 'solid-js'
import type { Identities } from '~/core/identities/identities.types'
import type { Envelope, VanillaClient } from '../vanilla'

/** Solid provider props, primitive results and the vanilla types a consumer needs. */
export namespace SolidClient {
  /** What the provider puts in context. */
  export type Context<Profile extends Identities.ProfileMetadataBase> = {
    /** The client every primitive calls through. */
    client: VanillaClient.Client<Profile>
    /** The last session read; both fields are `null` for a guest. */
    state: () => VanillaClient.SessionResult<Profile>
    /** `loading` until the first resolve settles, then `authed` or `guest`. */
    status: () => 'loading' | 'authed' | 'guest'
    /** Re-reads the session from the server. */
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }

  /** What `Provider` takes: the vanilla client's options, or a client of your own. */
  export interface IProviderProps<Profile extends Identities.ProfileMetadataBase> extends VanillaClient.Cfg {
    /** The tree the primitives are used in. */
    children?: JSX.Element
    /** Pre-built client; overrides config. */
    client?: VanillaClient.Client<Profile>
    /** Disable the initial automatic /session fetch on mount. */
    noInitialFetch?: boolean
  }

  /** What `authUseSession` answers. */
  export type UseSessionResult<Profile extends Identities.ProfileMetadataBase> = {
    /** The session and identity; both are `null` for a guest. */
    data: () => VanillaClient.SessionResult<Profile>
    /** `loading` until the first resolve settles, then `authed` or `guest`. */
    status: () => 'loading' | 'authed' | 'guest'
    /** Re-reads the session from the server. */
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }

  /** What a mutation primitive answers: the call, and its loading and error signals. */
  export type MutationResult<I, O> = {
    /** Runs the mutation. */
    mutate(input: I): Promise<O>
    /** Whether a call is in flight. */
    loading: () => boolean
    /** What the last call threw, cleared when the next starts. A refusal is an envelope, not a throw. */
    error: () => unknown
  }
}
