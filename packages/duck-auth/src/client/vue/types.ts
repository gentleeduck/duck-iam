/** Vue client types — the public `VueClient` namespace. */

import type { App, Ref } from 'vue'
import type { Identities } from '~/core/identities'
import type { Envelope, VanillaClient } from '../vanilla'

/** Vue plugin options, composable results and the vanilla types a consumer needs. */
export namespace VueClient {
  /** The Vue plugin `createAuthVuePlugin` answers. */
  export type Plugin = {
    /** Provides the client and session state to `app`. */
    install(app: App): void
  }

  /** What `createAuthVuePlugin` takes: the vanilla client's options, or a client of your own. */
  export interface Cfg<Profile extends Identities.ProfileMetadataBase> extends VanillaClient.Cfg {
    /** Pre-built client; overrides config. */
    client?: VanillaClient.Client<Profile>
    /** Disable the initial automatic /session fetch on plugin install. */
    noInitialFetch?: boolean
  }

  /** What the plugin provides. */
  export type Injected<Profile extends Identities.ProfileMetadataBase> = {
    /** The client every composable calls through. */
    client: VanillaClient.Client<Profile>
    /** The last session read; both fields are `null` for a guest. */
    state: Ref<VanillaClient.SessionResult<Profile>>
    /** `loading` until the first resolve settles, then `authed` or `guest`. */
    status: Ref<'loading' | 'authed' | 'guest'>
    /** Re-reads the session from the server. */
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }

  /** What `useAuthSession` answers. */
  export type UseSessionResult<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> = {
    /** The session and identity; both are `null` for a guest. */
    data: Ref<VanillaClient.SessionResult<Profile>>
    /** `loading` until the first resolve settles, then `authed` or `guest`. */
    status: Ref<'loading' | 'authed' | 'guest'>
    /** Re-reads the session from the server. */
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }

  /** What a mutation composable answers: the call, and its loading and error refs. */
  export type MutationResult<I, O> = {
    /** Runs the mutation. */
    mutate(input: I): Promise<O>
    /** Whether a call is in flight. */
    loading: Ref<boolean>
    /** What the last call threw, cleared when the next starts. A refusal is an envelope, not a throw. */
    error: Ref<unknown>
  }
}
