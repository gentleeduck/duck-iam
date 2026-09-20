/** Svelte client types — the public `SvelteClient` namespace. */

import type { Envelope } from '~/core/errors/errors.types'
import type { Identities } from '~/core/identities'
import type { VanillaClient } from '../vanilla'

/** Svelte store shapes and the vanilla types a consumer needs. */
export namespace SvelteClient {
  /**
   * The minimal Svelte-store contract. Compatible with
   * `import type { Readable } from 'svelte/store'` without depending
   * on `svelte` at typecheck time.
   */
  export type Readable<T> = {
    subscribe(run: (value: T) => void): () => void
  }

  export interface Cfg<Profile extends Identities.ProfileMetadataBase> extends VanillaClient.Cfg {
    /** Pre-built client; overrides cfg. */
    client?: VanillaClient.Client<Profile>
    /** Disable the initial automatic /session fetch on store creation. */
    noInitialFetch?: boolean
  }

  export type State<Profile extends Identities.ProfileMetadataBase> = {
    session: VanillaClient.SessionResult<Profile>['session']
    identity: VanillaClient.SessionResult<Profile>['identity']
    /** `loading` until the first resolve settles, then `authed` or `guest`. */
    status: 'loading' | 'authed' | 'guest'
  }

  export type StoreBag<Profile extends Identities.ProfileMetadataBase> = {
    /** Svelte store exposing `{ session, identity, status }`. */
    state: SvelteClient.Readable<SvelteClient.State<Profile>>
    /** The underlying vanilla client (for advanced flows). */
    client: VanillaClient.Client<Profile>
    signIn(opts: VanillaClient.SignInOptions): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
    signOut(): Promise<Envelope<unknown, string>>
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }
}
