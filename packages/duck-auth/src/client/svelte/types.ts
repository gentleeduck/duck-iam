/** Svelte client types — the public `SvelteClient` namespace. */

import type { Identities } from '~/core/identities'
import type { Envelope, VanillaClient } from '../vanilla'

/** Svelte store shapes and the vanilla types a consumer needs. */
export namespace SvelteClient {
  /**
   * The minimal Svelte-store contract. Compatible with
   * `import type { Readable } from 'svelte/store'` without depending
   * on `svelte` at typecheck time.
   */
  export type Readable<T> = {
    /** Calls `run` with every value; answers the unsubscribe. */
    subscribe(run: (value: T) => void): () => void
  }

  export interface Cfg<Profile extends Identities.ProfileMetadataBase> extends VanillaClient.Cfg {
    /** Pre-built client; overrides cfg. */
    client?: VanillaClient.Client<Profile>
    /** Disable the initial automatic /session fetch on store creation. */
    noInitialFetch?: boolean
  }

  /** The session, identity and status the store holds. */
  export type State<Profile extends Identities.ProfileMetadataBase> = {
    /** The session, `null` for a guest. */
    session: VanillaClient.SessionResult<Profile>['session']
    /** Who it belongs to, `null` for a guest. */
    identity: VanillaClient.SessionResult<Profile>['identity']
    /** `loading` until the first resolve settles, then `authed` or `guest`. */
    status: 'loading' | 'authed' | 'guest'
  }

  /** What `createAuthStore` answers: the store and its actions. */
  export type StoreBag<Profile extends Identities.ProfileMetadataBase> = {
    /** Svelte store exposing `{ session, identity, status }`. */
    state: SvelteClient.Readable<SvelteClient.State<Profile>>
    /** The underlying vanilla client (for advanced flows). */
    client: VanillaClient.Client<Profile>
    /** `client.signIn`. */
    signIn(opts: VanillaClient.SignInOptions): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
    /** `client.signOut`. */
    signOut(): Promise<Envelope<unknown, string>>
    /** Re-reads the session from the server. */
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }
}
