/** Svelte client types — the public `SvelteClient` namespace. */
import type { Identity } from '../../core'
import type { Envelope } from '../../core/types/session'
import type { VanillaClient } from '../vanilla'

export namespace SvelteClient {
  /**
   * The minimal Svelte-store contract. Compatible with
   * `import type { Readable } from 'svelte/store'` without depending
   * on `svelte` at typecheck time.
   */
  export type Readable<T> = {
    subscribe(run: (value: T) => void): () => void
  }

  export interface IConfig<Profile extends Identity.ProfileMetadataBase> extends VanillaClient.Config {
    /** Pre-built client; overrides cfg. */
    client?: VanillaClient.Client<Profile>
    /** Disable the initial automatic /session fetch on store creation. */
    noInitialFetch?: boolean
  }

  export type State<Profile extends Identity.ProfileMetadataBase> = {
    session: VanillaClient.SessionResult<Profile>['session']
    identity: VanillaClient.SessionResult<Profile>['identity']
    status: 'loading' | 'authed' | 'guest'
  }

  export type StoreBag<Profile extends Identity.ProfileMetadataBase> = {
    /** Svelte store exposing `{ session, identity, status }`. */
    state: SvelteClient.Readable<SvelteClient.State<Profile>>
    /** The underlying vanilla client (for advanced flows). */
    client: VanillaClient.Client<Profile>
    signIn(opts: VanillaClient.SignInOptions): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
    signOut(): Promise<Envelope<Record<string, never>, string>>
    refresh(): Promise<Envelope<VanillaClient.SessionResult<Profile>, string>>
  }
}
