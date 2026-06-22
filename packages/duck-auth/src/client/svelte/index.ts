/** Svelte client - exposes the vanilla AuthClient as duck-typed `Readable` stores. */
import { type AuthVanillaClient, authCreateClient } from '../vanilla'

/**
 * Build a Svelte-compatible auth store + signIn/signOut actions.
 * Returns the bag eagerly (no Svelte runtime needed); `state` is a
 * `Readable` and updates whenever the underlying vanilla client emits.
 */
export function authCreateStore<Profile = unknown>(
  cfg: AuthSvelteClient.IConfig<Profile> = {},
): AuthSvelteClient.IAuthStoreBag<Profile> {
  const client = cfg.client ?? authCreateClient<Profile>(cfg)
  let current: AuthSvelteClient.IAuthState<Profile> = {
    identity: null,
    session: null,
    status: cfg.noInitialFetch ? 'guest' : 'loading',
  }
  const subs = new Set<(value: AuthSvelteClient.IAuthState<Profile>) => void>()
  const notify = (next: AuthSvelteClient.IAuthState<Profile>): void => {
    current = next
    for (const fn of subs) fn(current)
  }
  client.onChange((s) => {
    notify({
      identity: s.identity,
      session: s.session,
      status: s.identity ? 'authed' : 'guest',
    })
  })
  if (!cfg.noInitialFetch) {
    client.refresh().catch(() => notify({ ...current, status: 'guest' }))
  }
  const state: AuthSvelteClient.IReadable<AuthSvelteClient.IAuthState<Profile>> = {
    subscribe(run) {
      subs.add(run)
      run(current)
      return () => {
        subs.delete(run)
      }
    },
  }
  return {
    client,
    refresh: () => client.refresh(),
    signIn: (opts) => client.signIn(opts),
    signOut: () => client.signOut(),
    state,
  }
}

export namespace AuthSvelteClient {
  /**
   * The minimal Svelte-store contract. Compatible with
   * `import type { Readable } from 'svelte/store'` without depending
   * on `svelte` at typecheck time.
   */
  export interface IReadable<T> {
    subscribe(run: (value: T) => void): () => void
  }

  export interface IConfig<Profile = unknown> extends AuthVanillaClient.IConfig {
    /** Pre-built client; overrides cfg. */
    client?: AuthVanillaClient.IClient<Profile>
    /** Disable the initial automatic /session fetch on store creation. */
    noInitialFetch?: boolean
  }

  export interface IAuthState<Profile = unknown> {
    session: AuthVanillaClient.ISessionResult<Profile>['session']
    identity: AuthVanillaClient.ISessionResult<Profile>['identity']
    status: 'loading' | 'authed' | 'guest'
  }

  export interface IAuthStoreBag<Profile = unknown> {
    /** Svelte store exposing `{ session, identity, status }`. */
    state: IReadable<IAuthState<Profile>>
    /** The underlying vanilla client (for advanced flows). */
    client: AuthVanillaClient.IClient<Profile>
    signIn(opts: AuthVanillaClient.ISignInOptions): Promise<AuthVanillaClient.ISignInResult<Profile>>
    signOut(): Promise<{ ok: true }>
    refresh(): Promise<AuthVanillaClient.ISessionResult<Profile>>
  }
}
