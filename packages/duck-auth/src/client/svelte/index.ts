/**
 * Svelte client - exposes the vanilla AuthClient as a set of Svelte
 * stores via the duck-typed `Readable` contract (`{ subscribe }`).
 * Doesn't import `svelte` directly, so the auth core stays
 * framework-free; consumers `import` these from
 * `@gentleduck/auth/client/svelte` exactly like a normal Svelte
 * store.
 *
 * @example
 * ```svelte
 * <script lang="ts">
 *   import { createAuthStore } from '@gentleduck/auth/client/svelte'
 *   const auth = createAuthStore({ baseUrl: '/auth' })
 *   $: ({ session, identity } = $auth.state)
 * </script>
 * ```
 */
import { createAuthClient, type VanillaClient } from '../vanilla'

/**
 * Build a Svelte-compatible auth store + signIn/signOut actions.
 * Returns the bag eagerly (no Svelte runtime needed); `state` is a
 * `Readable` and updates whenever the underlying vanilla client emits.
 */
export function createAuthStore<Profile = unknown>(
  cfg: SvelteClient.IConfig<Profile> = {},
): SvelteClient.IAuthStoreBag<Profile> {
  const client = cfg.client ?? createAuthClient<Profile>(cfg)
  let current: SvelteClient.IAuthState<Profile> = {
    identity: null,
    session: null,
    status: cfg.noInitialFetch ? 'guest' : 'loading',
  }
  const subs = new Set<(value: SvelteClient.IAuthState<Profile>) => void>()
  const notify = (next: SvelteClient.IAuthState<Profile>): void => {
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
  const state: SvelteClient.IReadable<SvelteClient.IAuthState<Profile>> = {
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

/**
 * Namespace merge for SvelteClient.
 */
export namespace SvelteClient {
  /**
   * The minimal Svelte-store contract. Compatible with
   * `import type { Readable } from 'svelte/store'` without depending
   * on `svelte` at typecheck time.
   */
  export interface IReadable<T> {
    subscribe(run: (value: T) => void): () => void
  }

  export interface IConfig<Profile = unknown> extends VanillaClient.IConfig {
    /** Pre-built client; overrides cfg. */
    client?: VanillaClient.IClient<Profile>
    /** Disable the initial automatic /session fetch on store creation. */
    noInitialFetch?: boolean
  }

  export interface IAuthState<Profile = unknown> {
    session: VanillaClient.ISessionResult<Profile>['session']
    identity: VanillaClient.ISessionResult<Profile>['identity']
    status: 'loading' | 'authed' | 'guest'
  }

  export interface IAuthStoreBag<Profile = unknown> {
    /** Svelte store exposing `{ session, identity, status }`. */
    state: IReadable<IAuthState<Profile>>
    /** The underlying vanilla client (for advanced flows). */
    client: VanillaClient.IClient<Profile>
    signIn(opts: VanillaClient.ISignInOptions): Promise<VanillaClient.ISignInResult<Profile>>
    signOut(): Promise<{ ok: true }>
    refresh(): Promise<VanillaClient.ISessionResult<Profile>>
  }
}
