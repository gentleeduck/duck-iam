/** Svelte client - exposes the vanilla AuthClient as duck-typed `Readable` stores. Types live in `./types`. */
import type { Identity } from '../../core'
import { createAuthClient } from '../vanilla'
import type { SvelteClient } from './types'

export type { SvelteClient } from './types'

/**
 * Build a Svelte-compatible auth store + signIn/signOut actions.
 * Returns the bag eagerly (no Svelte runtime needed); `state` is a
 * `Readable` and updates whenever the underlying vanilla client emits.
 */
export function createAuthStore<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  cfg: SvelteClient.IConfig<Profile> = {},
): SvelteClient.StoreBag<Profile> {
  const client = cfg.client ?? createAuthClient<Profile>(cfg)
  let current: SvelteClient.State<Profile> = {
    identity: null,
    session: null,
    status: cfg.noInitialFetch ? 'guest' : 'loading',
  }
  const subs = new Set<(value: SvelteClient.State<Profile>) => void>()
  const notify = (next: SvelteClient.State<Profile>): void => {
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
  const state: SvelteClient.Readable<SvelteClient.State<Profile>> = {
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
