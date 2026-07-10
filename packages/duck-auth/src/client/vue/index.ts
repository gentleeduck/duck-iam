/** Vue 3 plugin + composables; `vue` is an OPTIONAL peerDep resolved lazily. Types live in `./types`. */

import type { Envelope } from '~/core/errors/errors.types'
import type { Identities } from '~/core/identities'
import { createAuthClient, type VanillaClient } from '../vanilla'
import type { VueClient } from './types'

export type { VueClient } from './types'

/**
 * Build a Vue 3 plugin that installs the auth client + composables.
 * The returned object is plugin-shaped (`{ install }`) so it works
 * with `app.use(authPlugin)` from a `createApp` boot.
 */
export function createAuthVuePlugin<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  cfg: VueClient.Cfg<Profile> = {},
): VueClient.Plugin {
  const client = cfg.client ?? createAuthClient<Profile>(cfg)
  return {
    install(app: VueClient.App): void {
      const vue = loadVueSync()
      const state = vue.ref<VanillaClient.SessionResult<Profile>>({ identity: null, session: null })
      const status = vue.ref<'loading' | 'authed' | 'guest'>(cfg.noInitialFetch ? 'guest' : 'loading')
      client.onChange((s) => {
        state.value = s
        status.value = s.identity ? 'authed' : 'guest'
      })
      if (!cfg.noInitialFetch) {
        client.refresh().catch(() => {
          status.value = 'guest'
        })
      }
      const ctx: VueClient.Injected<Profile> = { client, refresh: () => client.refresh(), state, status }
      app.provide(AUTH_VUE_KEY, ctx)
    },
  }
}

/** Shared Symbol key used by `app.provide` / `inject`. */
export const AUTH_VUE_KEY = Symbol.for('@gentleduck/AUTH/client/vue')

function useAuthCtx<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(): VueClient.Injected<Profile> {
  const vue = loadVueSync()
  const ctx = vue.inject(AUTH_VUE_KEY) as VueClient.Injected<Profile> | undefined
  if (!ctx) {
    throw new Error('[@gentleduck/AUTH/client/vue] use* composables require app.use(authCreateVuePlugin(...))')
  }
  return ctx
}

export function useAuthSession<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(): VueClient.UseSessionResult<Profile> {
  const ctx = useAuthCtx<Profile>()
  return { data: ctx.state, refresh: ctx.refresh, status: ctx.status }
}

function useMutation<I, O>(fn: (input: I) => Promise<O>): VueClient.MutationResult<I, O> {
  const vue = loadVueSync()
  const loading = vue.ref(false)
  const error = vue.ref<unknown | null>(null)
  const mutate = async (input: I) => {
    loading.value = true
    error.value = null
    try {
      return await fn(input)
    } catch (err) {
      error.value = err
      throw err
    } finally {
      loading.value = false
    }
  }
  return { error, loading, mutate }
}

export function useAuthSignIn<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(): VueClient.MutationResult<VanillaClient.SignInOptions, Envelope<VanillaClient.SessionResult<Profile>, string>> {
  const { client } = useAuthCtx<Profile>()
  return useMutation((opts: VanillaClient.SignInOptions) => client.signIn(opts))
}

export function useAuthSignOut(): VueClient.MutationResult<void, Envelope<Record<string, never>, string>> {
  const { client } = useAuthCtx()
  return useMutation(() => client.signOut())
}

export function useAuthClient<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(): VanillaClient.Client<Profile> {
  return useAuthCtx<Profile>().client
}

let _vueModule: VueClient.VueModule | null = null
function loadVueSync(): VueClient.VueModule {
  if (_vueModule) return _vueModule
  // CJS-style require keeps this synchronous: composables MUST run
  // inside Vue's reactive scope, so a Promise here would break the
  // `setup()` contract.
  try {
    const req = new Function('return require')()
    _vueModule = req('vue') as VueClient.VueModule
    return _vueModule
  } catch {
    throw new Error('[@gentleduck/AUTH/client/vue] `vue` is not installed. Add it: `bun add vue` (^3).')
  }
}
