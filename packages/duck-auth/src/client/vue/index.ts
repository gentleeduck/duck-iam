/** Vue 3 plugin + composables; `vue` is an OPTIONAL peerDep resolved lazily. */
import { type AuthVanillaClient, authCreateClient } from '../vanilla'

/**
 * Build a Vue 3 plugin that installs the auth client + composables.
 * The returned object is plugin-shaped (`{ install }`) so it works
 * with `app.use(authPlugin)` from a `createApp` boot.
 */
export function authCreateVuePlugin<Profile = unknown>(
  cfg: AuthVueClient.IPluginConfig<Profile> = {},
): AuthVueClient.IPlugin {
  const client = cfg.client ?? authCreateClient<Profile>(cfg)
  return {
    install(app: AuthVueClient.IApp): void {
      const vue = loadVueSync()
      const state = vue.ref<AuthVanillaClient.ISessionResult<Profile>>({ identity: null, session: null })
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
      const ctx: AuthVueClient.IInjected<Profile> = { client, refresh: () => client.refresh(), state, status }
      app.provide(AUTH_VUE_KEY, ctx)
    },
  }
}

/** Shared Symbol key used by `app.provide` / `inject`. */
export const AUTH_VUE_KEY = Symbol.for('@gentleduck/auth/client/vue')

function useAuthCtx<Profile = unknown>(): AuthVueClient.IInjected<Profile> {
  const vue = loadVueSync()
  const ctx = vue.inject(AUTH_VUE_KEY) as AuthVueClient.IInjected<Profile> | undefined
  if (!ctx) {
    throw new Error(
      '[@gentleduck/auth/client/vue] authUseSession / authUseSignIn requires app.use(authCreateVuePlugin(...))',
    )
  }
  return ctx
}

/** `authUseSession`. */
export function authUseSession<Profile = unknown>(): AuthVueClient.IUseSessionResult<Profile> {
  const ctx = useAuthCtx<Profile>()
  return { data: ctx.state, refresh: ctx.refresh, status: ctx.status }
}

function useMutation<I, O>(fn: (input: I) => Promise<O>): AuthVueClient.IMutationResult<I, O> {
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

/** `authUseSignIn`. */
export function authUseSignIn<Profile = unknown>(): AuthVueClient.IMutationResult<
  AuthVanillaClient.ISignInOptions,
  AuthVanillaClient.ISignInResult<Profile>
> {
  const { client } = useAuthCtx<Profile>()
  return useMutation((opts: AuthVanillaClient.ISignInOptions) => client.signIn(opts))
}

/** `authUseSignOut`. */
export function authUseSignOut(): AuthVueClient.IMutationResult<void, { ok: true }> {
  const { client } = useAuthCtx()
  return useMutation(() => client.signOut())
}

/** `authUseClient`. */
export function authUseClient<Profile = unknown>(): AuthVanillaClient.IClient<Profile> {
  return useAuthCtx<Profile>().client
}

let _vueModule: AuthVueClient.IVueModule | null = null
function loadVueSync(): AuthVueClient.IVueModule {
  if (_vueModule) return _vueModule
  // CJS-style require keeps this synchronous: composables MUST run
  // inside Vue's reactive scope, so a Promise here would break the
  // `setup()` contract.
  try {
    const req = new Function('return require')() as (id: string) => unknown
    _vueModule = req('vue') as AuthVueClient.IVueModule
    return _vueModule
  } catch {
    throw new Error('[@gentleduck/auth/client/vue] `vue` is not installed. Add it: `bun add vue` (^3).')
  }
}

export namespace AuthVueClient {
  /** Minimal `Ref<T>` surface compatible with Vue 3 `vue.ref`. */
  export interface IRef<T> {
    value: T
  }

  export interface IVueModule {
    ref<T>(value: T): IRef<T>
    inject(key: symbol): unknown
    // biome-ignore lint/suspicious/noExplicitAny: keep this shape framework-agnostic.
    provide(key: symbol, value: any): void
  }

  export interface IApp {
    provide(key: symbol, value: unknown): IApp
  }

  export interface IPlugin {
    install(app: IApp): void
  }

  export interface IPluginConfig<Profile = unknown> extends AuthVanillaClient.IConfig {
    /** Pre-built client; overrides config. */
    client?: AuthVanillaClient.IClient<Profile>
    /** Disable the initial automatic /session fetch on plugin install. */
    noInitialFetch?: boolean
  }

  export interface IInjected<Profile = unknown> {
    client: AuthVanillaClient.IClient<Profile>
    state: IRef<AuthVanillaClient.ISessionResult<Profile>>
    status: IRef<'loading' | 'authed' | 'guest'>
    refresh(): Promise<AuthVanillaClient.ISessionResult<Profile>>
  }

  export interface IUseSessionResult<Profile = unknown> {
    data: IRef<AuthVanillaClient.ISessionResult<Profile>>
    status: IRef<'loading' | 'authed' | 'guest'>
    refresh(): Promise<AuthVanillaClient.ISessionResult<Profile>>
  }

  export interface IMutationResult<I, O> {
    mutate(input: I): Promise<O>
    loading: IRef<boolean>
    error: IRef<unknown | null>
  }
}
