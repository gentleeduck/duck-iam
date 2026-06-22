/** Solid client - context + signals; `solid-js` is an OPTIONAL peerDep. */
import { createContext, createMemo, createSignal, type JSX, onCleanup, onMount, useContext } from 'solid-js'
import { type AuthVanillaClient, authCreateClient } from '../vanilla'

interface SolidAuthContextValue<Profile = unknown> {
  client: AuthVanillaClient.IClient<Profile>
  state: () => AuthVanillaClient.ISessionResult<Profile>
  status: () => 'loading' | 'authed' | 'guest'
  refresh(): Promise<AuthVanillaClient.ISessionResult<Profile>>
}

const AuthContext = createContext<SolidAuthContextValue<unknown> | null>(null)

/** `AuthProvider`. */
export function AuthProvider(props: AuthSolidClient.IProviderProps): JSX.Element {
  const client = props.client ?? authCreateClient(props)
  const [state, setState] = createSignal<AuthVanillaClient.ISessionResult<unknown>>({ identity: null, session: null })
  const [status, setStatus] = createSignal<'loading' | 'authed' | 'guest'>(props.noInitialFetch ? 'guest' : 'loading')

  onMount(() => {
    const off = client.onChange((s) => {
      setState(s)
      setStatus(s.identity ? 'authed' : 'guest')
    })
    if (!props.noInitialFetch) {
      client.refresh().catch(() => setStatus('guest'))
    }
    onCleanup(off)
  })

  const ctxVal: SolidAuthContextValue<unknown> = {
    client,
    refresh: () => client.refresh(),
    state,
    status,
  }

  return AuthContext.Provider({ children: props.children, value: ctxVal }) as JSX.Element
}

function useAuthCtx<Profile = unknown>(): SolidAuthContextValue<Profile> {
  const ctx = useContext(AuthContext) as SolidAuthContextValue<Profile> | null
  if (!ctx) {
    throw new Error('[@gentleduck/auth/client/solid] authUseSession / authUseSignIn must be used inside <AuthProvider>')
  }
  return ctx
}

/** `authUseSession`. */
export function authUseSession<Profile = unknown>(): AuthSolidClient.IUseSessionResult<Profile> {
  const ctx = useAuthCtx<Profile>()
  return { data: ctx.state, refresh: ctx.refresh, status: ctx.status }
}

function useMutation<I, O>(fn: (input: I) => Promise<O>): AuthSolidClient.IMutationResult<I, O> {
  const [loading, setLoading] = createSignal(false)
  const [error, setError] = createSignal<unknown | null>(null)
  const mutate = async (input: I) => {
    setLoading(true)
    setError(null)
    try {
      return await fn(input)
    } catch (err) {
      setError(() => err)
      throw err
    } finally {
      setLoading(false)
    }
  }
  return {
    error: createMemo(() => error()),
    loading: createMemo(() => loading()),
    mutate,
  }
}

/** `authUseSignIn`. */
export function authUseSignIn<Profile = unknown>(): AuthSolidClient.IMutationResult<
  AuthVanillaClient.ISignInOptions,
  AuthVanillaClient.ISignInResult<Profile>
> {
  const { client } = useAuthCtx<Profile>()
  return useMutation((opts: AuthVanillaClient.ISignInOptions) => client.signIn(opts))
}

/** `authUseSignOut`. */
export function authUseSignOut(): AuthSolidClient.IMutationResult<void, { ok: true }> {
  const { client } = useAuthCtx()
  return useMutation(() => client.signOut())
}

/** `authUseClient`. */
export function authUseClient<Profile = unknown>(): AuthVanillaClient.IClient<Profile> {
  return useAuthCtx<Profile>().client
}

export namespace AuthSolidClient {
  export interface IProviderProps extends AuthVanillaClient.IConfig {
    children?: JSX.Element
    /** Pre-built client; overrides config. */
    client?: AuthVanillaClient.IClient<unknown>
    /** Disable the initial automatic /session fetch on mount. */
    noInitialFetch?: boolean
  }

  export interface IUseSessionResult<Profile = unknown> {
    data: () => AuthVanillaClient.ISessionResult<Profile>
    status: () => 'loading' | 'authed' | 'guest'
    refresh(): Promise<AuthVanillaClient.ISessionResult<Profile>>
  }

  export interface IMutationResult<I, O> {
    mutate(input: I): Promise<O>
    loading: () => boolean
    error: () => unknown | null
  }
}
