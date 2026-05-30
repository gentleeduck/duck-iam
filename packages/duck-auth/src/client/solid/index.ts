/** Solid client - context + signals; `solid-js` is an OPTIONAL peerDep. */
import { createContext, createMemo, createSignal, type JSX, onCleanup, onMount, useContext } from 'solid-js'
import { createAuthClient, type VanillaClient } from '../vanilla'

interface SolidAuthContextValue<Profile = unknown> {
  client: VanillaClient.IClient<Profile>
  state: () => VanillaClient.ISessionResult<Profile>
  status: () => 'loading' | 'authed' | 'guest'
  refresh(): Promise<VanillaClient.ISessionResult<Profile>>
}

const AuthContext = createContext<SolidAuthContextValue<unknown> | null>(null)

/** `AuthProvider`. */
export function AuthProvider(props: SolidClient.IProviderProps): JSX.Element {
  const client = props.client ?? createAuthClient(props)
  const [state, setState] = createSignal<VanillaClient.ISessionResult<unknown>>({ identity: null, session: null })
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
    throw new Error('[@gentleduck/auth/client/solid] useSession / useSignIn must be used inside <AuthProvider>')
  }
  return ctx
}

/** `useSession`. */
export function useSession<Profile = unknown>(): SolidClient.IUseSessionResult<Profile> {
  const ctx = useAuthCtx<Profile>()
  return { data: ctx.state, refresh: ctx.refresh, status: ctx.status }
}

function useMutation<I, O>(fn: (input: I) => Promise<O>): SolidClient.IMutationResult<I, O> {
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

/** `useSignIn`. */
export function useSignIn<Profile = unknown>(): SolidClient.IMutationResult<
  VanillaClient.ISignInOptions,
  VanillaClient.ISignInResult<Profile>
> {
  const { client } = useAuthCtx<Profile>()
  return useMutation((opts: VanillaClient.ISignInOptions) => client.signIn(opts))
}

/** `useSignOut`. */
export function useSignOut(): SolidClient.IMutationResult<void, { ok: true }> {
  const { client } = useAuthCtx()
  return useMutation(() => client.signOut())
}

/** `useAuthClient`. */
export function useAuthClient<Profile = unknown>(): VanillaClient.IClient<Profile> {
  return useAuthCtx<Profile>().client
}

export namespace SolidClient {
  export interface IProviderProps extends VanillaClient.IConfig {
    children?: JSX.Element
    /** Pre-built client; overrides config. */
    client?: VanillaClient.IClient<unknown>
    /** Disable the initial automatic /session fetch on mount. */
    noInitialFetch?: boolean
  }

  export interface IUseSessionResult<Profile = unknown> {
    data: () => VanillaClient.ISessionResult<Profile>
    status: () => 'loading' | 'authed' | 'guest'
    refresh(): Promise<VanillaClient.ISessionResult<Profile>>
  }

  export interface IMutationResult<I, O> {
    mutate(input: I): Promise<O>
    loading: () => boolean
    error: () => unknown | null
  }
}
