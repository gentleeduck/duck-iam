/**
 * React client - hooks + provider wrapping the vanilla AuthClient. Keeps
 * React itself as a peerDep so the auth core has no React in its graph.
 *
 * @example
 * ```tsx
 * import { AuthProvider, authUseSession, authUseSignIn } from '@gentleduck/auth/client/react'
 *
 * <AuthProvider baseUrl="/auth">
 *   <App />
 * </AuthProvider>
 *
 * function SignIn() {
 *   const signIn = authUseSignIn()
 *   return <button onClick={() => signIn.mutate({ providerId: 'password', input: { ... } })}>...</button>
 * }
 * ```
 */
import {
  createContext,
  createElement,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import { authCreateClient, type AuthVanillaClient } from '../vanilla'

// --- context ----------------------------------------------------------

interface AuthContextValue<Profile = unknown> {
  client: AuthVanillaClient.IClient<Profile>
  state: AuthVanillaClient.ISessionResult<Profile>
  status: 'loading' | 'authed' | 'guest'
  refresh(): Promise<AuthVanillaClient.ISessionResult<Profile>>
}

const AuthContext = createContext<AuthContextValue<unknown> | null>(null)

/** `AuthProvider`. */
export function AuthProvider(props: AuthReactClient.IProviderProps): ReturnType<typeof createElement> {
  const { children, client: externalClient, noInitialFetch, ...cfg } = props
  // biome-ignore lint/correctness/useExhaustiveDependencies: cfg is a destructured spread; only baseUrl matters for client identity.
  const client = useMemo(() => externalClient ?? authCreateClient(cfg), [externalClient, cfg.baseUrl])
  const [state, setState] = useState<AuthVanillaClient.ISessionResult<unknown>>({ session: null, identity: null })
  const [status, setStatus] = useState<'loading' | 'authed' | 'guest'>(noInitialFetch ? 'guest' : 'loading')
  const subscribed = useRef(false)

  useEffect(() => {
    if (subscribed.current) return
    subscribed.current = true
    const off = client.onChange((s) => {
      setState(s)
      setStatus(s.identity ? 'authed' : 'guest')
    })
    if (!noInitialFetch) {
      client.refresh().catch(() => setStatus('guest'))
    }
    return () => {
      subscribed.current = false
      off()
    }
  }, [client, noInitialFetch])

  const value: AuthContextValue<unknown> = useMemo(
    () => ({
      client,
      state,
      status,
      refresh: () => client.refresh(),
    }),
    [client, state, status],
  )

  return createElement(AuthContext.Provider, { value }, children)
}

function useAuthCtx<Profile = unknown>(): AuthContextValue<Profile> {
  const ctx = useContext(AuthContext) as AuthContextValue<Profile> | null
  if (!ctx) {
    throw new Error('[@gentleduck/auth/client/react] useAuth* hooks must be used inside <AuthProvider>')
  }
  return ctx
}

// --- hooks ------------------------------------------------------------

/** `authUseSession`. */
export function authUseSession<Profile = unknown>(): AuthReactClient.IUseSessionResult<Profile> {
  const ctx = useAuthCtx<Profile>()
  return { data: ctx.state, status: ctx.status, refresh: ctx.refresh }
}

function useMutation<I, O>(fn: (input: I) => Promise<O>): AuthReactClient.IMutationResult<I, O> {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<unknown | null>(null)
  const mutate = useCallback(
    async (input: I) => {
      setLoading(true)
      setError(null)
      try {
        return await fn(input)
      } catch (err) {
        setError(err)
        throw err
      } finally {
        setLoading(false)
      }
    },
    [fn],
  )
  return { mutate, loading, error }
}

/** `authUseSignIn`. */
export function authUseSignIn<Profile = unknown>(): AuthReactClient.IMutationResult<
  AuthVanillaClient.ISignInOptions,
  AuthVanillaClient.ISignInResult<Profile>
> {
  const { client } = useAuthCtx<Profile>()
  return useMutation((opts: AuthVanillaClient.ISignInOptions) => client.signIn(opts))
}

/** `authUseSignOut`. */
export function authUseSignOut(): AuthReactClient.IMutationResult<void, { ok: true }> {
  const { client } = useAuthCtx()
  return useMutation(() => client.signOut())
}

/** `authUseBeginProvider`. */
export function authUseBeginProvider(): AuthReactClient.IMutationResult<{ id: string; input?: unknown }, { body: unknown }> {
  const { client } = useAuthCtx()
  return useMutation(({ id, input }) => client.beginProvider(id, input))
}

/** `authUseClient`. */
export function authUseClient<Profile = unknown>(): AuthVanillaClient.IClient<Profile> {
  return useAuthCtx<Profile>().client
}

export namespace AuthReactClient {
  export interface IProviderProps extends AuthVanillaClient.IConfig {
    children?: ReactNode
    /** Optional pre-built client; overrides cfg. */
    client?: AuthVanillaClient.IClient<unknown>
    /** Disable the initial automatic /session fetch on mount. */
    noInitialFetch?: boolean
  }

  export interface IUseSessionResult<Profile = unknown> {
    data: AuthVanillaClient.ISessionResult<Profile>
    status: 'loading' | 'authed' | 'guest'
    refresh(): Promise<AuthVanillaClient.ISessionResult<Profile>>
  }

  export interface IMutationResult<I, O> {
    mutate(input: I): Promise<O>
    loading: boolean
    error: unknown | null
  }
}
