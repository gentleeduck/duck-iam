/**
 * @packageDocumentation
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

/**
 * React client - hooks + provider wrapping the vanilla AuthClient. Keeps
 * React itself as a peerDep so the auth core has no React in its graph.
 *
 * @example
 * ```tsx
 * import { AuthProvider, useSession, useSignIn } from '@gentleduck/auth/client/react'
 *
 * <AuthProvider baseUrl="/auth">
 *   <App />
 * </AuthProvider>
 *
 * function SignIn() {
 *   const signIn = useSignIn()
 *   return <button onClick={() => signIn.mutate({ providerId: 'password', input: { ... } })}>...</button>
 * }
 * ```
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
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
import {
  type AuthClient,
  type AuthClientConfig,
  createAuthClient,
  type SessionResult,
  type SignInOptions,
  type SignInResult,
} from '../vanilla'

// --- context ----------------------------------------------------------

interface AuthContextValue<Profile = unknown> {
  client: AuthClient<Profile>
  state: SessionResult<Profile>
  status: 'loading' | 'authed' | 'guest'
  refresh(): Promise<SessionResult<Profile>>
}

const AuthContext = createContext<AuthContextValue<unknown> | null>(null)

export interface AuthProviderProps extends AuthClientConfig {
  children: ReactNode
  /** Optional pre-built client; overrides cfg. */
  client?: AuthClient<unknown>
  /** Disable the initial automatic /session fetch on mount. */
  noInitialFetch?: boolean
}

/**
 * `AuthProvider`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function AuthProvider(props: AuthProviderProps): ReturnType<typeof createElement> {
  const { children, client: externalClient, noInitialFetch, ...cfg } = props
  const client = useMemo(() => externalClient ?? createAuthClient(cfg), [externalClient, cfg.baseUrl])
  const [state, setState] = useState<SessionResult<unknown>>({ session: null, identity: null })
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

export interface UseSessionResult<Profile = unknown> {
  data: SessionResult<Profile>
  status: 'loading' | 'authed' | 'guest'
  refresh(): Promise<SessionResult<Profile>>
}

/**
 * `useSession`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function useSession<Profile = unknown>(): UseSessionResult<Profile> {
  const ctx = useAuthCtx<Profile>()
  return { data: ctx.state, status: ctx.status, refresh: ctx.refresh }
}

export interface MutationResult<I, O> {
  mutate(input: I): Promise<O>
  loading: boolean
  error: unknown | null
}

function useMutation<I, O>(fn: (input: I) => Promise<O>): MutationResult<I, O> {
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

/**
 * `useSignIn`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function useSignIn<Profile = unknown>(): MutationResult<SignInOptions, SignInResult<Profile>> {
  const { client } = useAuthCtx<Profile>()
  return useMutation((opts: SignInOptions) => client.signIn(opts))
}

/**
 * `useSignOut`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function useSignOut(): MutationResult<void, { ok: true }> {
  const { client } = useAuthCtx()
  return useMutation(() => client.signOut())
}

/**
 * `useBeginProvider`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function useBeginProvider(): MutationResult<{ id: string; input?: unknown }, { body: unknown }> {
  const { client } = useAuthCtx()
  return useMutation(({ id, input }) => client.beginProvider(id, input))
}

/**
 * `useAuthClient`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function useAuthClient<Profile = unknown>(): AuthClient<Profile> {
  return useAuthCtx<Profile>().client
}

/**
 * Namespace merge for ReactClient. Co-locates the config + input +
 * output shapes via TS namespace declaration. Consumers can write either
 * the flat name (AuthProviderProps) or the namespaced form
 * (ReactClient.IProviderProps); both resolve to the same type.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace ReactClient {
  /** Alias for the flat `AuthProviderProps` type. */
  export type IProviderProps = AuthProviderProps
  /** Alias for the flat `UseSessionResult<Profile = unknown>` type. */
  export type IUseSessionResult<Profile = unknown> = UseSessionResult<Profile>
  /** Alias for the flat `MutationResult<I, O>` type. */
  export type IMutationResult<I, O> = MutationResult<I, O>
}
