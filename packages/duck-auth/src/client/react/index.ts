/**
 * React client: hooks + provider wrapping the vanilla AuthClient. Keeps React
 * as a peerDep so the auth core has no React in its graph. Types live in
 * `./types`.
 *
 * @example
 * ```tsx
 * import { Provider, useSession, useSignIn } from '@gentleduck/AUTH/client/react'
 *
 * <Provider baseUrl="/auth">
 *   <App />
 * </Provider>
 *
 * function SignIn() {
 *   const signIn = useSignIn()
 *   return <button onClick={() => signIn.mutate({ providerId: 'password', input: { ... } })}>...</button>
 * }
 * ```
 */
import { createContext, createElement, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import type { Envelope } from '~/core/errors/errors.types'
import type { Identities } from '~/core/identities'
import { createAuthClient, type VanillaClient } from '../vanilla'
import type { ReactClient } from './types'

export type { ReactClient } from './types'

// --- context ----------------------------------------------------------

const AuthContext = createContext<ReactClient.ContextValue<Identities.ProfileMetadataBase> | null>(null)

/** `Provider`. */
export function Provider<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
  props: ReactClient.IProviderProps<Profile>,
): ReturnType<typeof createElement> {
  const { children, client: externalClient, noInitialFetch, ...cfg } = props
  // biome-ignore lint/correctness/useExhaustiveDependencies: cfg is a destructured spread; only baseUrl matters for client identity.
  const client = useMemo(() => externalClient ?? createAuthClient<Profile>(cfg), [externalClient, cfg.baseUrl])
  const [state, setState] = useState<VanillaClient.SessionResult<Profile>>({ session: null, identity: null })
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

  const value: ReactClient.ContextValue<Profile> = useMemo(
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

function useAuthCtx<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(): ReactClient.ContextValue<Profile> {
  const ctx = useContext(AuthContext) as ReactClient.ContextValue<Profile> | null
  if (!ctx) {
    throw new Error('[@gentleduck/AUTH/client/react] use* hooks must be used inside <Provider>')
  }
  return ctx
}

// --- hooks ------------------------------------------------------------

function useMutation<I, O>(fn: (input: I) => Promise<O>): ReactClient.MutationResult<I, O> {
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

/** `useSession`. */
export function useSession<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(): ReactClient.UseSessionResult<Profile> {
  const ctx = useAuthCtx<Profile>()
  return { data: ctx.state, status: ctx.status, refresh: ctx.refresh }
}

/** `useSignIn`. */
export function useSignIn<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(): ReactClient.MutationResult<VanillaClient.SignInOptions, Envelope<VanillaClient.SessionResult<Profile>, string>> {
  const { client } = useAuthCtx<Profile>()
  return useMutation((opts: VanillaClient.SignInOptions) => client.signIn(opts))
}

/**
 * `useSignUp`. Registration is app-shaped, so `Input` is caller-typed and the
 * result echoes the response `data`. Does not create a session.
 */
export function useSignUp<
  Input extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(): ReactClient.MutationResult<Input, Envelope<unknown, string>> {
  const { client } = useAuthCtx()
  return useMutation((input: Input) => client.signUp(input))
}

/** `useSignOut`. */
export function useSignOut(): ReactClient.MutationResult<void, Envelope<Record<string, never>, string>> {
  const { client } = useAuthCtx()
  return useMutation(() => client.signOut())
}

/** `useBeginProvider`. */
export function useBeginProvider(): ReactClient.MutationResult<
  { id: string; input?: unknown },
  Envelope<unknown, string>
> {
  const { client } = useAuthCtx()
  return useMutation(({ id, input }) => client.beginProvider(id, input))
}

/** `useAuthClient`. */
export function useAuthClient<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(): VanillaClient.Client<Profile> {
  return useAuthCtx<Profile>().client
}
