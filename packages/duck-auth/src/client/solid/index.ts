/** Solid client - context + signals; `solid-js` is an OPTIONAL peerDep. Types live in `./types`. */
import { createContext, createMemo, createSignal, type JSX, onCleanup, onMount, useContext } from 'solid-js'
import type { Identity } from '../../core'
import type { Envelope } from '../../core/types/session'
import { createAuthClient, type VanillaClient } from '../vanilla'
import type { SolidClient } from './types'

export type { SolidClient } from './types'

const AuthContext = createContext<SolidClient.Context<Identity.ProfileMetadataBase> | null>(null)

/** `AuthProvider`. */
export function AuthProvider<Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase>(
  props: SolidClient.IProviderProps<Profile>,
): JSX.Element {
  const client = props.client ?? createAuthClient(props)
  const [state, setState] = createSignal<VanillaClient.SessionResult<Profile>>({
    identity: null,
    session: null,
  })
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

  const ctxVal: SolidClient.Context<Profile> = {
    client,
    refresh: () => client.refresh(),
    state,
    status,
  }

  return AuthContext.Provider({ children: props.children, value: ctxVal })
}

function useAuthCtx<
  Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
>(): SolidClient.Context<Profile> {
  const ctx = useContext(AuthContext) as SolidClient.Context<Profile> | null
  if (!ctx) {
    throw new Error('[@gentleduck/AUTH/client/solid] use* hooks must be used inside <AuthProvider>')
  }
  return ctx
}

/** `authUseSession`. */
export function authUseSession<
  Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
>(): SolidClient.UseSessionResult<Profile> {
  const ctx = useAuthCtx<Profile>()
  return { data: ctx.state, refresh: ctx.refresh, status: ctx.status }
}

function useMutation<I, O>(fn: (input: I) => Promise<O>): SolidClient.MutationResult<I, O> {
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
export function authUseSignIn<
  Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
>(): SolidClient.MutationResult<VanillaClient.SignInOptions, Envelope<VanillaClient.SessionResult<Profile>, string>> {
  const { client } = useAuthCtx<Profile>()
  return useMutation((opts: VanillaClient.SignInOptions) => client.signIn(opts))
}

/** `authUseSignOut`. */
export function authUseSignOut(): SolidClient.MutationResult<void, Envelope<Record<string, never>, string>> {
  const { client } = useAuthCtx()
  return useMutation(() => client.signOut())
}

/** `authUseClient`. */
export function authUseClient<
  Profile extends Identity.ProfileMetadataBase = Identity.ProfileMetadataBase,
>(): VanillaClient.Client<Profile> {
  return useAuthCtx<Profile>().client
}
