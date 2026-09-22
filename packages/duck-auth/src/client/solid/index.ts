/** Context and signals over the vanilla client; `solid-js` is an optional peerDep. Types live in `./types`. */
import { createContext, createMemo, createSignal, type JSX, onCleanup, onMount, useContext } from 'solid-js'
import { AuthError } from '~/core/errors'
import type { Envelope } from '~/core/errors/errors.types'
import type { Identities } from '~/core/identities'
import { createAuthClient, type VanillaClient } from '../vanilla'
import type { SolidClient } from './types'

export type { SolidClient } from './types'

const AuthContext = createContext<SolidClient.Context<Identities.ProfileMetadataBase> | null>(null)

/** Puts an auth client on the Solid context. Every primitive below reads it. */
export function Provider<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase>(
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
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(): SolidClient.Context<Profile> {
  const ctx = useContext(AuthContext) as SolidClient.Context<Profile> | null
  if (!ctx) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: '[@gentleduck/auth/client/solid] use* hooks must be used inside <Provider>',
    })
  }
  return ctx
}

/** The current session, refetched when the client says it changed. */
export function authUseSession<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
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

/** Signs in through a provider. */
export function authUseSignIn<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(): SolidClient.MutationResult<VanillaClient.SignInOptions, Envelope<VanillaClient.SessionResult<Profile>, string>> {
  const { client } = useAuthCtx<Profile>()
  return useMutation((opts: VanillaClient.SignInOptions) => client.signIn(opts))
}

/** Signs the current session out. */
export function authUseSignOut(): SolidClient.MutationResult<void, Envelope<unknown, string>> {
  const { client } = useAuthCtx()
  return useMutation(() => client.signOut())
}

/** The client on the context, for a call no primitive covers. */
export function authUseClient<
  Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase,
>(): VanillaClient.Client<Profile> {
  return useAuthCtx<Profile>().client
}
