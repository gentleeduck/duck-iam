import type { Credential } from '~/core/credentials/credentials.types'
import { AuthError, asAuthError, type ErrorMap, type Failed, GENERIC } from '~/core/errors'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'

/** The contract every adapter meets, and the shape every one of its calls answers in. */
export namespace Adapter {
  /** What `wrap` answers: the value, or the typed error awaiting the call would have thrown. */
  export type Result<T, Code extends AuthError.Code = AuthError.Faults> =
    | { readonly data: T; readonly error: null }
    // A code outside `Code` is re-labelled rather than smuggled through, so the union is always true.
    | { readonly data: null; readonly error: AuthError<Failed<Code>> }

  /** A call in flight. Awaiting it throws; `wrap()` takes the failure as a value, on a closed `Code`. */
  export interface Answer<T, Code extends AuthError.Code = AuthError.Faults> extends Promise<T> {
    /** Discriminated on `error`, so a call whose value is legitimately null still narrows. */
    wrap(): Promise<Result<T, Code>>
  }

  /** A store with `wrap` on every call. `Answer<T>` is a `Promise<T>`, so a `Wrapped<S>` still is an `S`. */
  export type Wrapped<S, Code extends AuthError.Code = AuthError.Faults> = {
    [K in keyof S]: S[K] extends (...args: infer A) => Promise<infer R> ? (...args: A) => Answer<R, Code> : S[K]
  }

  /** The three stores an adapter hands the engine, whatever it is built on. */
  export type Me<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> = {
    identities: Wrapped<Identities.Store<Profile>>
    credentials: Wrapped<Credential.Store>
    sessions: Wrapped<Sessions.Store>
    /** Every facet rebound onto `client` - a driver transaction handle - as one adapter. Absent means this
     *  adapter has no transactional driver, and `withTransaction` refuses. */
    withClient?(client: unknown): Me<Profile>
  }
}

/** Checked, not claimed: this is what makes {@link Adapter.Result}'s union true at runtime. */
function raises<C extends AuthError.Code>(err: AuthError, codes: ReadonlySet<C>): err is AuthError<C> {
  // NOTE: iterated, not `codes.has(err.code)` - a `ReadonlySet<C>` refuses a wider argument.
  for (const code of codes) if (code === err.code) return true

  return false
}

/** The class every adapter extends: it hands its driver's error mapper to `super` and calls through `run`. */
export abstract class AdapterStore<C extends AuthError.Code = 'AUTH_ADAPTER_FAILED'> {
  constructor(protected readonly toError: ErrorMap<C>) {}

  /** NOTE: not `async` - an async method would assimilate the answer and drop the `wrap` put on it. */
  protected run<T>(call: () => Promise<T>): Adapter.Answer<T, C> {
    // A thunk, not a promise: a query builder can throw while it is still being built, inside the executor.
    return AdapterStore.answer(new Promise<T>((resolve) => resolve(call())), this.toError)
  }

  /** The same answer for a promise that is not a store call's - a test double standing in for one. */
  static answer<T>(call: Promise<T>): Adapter.Answer<T, 'AUTH_ADAPTER_FAILED'>
  static answer<T, C extends AuthError.Code>(call: Promise<T>, toError: ErrorMap<C>): Adapter.Answer<T, C>
  static answer<T, C extends AuthError.Code>(
    call: Promise<T>,
    // Widened for the default alone: `GENERIC` answers with the label and nothing else, whatever `C` is.
    toError: ErrorMap<Failed<C>> = GENERIC,
  ): Adapter.Answer<T, C> {
    // NOTE: mapped once, onto a promise of ours - `wrap` would otherwise land on the caller's.
    const typed = call.then(
      (data) => data,
      (err: unknown) => {
        throw toError(err)
      },
    )

    return Object.assign(typed, {
      wrap: (): Promise<Adapter.Result<T, C>> =>
        typed.then(
          (data) => ({ data, error: null }),
          (thrown: unknown) => {
            const err = asAuthError(thrown, 'AUTH_ADAPTER_FAILED')

            // SECURITY: a code the map never declared is re-labelled, not passed off as one it did.
            return { data: null, error: raises(err, toError.codes) ? err : new AuthError('AUTH_ADAPTER_FAILED') }
          },
        ),
    })
  }
}
