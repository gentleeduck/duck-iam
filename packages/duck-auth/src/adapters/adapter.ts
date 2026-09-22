import type { Credential } from '~/core/credentials/credentials.types'
import { AuthError, type ErrorMap } from '~/core/errors'
import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'

/** The contract every adapter meets: three stores, each answering with the row or throwing. */
export namespace Adapter {
  /** The three stores an adapter hands the engine, whatever it is built on. */
  export type Me<Profile extends Identities.ProfileMetadataBase = Identities.ProfileMetadataBase> = {
    identities: Identities.Store<Profile>
    credentials: Credential.Store
    sessions: Sessions.Store
    /** Every facet rebound onto `client`, a driver transaction handle, as one adapter. Absent means this
     *  adapter has no transactional driver, and `withTransaction` refuses. */
    withClient?(client: unknown): Me<Profile>
  }
}

/** The class every adapter extends: it hands its driver's error mapper to `super` and calls through `run`. */
export abstract class AdapterStore<C extends AuthError.Code = 'AUTH_ADAPTER_FAILED'> {
  constructor(protected readonly toError: ErrorMap<C>) {}

  /** The call, with whatever its driver threw mapped onto a code this package declares. */
  protected async run<T>(call: () => Promise<T>): Promise<T> {
    try {
      // A thunk, not a promise: a query builder can throw while it is still being built, inside the executor.
      return await call()
    } catch (err) {
      const typed = this.toError(err)
      // SECURITY: a code the map never declared is re-labelled, not passed off as one it did, so a store
      // cannot forge an outcome the engine branches on. Iterated and not `codes.has(typed.code)`, because a
      // `ReadonlySet<C>` refuses a wider argument.
      for (const code of this.toError.codes) if (code === typed.code) throw typed

      throw new AuthError('AUTH_ADAPTER_FAILED')
    }
  }
}
