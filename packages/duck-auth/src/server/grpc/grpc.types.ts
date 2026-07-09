import type { Identity } from '~/core/identities/identities.types'
import type { Session } from '~/core/sessions/sessions.types'

export namespace GrpcAdapter {
  export type UnaryHandler<Req = unknown, Res = unknown> = (
    call: GrpcAdapter.UnaryCall<Req>,
    callback: GrpcAdapter.Callback<Res>,
  ) => void

  export type UnaryCall<Req = unknown> = {
    metadata: GrpcAdapter.Metadata
    request: Req
    /** Mutation slots for the interceptor; downstream handlers read them. Null until the interceptor resolves a session. */
    session: Session.Me | null
    identity: Identity.Me | null
  }

  export type Callback<Res = unknown> = (
    error: { code: number; message: string; metadata?: GrpcAdapter.Metadata } | null,
    response?: Res,
  ) => void

  export type Metadata = {
    get(key: string): Array<string | Buffer>
    set(key: string, value: string | Buffer): void
  }
}
