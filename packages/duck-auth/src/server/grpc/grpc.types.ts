import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import type { ActorOptions } from '~/server/generic'

/** The `@grpc/grpc-js` surface the adapter touches, kept local so the package needs no dependency on it. */
export namespace GrpcAdapter {
  /** A grpc-js unary handler. */
  export type UnaryHandler<Req = unknown, Res = unknown> = (
    call: GrpcAdapter.UnaryCall<Req>,
    callback: GrpcAdapter.Callback<Res>,
  ) => void

  /** A grpc-js unary call. */
  export type UnaryCall<Req = unknown> = {
    metadata: GrpcAdapter.Metadata
    request: Req
    /** Set once a session resolves, for the handler to read. */
    session?: Sessions.Me
    identity?: Identities.Me | null
  }

  /** The grpc-js unary callback. */
  export type Callback<Res = unknown> = (error: { code: number; message: string } | null, response?: Res) => void

  /** {@link ActorOptions}, plus whether a call without a session is refused and where its token is read. */
  export type WithGrpcOptions<Req = unknown> = ActorOptions<GrpcAdapter.UnaryCall<Req>> & {
    /** Refuse with UNAUTHENTICATED when nothing resolves. Default `true`. */
    required?: boolean
    /** Metadata key holding the token. Default `authorization`. */
    headerName?: string
  }

  /** grpc-js call metadata, read by key. */
  export type Metadata = {
    get(key: string): Array<string | Buffer>
  }
}
