import type { Identities } from '~/core/identities/identities.types'
import type { Sessions } from '~/core/sessions/sessions.types'
import type { RequestSecurityOptions } from '~/server/generic'

/** The `@grpc/grpc-js` surface the adapter touches, kept local so the package needs no dependency on it. */
export namespace GrpcAdapter {
  export type UnaryHandler<Req = unknown, Res = unknown> = (
    call: GrpcAdapter.UnaryCall<Req>,
    callback: GrpcAdapter.Callback<Res>,
  ) => void

  export type UnaryCall<Req = unknown> = {
    metadata: GrpcAdapter.Metadata
    request: Req
    /** Mutation slots for the interceptor; downstream handlers read them. Null until the interceptor resolves a session. */
    session: Sessions.Me | null
    identity: Identities.Me | null
  }

  export type Callback<Res = unknown> = (
    error: { code: number; message: string; metadata?: GrpcAdapter.Metadata } | null,
    response?: Res,
  ) => void

  /** `getCaller` is the opt-in: without it the wrapper resolves a session and refuses nothing extra;
   *  with it, every call's fingerprint is compared with the session's and the hijack policy runs. */
  export type WithGrpcOptions<Req = unknown> = {
    /** Refuse with UNAUTHENTICATED when nothing resolves. Default `true`. */
    required?: boolean
    /** Metadata key holding the token. Default `authorization`. */
    headerName?: string
    /** Read the call's fingerprint; `grpcCaller` reads the user agent. */
    getCaller?: (call: GrpcAdapter.UnaryCall<Req>) => { ip?: string; userAgent?: string }
    /** Handle drift yourself, including the `'rotate'` reaction the wrapper cannot perform. */
    onHijack?: RequestSecurityOptions['onHijack']
  }

  export type Metadata = {
    get(key: string): Array<string | Buffer>
    set(key: string, value: string | Buffer): void
  }
}
