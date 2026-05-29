/**
 * @packageDocumentation
 * gRPC server adapter. gRPC is binary + bidirectional; the auth lib
 * exposes the AuthRoot flows over standard unary RPCs by wrapping the
 * service handlers in interceptors that:
 *   - extract a bearer token from the `authorization` metadata
 *   - resolve the session via auth.resolveSession
 *   - attach session + identity onto the call context for handler use
 *
 * The actual `@grpc/grpc-js` server is lazy-loaded as a peerDep; this
 * module ships the interceptor + handler factories only.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import type { AuthRoot } from '../../core/auth'
import { AuthErrorObject } from '../../core/errors'
import type { Identity } from '../../core/types/identity'
import type { Session } from '../../core/types/session'

/**
 * Narrow subset of `@grpc/grpc-js` Metadata we need.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface GrpcMetadataLike {
  get(key: string): Array<string | Buffer>
  set(key: string, value: string | Buffer): void
}

/**
 * Narrow subset of `@grpc/grpc-js` ServerUnaryCall. The library uses
 * the same `metadata` + `getPeer` for every call type so this same
 * shape covers all four streaming directions.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface GrpcUnaryCallLike<Req = unknown> {
  metadata: GrpcMetadataLike
  request: Req
  /** Mutation slots for the interceptor; downstream handlers read them. */
  session?: Session.ISession
  identity?: Identity.IIdentity<unknown> | null
}

export type GrpcCallback<Res = unknown> = (
  error: { code: number; message: string; metadata?: GrpcMetadataLike } | null,
  response?: Res,
) => void

/** gRPC unary handler signature. */
export type GrpcUnaryHandler<Req = unknown, Res = unknown> = (
  call: GrpcUnaryCallLike<Req>,
  callback: GrpcCallback<Res>,
) => void

/**
 * Subset of gRPC status codes we map AuthErrorObject onto. Mirrors
 * `grpc.status.*` enum without forcing the peerDep on consumers that
 * just want the auth wrapper.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export const GRPC_STATUS = {
  OK: 0,
  CANCELLED: 1,
  UNKNOWN: 2,
  INVALID_ARGUMENT: 3,
  DEADLINE_EXCEEDED: 4,
  NOT_FOUND: 5,
  ALREADY_EXISTS: 6,
  PERMISSION_DENIED: 7,
  RESOURCE_EXHAUSTED: 8,
  FAILED_PRECONDITION: 9,
  ABORTED: 10,
  OUT_OF_RANGE: 11,
  UNIMPLEMENTED: 12,
  INTERNAL: 13,
  UNAVAILABLE: 14,
  DATA_LOSS: 15,
  UNAUTHENTICATED: 16,
} as const

/**
 * Map an HTTP status (the shape AuthError.status carries) onto the
 * closest gRPC status code per the gRPC HTTP gateway convention.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function httpStatusToGrpc(status: number): number {
  if (status === 401) return GRPC_STATUS.UNAUTHENTICATED
  if (status === 403) return GRPC_STATUS.PERMISSION_DENIED
  if (status === 404) return GRPC_STATUS.NOT_FOUND
  if (status === 409) return GRPC_STATUS.ABORTED
  if (status === 410) return GRPC_STATUS.NOT_FOUND
  if (status === 423 || status === 429) return GRPC_STATUS.RESOURCE_EXHAUSTED
  if (status === 503) return GRPC_STATUS.UNAVAILABLE
  if (status >= 500) return GRPC_STATUS.INTERNAL
  if (status >= 400) return GRPC_STATUS.INVALID_ARGUMENT
  return GRPC_STATUS.OK
}

/**
 * Wrap a unary handler with authentication. The wrapper:
 *   - reads `authorization: Bearer <token>` (or `bearer-token` /
 *     `x-api-key` per `headerName` config) from the call metadata
 *   - calls `auth.resolveSession` and attaches `call.session` +
 *     `call.identity`
 *   - when `required: true` (default) AND no session resolves, replies
 *     with UNAUTHENTICATED via the callback (handler not invoked)
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export function withAuth<Req, Res>(
  auth: AuthRoot,
  handler: GrpcUnaryHandler<Req, Res>,
  opts: { required?: boolean; headerName?: string } = {},
): GrpcUnaryHandler<Req, Res> {
  const required = opts.required ?? true
  const headerName = opts.headerName ?? 'authorization'
  return (call, callback) => {
    void (async () => {
      try {
        const headers = metadataToHeaders(call.metadata, headerName)
        const resolved = await auth.resolveSession({ headers })
        if (!resolved) {
          if (required) {
            callback({
              code: GRPC_STATUS.UNAUTHENTICATED,
              message: 'AUTH/UNAUTHENTICATED',
            })
            return
          }
        } else {
          call.session = resolved.session
          call.identity = resolved.identity
        }
        handler(call, callback)
      } catch (err) {
        if (err instanceof AuthErrorObject) {
          callback({
            code: httpStatusToGrpc(err.status),
            message: err.code,
          })
          return
        }
        callback({ code: GRPC_STATUS.INTERNAL, message: 'AUTH/MISCONFIGURED' })
      }
    })()
  }
}

/**
 * Translate a gRPC Metadata bag into a `Headers` object so
 * `auth.resolveSession` accepts it unchanged. Only the configured
 * `headerName` (and `cookie`, since some grpc-web bridges forward it)
 * are projected; metadata is otherwise small.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
function metadataToHeaders(metadata: GrpcMetadataLike, headerName: string): Headers {
  const out = new Headers()
  const auth = metadata.get(headerName)
  for (const v of auth) out.append(headerName, typeof v === 'string' ? v : v.toString('utf8'))
  const cookie = metadata.get('cookie')
  for (const v of cookie) out.append('cookie', typeof v === 'string' ? v : v.toString('utf8'))
  return out
}

/**
 * Namespace merge for the gRPC adapter surface.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace GrpcAdapter {
  /** Alias for `GrpcUnaryHandler`. */
  export type IUnaryHandler<Req = unknown, Res = unknown> = GrpcUnaryHandler<Req, Res>
  /** Alias for `GrpcUnaryCallLike`. */
  export type IUnaryCall<Req = unknown> = GrpcUnaryCallLike<Req>
  /** Alias for `GrpcCallback`. */
  export type ICallback<Res = unknown> = GrpcCallback<Res>
  /** Alias for `GrpcMetadataLike`. */
  export type IMetadata = GrpcMetadataLike
}
