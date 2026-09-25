/** gRPC server adapter: interceptors that pull a bearer token off the `authorization` metadata, resolve the
 *  session, and attach it and its identity to the call context. `@grpc/grpc-js` is never imported, only
 *  structurally typed, so only the interceptor and handler factories ship here. */

import { withResolvedActor } from '~/core/actor'
import type { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import { type CallerFingerprint, callerContext, requestSecurity } from '../generic'

import type { GrpcAdapter } from './grpc.types'
/** The gRPC status codes an AuthError maps onto, mirroring `grpc.status.*` so the package needs no
 *  dependency on `@grpc/grpc-js`. */
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

/** Wrap a unary handler with authentication: read the token from the call metadata under `headerName`, resolve
 *  it onto `call.session` and `call.identity`, and under the default `required: true` answer UNAUTHENTICATED
 *  without invoking the handler when nothing resolves. */
export function withGrpc<Req, Res>(
  auth: AuthEngine,
  handler: GrpcAdapter.UnaryHandler<Req, Res>,
  opts: GrpcAdapter.WithGrpcOptions<Req> = {},
): GrpcAdapter.UnaryHandler<Req, Res> {
  const required = opts.required ?? true
  const headerName = opts.headerName ?? 'authorization'
  return (call, callback) => {
    void (async () => {
      try {
        const headers = metadataToHeaders(call.metadata, headerName)
        // The same opt-in the seven HTTP adapters take: no `getCaller` means no fingerprint, so nothing is
        // compared and a deployment that did not ask keeps the behaviour it had.
        const security = requestSecurity(auth, {
          caller: opts.getCaller?.(call),
          onAnomaly: opts.onAnomaly,
          onHijack: opts.onHijack,
        })
        const resolved = await auth
          .resolveSession(
            { headers },
            security.requestSnapshot ? { requestSnapshot: security.requestSnapshot } : undefined,
          )
          .orNull()
        if (!resolved) {
          if (required) {
            callback({
              code: GRPC_STATUS.UNAUTHENTICATED,
              message: 'AUTH_UNAUTHENTICATED',
            })
            return
          }
          handler(call, callback)
          return
        }
        call.session = resolved.session
        // Adapter is profile-agnostic; store the resolved identity opaquely.
        call.identity = resolved.identity as GrpcAdapter.UnaryCall['identity']
        // Bound here rather than in a separate wrapper: the session is already
        // resolved, and a write the handler drives records a `null` actor
        // without it. The handler starts synchronously inside the scope, so its
        // async continuations inherit the binding.
        await withResolvedActor(
          resolved.session,
          async () => {
            handler(call, callback)
          },
          security.onSession ? { onSession: security.onSession } : {},
          resolved.anomaly,
        )
      } catch (err) {
        if (err instanceof AuthError) {
          callback({
            code: httpStatusToGrpc(err.status),
            message: err.code,
          })
          return
        }
        callback({ code: GRPC_STATUS.INTERNAL, message: 'AUTH_MISCONFIGURED' })
      }
    })()
  }
}

/** The request fingerprint gRPC carries. Only the user agent: `Metadata` holds no address, and the peer
 *  is on the call object the runtime owns, so a host that resolves one passes its own `getCaller`. */
export function grpcCaller(call: { metadata: GrpcAdapter.Metadata }): CallerFingerprint {
  const [ua] = call.metadata.get('user-agent')
  return callerContext({ userAgent: typeof ua === 'string' ? ua : ua?.toString('utf8') })
}

/** Project a gRPC Metadata bag into `Headers` so `auth.resolveSession` takes it unchanged. Only `headerName`
 *  and `cookie` carry over, the latter because some grpc-web bridges forward it. */
function metadataToHeaders(metadata: GrpcAdapter.Metadata, headerName: string): Headers {
  const out = new Headers()
  const auth = metadata.get(headerName)
  for (const v of auth) out.append(headerName, typeof v === 'string' ? v : v.toString('utf8'))
  const cookie = metadata.get('cookie')
  for (const v of cookie) out.append('cookie', typeof v === 'string' ? v : v.toString('utf8'))
  return out
}

export type { GrpcAdapter } from './grpc.types'
