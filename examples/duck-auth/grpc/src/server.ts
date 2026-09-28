import { buildAuth } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { AuthError } from '@gentleduck/auth/core'
import { bearerTransport } from '@gentleduck/auth/core/transport'
import { errorToHttp } from '@gentleduck/auth/server/generic'
import { type GrpcAdapter, grpcCaller, httpStatusToGrpc, withGrpc } from '@gentleduck/auth/server/grpc'
import { Server, ServerCredentials } from '@grpc/grpc-js'
import { db } from './db'
import { authService } from './proto'

// A gRPC caller holds its token itself, so this backend issues bearer tokens rather than cookies.
const auth = buildAuth(db, bearerTransport())

/** grpc-js handlers take a callback; this runs an async one and answers an AuthError with its gRPC status,
 *  anything else as INTERNAL. `errorToHttp` logs the cause of either kind of 5xx. */
function unary<Res>(fn: (call: GrpcAdapter.UnaryCall) => Promise<Res>): GrpcAdapter.UnaryHandler<unknown, Res> {
  return (call, callback) => {
    fn(call).then(
      (res) => callback(null, res),
      (err) => {
        const { status } = errorToHttp(err)
        callback({ code: httpStatusToGrpc(status), message: err instanceof AuthError ? err.code : 'internal error' })
      },
    )
  }
}

/** The raw token: sign-out and step-up take it, where `withGrpc` keeps only the session it resolves to. */
function tokenOf(call: GrpcAdapter.UnaryCall): string {
  const headers = new Headers(call.metadata.get('authorization').map((v) => ['authorization', v.toString()]))
  const sid = auth.transport.extract({ headers })
  if (!sid) throw new AuthError('AUTH_UNAUTHENTICATED')
  return sid
}

const server = new Server()
server.addService(authService, {
  SignIn: unary(async ({ request }) => {
    const input = { email: readString(request, 'email'), password: readString(request, 'password') }
    const { sid, session } = await auth.flows.signIn({ providerId: 'password', input })
    if (!session) throw new AuthError('AUTH_UNAUTHENTICATED')
    return { token: sid, expiresAt: session.expiresAt.toISOString() }
  }),

  VerifyMfa: withGrpc(
    auth,
    unary(async (call) => {
      const code = readString(call.request, 'code') ?? ''
      const currentSid = tokenOf(call)
      const { sid, session } = await auth.flows.completeStepUp({
        currentSid,
        method: /^\d{6}$/.test(code) ? 'totp' : 'backup-code',
        code,
        ...grpcCaller(call),
      })
      // The caller swaps in the new token, so the one-factor one goes, as `stepUp()` does for a cookie.
      await auth.sessions.revoke(currentSid)
      return { token: sid, expiresAt: session.expiresAt.toISOString() }
    }),
  ),

  // `withGrpc` has already refused a call with no live session and put this one's on the call.
  Me: withGrpc(
    auth,
    unary(async ({ session, identity }) => {
      if (!session || !identity) throw new AuthError('AUTH_UNAUTHENTICATED')
      if (session.aal < 2 && (await auth.mfa.hasTotp(identity.id))) {
        throw new AuthError('AUTH_STEP_UP_REQUIRED', { challenge: { methods: ['totp', 'backup-code'] } })
      }
      const { email, name } = identity.profile
      return { id: identity.id, email, name, emailVerified: identity.emailVerified, aal: session.aal }
    }),
  ),

  SignOut: withGrpc(
    auth,
    unary(async (call) => {
      await auth.flows.signOut(tokenOf(call))
      return {}
    }),
  ),
})

const port = Number(process.env.PORT ?? 4900)
server.bindAsync(`0.0.0.0:${port}`, ServerCredentials.createInsecure(), (err) => {
  if (err) throw err
  console.log(`duck-auth grpc example on localhost:${port}`)
})
