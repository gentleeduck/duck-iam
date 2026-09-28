import type { AppAuth } from '@examples/duck-auth-shared/auth'
import { csrfGuard } from '@gentleduck/auth/core'
import { callerContext } from '@gentleduck/auth/server/generic'
import type { Server } from 'bun'

export type Handler<R extends Request = Request> = (req: R, server: Server<unknown>) => Promise<Response>

/** Bun.serve has no middleware, so a route that takes the CSRF guard is wrapped in it. */
export function guarded<R extends Request>(auth: AppAuth, handler: Handler<R>): Handler<R> {
  return async (req, server) => {
    await csrfGuard(auth, req)
    return handler(req, server)
  }
}

/** The caller's address and browser, for the session row and the hijack checks. */
export function caller(req: Request, server: Server<unknown>) {
  return callerContext({ ip: server.requestIP(req)?.address, userAgent: req.headers.get('user-agent') })
}
