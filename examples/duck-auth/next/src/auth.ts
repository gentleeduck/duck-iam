import { buildAuth } from '@examples/duck-auth-shared/auth'
import { errorResponse } from '@gentleduck/auth/server/generic'
import { withNextCsrf } from '@gentleduck/auth/server/next'
import { db } from './db'

export const auth = buildAuth(db)

/** One of this app's own routes: CSRF-guarded, and a refusal answered with its code rather than Next's 500. */
export function route(handler: (req: Request) => Promise<Response>): (req: Request) => Promise<Response> {
  return withNextCsrf(auth, async (req) => {
    try {
      return await handler(req)
    } catch (err) {
      return errorResponse(err)
    }
  })
}
