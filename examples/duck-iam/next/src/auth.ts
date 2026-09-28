import { buildAuth } from '@examples/duck-iam-shared/auth'
import { errorResponse } from '@gentleduck/auth/server/generic'
import { withNextCsrf } from '@gentleduck/auth/server/next'
import { db } from './db'

export const auth = buildAuth(db)

/** This app's own routes: CSRF-guarded, and a refusal answered with its code rather than Next's 500. */
export function route<Args extends [Request, ...unknown[]]>(
  handler: (...args: Args) => Promise<Response>,
): (...args: Args) => Promise<Response> {
  return withNextCsrf(auth, async (...args) => {
    try {
      return await handler(...args)
    } catch (err) {
      const res = errorResponse(err)
      if (res.status === 500) console.error(err)
      return res
    }
  })
}
