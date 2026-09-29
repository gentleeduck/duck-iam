import { providerCallback } from '@examples/duck-auth-shared/routes'
import { errorResponse, executeIntents, readBodyText } from '@gentleduck/auth/server/generic'
import { nextCaller } from '@gentleduck/auth/server/next'
import { auth } from '@/auth'

/** Where the IdP returns the browser; never guarded. Apple's form post is read as text, the same query string a
 *  redirect carries. */
async function callback(req: Request, { params }: { params: Promise<{ id: string }> }): Promise<Response> {
  try {
    const query =
      req.method === 'POST' ? new URLSearchParams((await readBodyText(req)) ?? '') : new URL(req.url).searchParams
    return executeIntents(await providerCallback(auth, (await params).id, query, req.headers, nextCaller(req)))
  } catch (err) {
    return errorResponse(err)
  }
}

export { callback as GET, callback as POST }
