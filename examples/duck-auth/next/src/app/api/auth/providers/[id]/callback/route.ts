import { landing } from '@examples/duck-auth-shared/auth'
import { errorResponse, executeIntents, oauthCallback } from '@gentleduck/auth/server/generic'
import { nextCaller } from '@gentleduck/auth/server/next'
import { auth } from '@/auth'

/** Where the IdP returns the browser; the cookies land, then the app takes over. */
async function callback(req: Request, { params }: { params: Promise<{ id: string }> }): Promise<Response> {
  try {
    const body = req.method === 'POST' ? await req.text() : undefined
    const request = { body, cookie: req.headers.get('cookie'), method: req.method, url: req.url }
    const intents = await landing(oauthCallback(auth, (await params).id, request, nextCaller(req)))
    return executeIntents(intents)
  } catch (err) {
    return errorResponse(err)
  }
}

export { callback as GET, callback as POST }
