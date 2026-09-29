import { signIn } from '@examples/duck-auth-shared/routes'
import { executeIntents, readBodyJson } from '@gentleduck/auth/server/generic'
import { nextCaller } from '@gentleduck/auth/server/next'
import { auth, route } from '@/auth'

export const POST = route(async (req) =>
  executeIntents(await signIn(auth, req.headers, await readBodyJson(req), nextCaller(req))),
)
