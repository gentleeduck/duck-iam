import { currentSession } from '@examples/duck-iam-shared/routes'
import { jsonResponse } from '@gentleduck/auth/server/generic'
import { auth, route } from '@/auth'

export const GET = route(async (req) => jsonResponse(200, await currentSession(auth, req.headers)))
