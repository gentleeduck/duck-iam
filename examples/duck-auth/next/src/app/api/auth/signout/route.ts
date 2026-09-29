import { signOut } from '@examples/duck-auth-shared/routes'
import { executeIntents } from '@gentleduck/auth/server/generic'
import { auth, route } from '@/auth'

export const POST = route(async (req) => executeIntents(await signOut(auth, req.headers)))
