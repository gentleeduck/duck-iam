import { signUp } from '@examples/duck-auth-shared/signup'
import { readBodyJson } from '@gentleduck/auth/server/generic'
import { auth, route } from '@/auth'

export const POST = route(async (req) => Response.json(await signUp(auth, await readBodyJson(req)), { status: 201 }))
