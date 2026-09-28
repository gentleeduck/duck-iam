import { readString } from '@examples/duck-auth-shared/body'
import { readBodyJson } from '@gentleduck/auth/server/generic'
import { auth, route } from '@/auth'

export const POST = route(async (req) => {
  const token = readString(await readBodyJson(req), 'token') ?? ''
  const { identityId } = await auth.flows.completeEmailVerification({ token })
  return Response.json({ identityId })
})
