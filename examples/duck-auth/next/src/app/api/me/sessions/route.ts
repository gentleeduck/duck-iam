import { signedIn } from '@examples/duck-auth-shared/session'
import { auth, route } from '@/auth'

export const GET = route(async (req) => {
  const { identity } = await signedIn(auth, req.headers)
  return Response.json(
    { sessions: await auth.sessions.listForIdentity(identity.id) },
    { headers: { 'cache-control': 'no-store' } },
  )
})
