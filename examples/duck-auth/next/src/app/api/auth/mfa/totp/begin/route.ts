import { signedIn } from '@examples/duck-auth-shared/session'
import { auth, route } from '@/auth'

export const POST = route(async (req) => {
  const { identity, session } = await signedIn(auth, req.headers)
  return Response.json(await auth.mfa.beginTotpEnrollment(identity.id, identity.profile.email, session))
})
