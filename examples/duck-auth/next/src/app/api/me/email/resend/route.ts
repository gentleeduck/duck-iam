import { PAGES } from '@examples/duck-auth-shared/auth'
import { signedIn } from '@examples/duck-auth-shared/session'
import { auth, route } from '@/auth'

export const POST = route(async (req) => {
  const { identity } = await signedIn(auth, req.headers)
  return Response.json(
    await auth.flows.requestEmailVerification({ identityId: identity.id, callbackPath: PAGES.verifyEmail }),
  )
})
