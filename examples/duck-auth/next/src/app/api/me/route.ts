import { signedIn } from '@examples/duck-auth-shared/session'
import { auth, route } from '@/auth'

export const GET = route(async (req) => {
  const { identity, session, totp } = await signedIn(auth, req.headers)
  const view = { id: session.id, aal: session.aal, expiresAt: session.expiresAt }
  return Response.json({ identity, totp, session: view }, { headers: { 'cache-control': 'no-store' } })
})
