import { signedIn } from '@examples/duck-auth-shared/session'
import { auth, route } from '@/auth'

export const POST = route(async (req) => {
  const { identity, session } = await signedIn(auth, req.headers)
  await auth.mfa.removeTotp(identity.id, session)
  await auth.mfa.removeBackupCodes(identity.id, session)
  return Response.json({ ok: true })
})
