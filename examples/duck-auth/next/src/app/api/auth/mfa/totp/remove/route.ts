import { signedIn } from '@examples/duck-auth-shared/session'
import { auth, route } from '@/auth'

export const POST = route(async (req) => {
  const { identity } = await signedIn(auth, req.headers)
  await auth.mfa.removeTotp(identity.id)
  await auth.mfa.removeBackupCodes(identity.id)
  return Response.json({ ok: true })
})
