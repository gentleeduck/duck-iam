import { signedIn } from '@examples/duck-auth-shared/session'
import { auth, route } from '@/auth'

export const POST = route(async (req) => {
  const { identity } = await signedIn(auth, req.headers)
  return Response.json({ backupCodes: await auth.mfa.regenerateBackupCodes(identity.id) })
})
