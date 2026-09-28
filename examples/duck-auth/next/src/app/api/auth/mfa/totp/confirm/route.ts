import { readString } from '@examples/duck-auth-shared/body'
import { signedIn } from '@examples/duck-auth-shared/session'
import { AuthError } from '@gentleduck/auth/core'
import { readBodyJson } from '@gentleduck/auth/server/generic'
import { auth, route } from '@/auth'

export const POST = route(async (req) => {
  const { identity } = await signedIn(auth, req.headers)
  const code = readString(await readBodyJson(req), 'code') ?? ''
  const confirmed = await auth.mfa.confirmTotpEnrollment(identity.id, code)
  if (!confirmed.ok) throw new AuthError('AUTH_INVALID_CREDENTIALS')
  return Response.json({ backupCodes: confirmed.backupCodes })
})
