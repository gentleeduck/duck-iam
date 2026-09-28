import type { AppAuth } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { signedIn, stepUp } from '@examples/duck-auth-shared/session'
import { AuthError } from '@gentleduck/auth/core'
import { executeIntents, readBodyJson } from '@gentleduck/auth/server/generic'
import { honoCaller, honoCsrf, toHonoAdapterCtx } from '@gentleduck/auth/server/hono'
import { Hono } from 'hono'
import { getConnInfo } from 'hono/bun'

export function mfaRouter(auth: AppAuth) {
  const router = new Hono()
  router.use((c, next) => honoCsrf(auth)(toHonoAdapterCtx(c), next))

  router.post('/verify', async (c) => {
    const caller = honoCaller({ req: c.req, ip: getConnInfo(c).remote.address })
    return executeIntents(await stepUp(auth, c.req.raw.headers, await readBodyJson(c.req.raw), caller))
  })

  router.post('/totp/begin', async (c) => {
    const { identity } = await signedIn(auth, c.req.raw.headers)
    return c.json(await auth.mfa.beginTotpEnrollment(identity.id, identity.profile.email))
  })

  router.post('/totp/confirm', async (c) => {
    const { identity } = await signedIn(auth, c.req.raw.headers)
    const code = readString(await readBodyJson(c.req.raw), 'code') ?? ''
    const confirmed = await auth.mfa.confirmTotpEnrollment(identity.id, code)
    if (!confirmed.ok) throw new AuthError('AUTH_INVALID_CREDENTIALS')
    return c.json({ backupCodes: confirmed.backupCodes })
  })

  router.post('/totp/remove', async (c) => {
    const { identity } = await signedIn(auth, c.req.raw.headers)
    await auth.mfa.removeTotp(identity.id)
    await auth.mfa.removeBackupCodes(identity.id)
    return c.json({ ok: true })
  })

  router.post('/backup-codes', async (c) => {
    const { identity } = await signedIn(auth, c.req.raw.headers)
    return c.json({ backupCodes: await auth.mfa.regenerateBackupCodes(identity.id) })
  })

  return router
}
