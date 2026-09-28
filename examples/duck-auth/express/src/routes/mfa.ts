import type { AppAuth } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { signedIn, stepUp } from '@examples/duck-auth-shared/session'
import { AuthError } from '@gentleduck/auth/core'
import { applyIntents, expressCaller, expressCsrf, toHeaders } from '@gentleduck/auth/server/express'
import { Router } from 'express'

export function mfaRouter(auth: AppAuth) {
  const router = Router()
  router.use(expressCsrf(auth))

  router.post('/verify', async (req, res) => {
    applyIntents(await stepUp(auth, toHeaders(req.headers), req.body, expressCaller(req)), res)
  })

  router.post('/totp/begin', async (req, res) => {
    const { identity } = await signedIn(auth, toHeaders(req.headers))
    res.json(await auth.mfa.beginTotpEnrollment(identity.id, identity.profile.email))
  })

  router.post('/totp/confirm', async (req, res) => {
    const { identity } = await signedIn(auth, toHeaders(req.headers))
    const confirmed = await auth.mfa.confirmTotpEnrollment(identity.id, readString(req.body, 'code') ?? '')
    if (!confirmed.ok) throw new AuthError('AUTH_INVALID_CREDENTIALS')
    res.json({ backupCodes: confirmed.backupCodes })
  })

  router.post('/totp/remove', async (req, res) => {
    const { identity } = await signedIn(auth, toHeaders(req.headers))
    await auth.mfa.removeTotp(identity.id)
    await auth.mfa.removeBackupCodes(identity.id)
    res.json({ ok: true })
  })

  router.post('/backup-codes', async (req, res) => {
    const { identity } = await signedIn(auth, toHeaders(req.headers))
    res.json({ backupCodes: await auth.mfa.regenerateBackupCodes(identity.id) })
  })

  return router
}
