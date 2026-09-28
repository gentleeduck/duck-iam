import type { AppAuth } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { signedIn, stepUp } from '@examples/duck-auth-shared/session'
import { AuthError } from '@gentleduck/auth/core'
import { nodeHeadersToFetch } from '@gentleduck/auth/server/generic'
import { koaApplyIntents, koaCaller, koaCsrf } from '@gentleduck/auth/server/koa'
import Router from '@koa/router'

export function mfaRouter(auth: AppAuth) {
  const router = new Router({ prefix: '/auth/mfa' })
  router.use(koaCsrf(auth))

  router.post('/verify', async (ctx) => {
    const intents = await stepUp(auth, nodeHeadersToFetch(ctx.request.headers), ctx.request.body, koaCaller(ctx))
    await koaApplyIntents(intents, ctx)
  })

  router.post('/totp/begin', async (ctx) => {
    const { identity } = await signedIn(auth, nodeHeadersToFetch(ctx.request.headers))
    ctx.body = await auth.mfa.beginTotpEnrollment(identity.id, identity.profile.email)
  })

  router.post('/totp/confirm', async (ctx) => {
    const { identity } = await signedIn(auth, nodeHeadersToFetch(ctx.request.headers))
    const confirmed = await auth.mfa.confirmTotpEnrollment(identity.id, readString(ctx.request.body, 'code') ?? '')
    if (!confirmed.ok) throw new AuthError('AUTH_INVALID_CREDENTIALS')
    ctx.body = { backupCodes: confirmed.backupCodes }
  })

  router.post('/totp/remove', async (ctx) => {
    const { identity } = await signedIn(auth, nodeHeadersToFetch(ctx.request.headers))
    await auth.mfa.removeTotp(identity.id)
    await auth.mfa.removeBackupCodes(identity.id)
    ctx.body = { ok: true }
  })

  router.post('/backup-codes', async (ctx) => {
    const { identity } = await signedIn(auth, nodeHeadersToFetch(ctx.request.headers))
    ctx.body = { backupCodes: await auth.mfa.regenerateBackupCodes(identity.id) }
  })

  return router
}
