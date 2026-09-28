import type { AppAuth } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { signedIn, stepUp } from '@examples/duck-auth-shared/session'
import { AuthError } from '@gentleduck/auth/core'
import { elysiaCaller, elysiaCsrf } from '@gentleduck/auth/server/elysia'
import { executeIntents } from '@gentleduck/auth/server/generic'
import { Elysia } from 'elysia'
import { withIp } from '../ip'

export function mfaRoutes(auth: AppAuth) {
  return new Elysia({ prefix: '/auth/mfa' })
    .onBeforeHandle(elysiaCsrf(auth))

    .post('/verify', async (ctx) => {
      return executeIntents(await stepUp(auth, ctx.request.headers, ctx.body, elysiaCaller(withIp(ctx))))
    })

    .post('/totp/begin', async ({ request }) => {
      const { identity } = await signedIn(auth, request.headers)
      return auth.mfa.beginTotpEnrollment(identity.id, identity.profile.email)
    })

    .post('/totp/confirm', async ({ body, request }) => {
      const { identity } = await signedIn(auth, request.headers)
      const confirmed = await auth.mfa.confirmTotpEnrollment(identity.id, readString(body, 'code') ?? '')
      if (!confirmed.ok) throw new AuthError('AUTH_INVALID_CREDENTIALS')
      return { backupCodes: confirmed.backupCodes }
    })

    .post('/totp/remove', async ({ request }) => {
      const { identity } = await signedIn(auth, request.headers)
      await auth.mfa.removeTotp(identity.id)
      await auth.mfa.removeBackupCodes(identity.id)
      return { ok: true }
    })

    .post('/backup-codes', async ({ request }) => {
      const { identity } = await signedIn(auth, request.headers)
      return { backupCodes: await auth.mfa.regenerateBackupCodes(identity.id) }
    })
}
