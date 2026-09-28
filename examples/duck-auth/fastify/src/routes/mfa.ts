import type { AppAuth } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { signedIn, stepUp } from '@examples/duck-auth-shared/session'
import { AuthError } from '@gentleduck/auth/core'
import { fastifyCaller, fastifyCsrf } from '@gentleduck/auth/server/fastify'
import { executeIntents, nodeHeadersToFetch } from '@gentleduck/auth/server/generic'
import type { FastifyInstance } from 'fastify'

export function mfaRoutes(auth: AppAuth) {
  return async (app: FastifyInstance) => {
    app.addHook('preHandler', fastifyCsrf(auth))

    app.post('/verify', async (req, reply) => {
      const intents = await stepUp(auth, nodeHeadersToFetch(req.headers), req.body, fastifyCaller(req))
      return reply.send(executeIntents(intents))
    })

    app.post('/totp/begin', async (req) => {
      const { identity } = await signedIn(auth, nodeHeadersToFetch(req.headers))
      return auth.mfa.beginTotpEnrollment(identity.id, identity.profile.email)
    })

    app.post('/totp/confirm', async (req) => {
      const { identity } = await signedIn(auth, nodeHeadersToFetch(req.headers))
      const confirmed = await auth.mfa.confirmTotpEnrollment(identity.id, readString(req.body, 'code') ?? '')
      if (!confirmed.ok) throw new AuthError('AUTH_INVALID_CREDENTIALS')
      return { backupCodes: confirmed.backupCodes }
    })

    app.post('/totp/remove', async (req) => {
      const { identity } = await signedIn(auth, nodeHeadersToFetch(req.headers))
      await auth.mfa.removeTotp(identity.id)
      await auth.mfa.removeBackupCodes(identity.id)
      return { ok: true }
    })

    app.post('/backup-codes', async (req) => {
      const { identity } = await signedIn(auth, nodeHeadersToFetch(req.headers))
      return { backupCodes: await auth.mfa.regenerateBackupCodes(identity.id) }
    })
  }
}
