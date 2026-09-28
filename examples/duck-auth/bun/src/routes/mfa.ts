import type { AppAuth } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { signedIn, stepUp } from '@examples/duck-auth-shared/session'
import { AuthError } from '@gentleduck/auth/core'
import { executeIntents, jsonResponse, readBodyJson } from '@gentleduck/auth/server/generic'
import { caller, guarded } from '../http'

export function mfaRoutes(auth: AppAuth) {
  return {
    '/auth/mfa/verify': {
      POST: guarded(auth, async (req, server) => {
        return executeIntents(await stepUp(auth, req.headers, await readBodyJson(req), caller(req, server)))
      }),
    },

    '/auth/mfa/totp/begin': {
      POST: guarded(auth, async (req) => {
        const { identity } = await signedIn(auth, req.headers)
        return jsonResponse(200, await auth.mfa.beginTotpEnrollment(identity.id, identity.profile.email))
      }),
    },

    '/auth/mfa/totp/confirm': {
      POST: guarded(auth, async (req) => {
        const { identity } = await signedIn(auth, req.headers)
        const code = readString(await readBodyJson(req), 'code') ?? ''
        const confirmed = await auth.mfa.confirmTotpEnrollment(identity.id, code)
        if (!confirmed.ok) throw new AuthError('AUTH_INVALID_CREDENTIALS')
        return jsonResponse(200, { backupCodes: confirmed.backupCodes })
      }),
    },

    '/auth/mfa/totp/remove': {
      POST: guarded(auth, async (req) => {
        const { identity } = await signedIn(auth, req.headers)
        await auth.mfa.removeTotp(identity.id)
        await auth.mfa.removeBackupCodes(identity.id)
        return jsonResponse(200, { ok: true })
      }),
    },

    '/auth/mfa/backup-codes': {
      POST: guarded(auth, async (req) => {
        const { identity } = await signedIn(auth, req.headers)
        return jsonResponse(200, { backupCodes: await auth.mfa.regenerateBackupCodes(identity.id) })
      }),
    },
  }
}
