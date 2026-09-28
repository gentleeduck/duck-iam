import { type AppAuth, PAGES } from '@examples/duck-auth-shared/auth'
import { signedIn } from '@examples/duck-auth-shared/session'
import { jsonResponse } from '@gentleduck/auth/server/generic'
import { guarded } from '../http'

export function accountRoutes(auth: AppAuth) {
  return {
    '/me': {
      GET: guarded(auth, async (req) => {
        const { identity, session, totp } = await signedIn(auth, req.headers)
        const view = { id: session.id, aal: session.aal, expiresAt: session.expiresAt }
        return jsonResponse(200, { identity, totp, session: view })
      }),
    },

    '/me/email/resend': {
      POST: guarded(auth, async (req) => {
        const { identity } = await signedIn(auth, req.headers)
        const input = { identityId: identity.id, callbackPath: PAGES.verifyEmail }
        return jsonResponse(200, await auth.flows.requestEmailVerification(input))
      }),
    },

    '/me/sessions': {
      GET: guarded(auth, async (req) => {
        const { identity } = await signedIn(auth, req.headers)
        return jsonResponse(200, { sessions: await auth.sessions.listForIdentity(identity.id) })
      }),
    },

    '/me/sessions/revoke-others': {
      POST: guarded(auth, async (req) => {
        const { identity } = await signedIn(auth, req.headers)
        return jsonResponse(200, await auth.sessions.revokeAllExcept(identity.id, auth.transport.extract(req) ?? ''))
      }),
    },
  }
}
