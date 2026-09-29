import { type AppAuth, PAGES } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { beginProvider, currentSession, providerCallback, signIn, signOut } from '@examples/duck-auth-shared/routes'
import { signUp } from '@examples/duck-auth-shared/signup'
import { executeIntents, jsonResponse, readBodyJson, readBodyText } from '@gentleduck/auth/server/generic'
import type { BunRequest } from 'bun'
import { caller, guarded, type Handler } from '../http'

export function authRoutes(auth: AppAuth) {
  // Where the IdP returns the browser. Apple's form post is read as text, the same query string a redirect carries.
  const callback: Handler<BunRequest<'/auth/providers/:id/callback'>> = async (req, server) => {
    const params =
      req.method === 'POST' ? new URLSearchParams((await readBodyText(req)) ?? '') : new URL(req.url).searchParams
    return executeIntents(await providerCallback(auth, req.params.id, params, req.headers, caller(req, server)))
  }

  return {
    '/auth/providers': { GET: () => jsonResponse(200, { providers: auth.providers.list() }) },

    '/auth/signin': {
      POST: guarded(auth, async (req, server) => {
        return executeIntents(await signIn(auth, req.headers, await readBodyJson(req), caller(req, server)))
      }),
    },

    '/auth/signout': {
      POST: guarded(auth, async (req) => executeIntents(await signOut(auth, req.headers))),
    },

    '/auth/session': {
      GET: async (req: Request) => jsonResponse(200, await currentSession(auth, req.headers)),
    },

    '/auth/providers/:id/begin': {
      POST: guarded(auth, async (req: BunRequest<'/auth/providers/:id/begin'>) => {
        return executeIntents(await beginProvider(auth, req.params.id, await readBodyJson(req)))
      }),
    },

    '/auth/providers/:id/callback': { GET: callback, POST: callback },

    '/auth/signup': {
      POST: guarded(auth, async (req) => {
        return jsonResponse(201, await signUp(auth, await readBodyJson(req)))
      }),
    },

    '/auth/password/forgot': {
      POST: guarded(auth, async (req) => {
        await auth.flows.requestPasswordReset({
          input: { email: readString(await readBodyJson(req), 'email') ?? '', callbackPath: PAGES.resetPassword },
          findIdentityByEmail: (e) => auth.identities.getByEmail(e).orNull(),
        })
        return jsonResponse(200, { ok: true })
      }),
    },

    '/auth/password/reset': {
      POST: guarded(auth, async (req) => {
        const body = await readBodyJson(req)
        const { intents } = await auth.flows.completePasswordReset({
          token: readString(body, 'token') ?? '',
          newPassword: readString(body, 'password') ?? '',
          currentSid: auth.transport.extract(req) ?? undefined,
        })
        return executeIntents([...intents, { type: 'json', status: 200, body: { ok: true } }])
      }),
    },

    '/auth/email/verify': {
      POST: guarded(auth, async (req) => {
        const token = readString(await readBodyJson(req), 'token') ?? ''
        const { identityId } = await auth.flows.completeEmailVerification({ token })
        return jsonResponse(200, { identityId })
      }),
    },
  }
}
