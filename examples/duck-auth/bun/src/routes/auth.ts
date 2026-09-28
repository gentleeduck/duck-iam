import { type AppAuth, landing, PAGES } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { signUp } from '@examples/duck-auth-shared/signup'
import {
  executeIntents,
  jsonResponse,
  oauthCallback,
  parseProviderBeginBody,
  parseSignInBody,
  readBodyJson,
  readBodyText,
  redirectForScript,
} from '@gentleduck/auth/server/generic'
import type { BunRequest } from 'bun'
import { caller, guarded, type Handler } from '../http'

export function authRoutes(auth: AppAuth) {
  // Where the IdP returns the browser; the cookies land, then the app takes over.
  const callback: Handler<BunRequest<'/auth/providers/:id/callback'>> = async (req, server) => {
    const body = req.method === 'POST' ? ((await readBodyText(req)) ?? '') : undefined
    const request = { body, cookie: req.headers.get('cookie'), method: req.method, url: req.url }
    const intents = await landing(oauthCallback(auth, req.params.id, request, caller(req, server)))
    return executeIntents(intents)
  }

  return {
    '/auth/providers': { GET: () => jsonResponse(200, { providers: auth.providers.list() }) },

    '/auth/signin': {
      POST: guarded(auth, async (req, server) => {
        const parsed = parseSignInBody(await readBodyJson(req))
        // The adapters' own answer to a body that is not a sign-in.
        if (!parsed) return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
        const { intents } = await auth.flows.signIn({
          ...parsed,
          ...caller(req, server),
          previousSid: auth.transport.extract(req) ?? undefined,
        })
        return executeIntents(intents)
      }),
    },

    '/auth/signout': {
      POST: guarded(auth, async (req) => {
        const sid = auth.transport.extract(req)
        return executeIntents(sid ? (await auth.flows.signOut(sid)).intents : auth.transport.revoke())
      }),
    },

    '/auth/session': {
      GET: async (req: Request) => {
        const resolved = await auth.resolveSession(req).orNull()
        if (!resolved) return jsonResponse(200, { session: null, identity: null })
        // `csrfHash` is server-side state; the browser holds the plaintext in its cookie.
        const { csrfHash: _csrfHash, ...session } = resolved.session
        return jsonResponse(200, { session, identity: resolved.identity })
      },
    },

    '/auth/providers/:id/begin': {
      POST: guarded(auth, async (req: BunRequest<'/auth/providers/:id/begin'>) => {
        const input = parseProviderBeginBody(await readBodyJson(req))
        if (input === null) return executeIntents([{ type: 'error', code: 'AUTH_INVALID_CREDENTIALS', status: 400 }])
        // A script cannot follow the redirect to the IdP, so a JSON caller gets `{ url }` instead.
        return executeIntents(redirectForScript(await auth.flows.beginProvider(req.params.id, input), req.headers))
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
