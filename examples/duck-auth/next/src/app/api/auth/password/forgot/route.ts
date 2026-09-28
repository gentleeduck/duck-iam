import { PAGES } from '@examples/duck-auth-shared/auth'
import { readString } from '@examples/duck-auth-shared/body'
import { readBodyJson } from '@gentleduck/auth/server/generic'
import { auth, route } from '@/auth'

export const POST = route(async (req) => {
  const email = readString(await readBodyJson(req), 'email') ?? ''
  await auth.flows.requestPasswordReset({
    input: { email, callbackPath: PAGES.resetPassword },
    findIdentityByEmail: (e) => auth.identities.getByEmail(e).orNull(),
  })
  return Response.json({ ok: true })
})
