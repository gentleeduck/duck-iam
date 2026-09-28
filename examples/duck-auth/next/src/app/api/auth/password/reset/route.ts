import { readString } from '@examples/duck-auth-shared/body'
import { executeIntents, readBodyJson } from '@gentleduck/auth/server/generic'
import { auth, route } from '@/auth'

export const POST = route(async (req) => {
  const body = await readBodyJson(req)
  const { intents } = await auth.flows.completePasswordReset({
    token: readString(body, 'token') ?? '',
    newPassword: readString(body, 'password') ?? '',
    currentSid: auth.transport.extract({ headers: req.headers }) ?? undefined,
  })
  return executeIntents([...intents, { type: 'json', status: 200, body: { ok: true } }])
})
