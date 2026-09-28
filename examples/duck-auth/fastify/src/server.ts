import { buildAuth } from '@examples/duck-auth-shared/auth'
import { AuthError } from '@gentleduck/auth/core'
import { errorToHttp } from '@gentleduck/auth/server/generic'
import Fastify, { errorCodes } from 'fastify'
import { db } from './db'
import { accountRoutes } from './routes/account'
import { authRoutes } from './routes/auth'
import { mfaRoutes } from './routes/mfa'

const auth = buildAuth(db)
const app = Fastify()

// A body that is not JSON reads as none, the way duck-auth's own `readBodyJson` treats it.
app.addContentTypeParser('application/json', { parseAs: 'string' }, async (_req: unknown, body: string) => {
  try {
    return JSON.parse(body)
  } catch {
    return null
  }
})
// An IdP answering with a form post, such as Apple; `oauthCallback` parses the raw text itself.
app.addContentTypeParser(
  'application/x-www-form-urlencoded',
  { parseAs: 'string' },
  async (_req: unknown, body: string) => body,
)

app.register(mfaRoutes(auth), { prefix: '/auth/mfa' })
app.register(authRoutes(auth), { prefix: '/auth' })
app.register(accountRoutes(auth), { prefix: '/me' })

// A body over Fastify's limit is a bad request, an AuthError keeps its code and status, anything else is a 500 `errorToHttp` logs.
app.setErrorHandler((err, _req, reply) => {
  const { status, body } = errorToHttp(
    err instanceof errorCodes.FST_ERR_CTP_BODY_TOO_LARGE ? new AuthError('AUTH_INVALID_PARAMETERS') : err,
  )
  return reply.status(status).send(body)
})

const port = Number(process.env.PORT ?? 4300)
await app.listen({ port })
console.log(`duck-auth fastify example on http://localhost:${port}`)
