import { buildAuth } from '@examples/duck-auth-shared/auth'
import { errorResponse } from '@gentleduck/auth/server/generic'
import { db } from './db'
import { accountRoutes } from './routes/account'
import { authRoutes } from './routes/auth'
import { mfaRoutes } from './routes/mfa'

const auth = buildAuth(db)

const server = Bun.serve({
  port: Number(process.env.PORT ?? 4700),
  routes: { ...authRoutes(auth), ...mfaRoutes(auth), ...accountRoutes(auth) },
  fetch: () => new Response('Not Found', { status: 404 }),
  // A thrown AuthError keeps its code and status; anything else is a 500 `errorResponse` logs.
  error: errorResponse,
})

console.log(`duck-auth bun example on ${server.url}`)
