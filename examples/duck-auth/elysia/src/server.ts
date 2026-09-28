import { buildAuth } from '@examples/duck-auth-shared/auth'
import { AuthError } from '@gentleduck/auth/core'
import { errorResponse } from '@gentleduck/auth/server/generic'
import { Elysia } from 'elysia'
import { db } from './db'
import { accountRoutes } from './routes/account'
import { authRoutes } from './routes/auth'
import { mfaRoutes } from './routes/mfa'

const auth = buildAuth(db)
const port = Number(process.env.PORT ?? 4500)

// duck-auth's own body readers stop at 100 KiB; Elysia parses the body itself, so Bun enforces the same.
new Elysia({ serve: { maxRequestBodySize: 100 * 1024 } })
  // An AuthError keeps its code and status; Elysia answers everything else itself.
  .onError(({ error }) => {
    if (error instanceof AuthError) return errorResponse(error)
  })
  .use(mfaRoutes(auth))
  .use(authRoutes(auth))
  .use(accountRoutes(auth))
  .listen(port)

console.log(`duck-auth elysia example on http://localhost:${port}`)
