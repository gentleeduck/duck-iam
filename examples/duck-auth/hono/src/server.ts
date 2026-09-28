import { buildAuth } from '@examples/duck-auth-shared/auth'
import { errorResponse } from '@gentleduck/auth/server/generic'
import { Hono } from 'hono'
import { db } from './db'
import { accountRouter } from './routes/account'
import { authRouter } from './routes/auth'
import { mfaRouter } from './routes/mfa'

const auth = buildAuth(db)
const app = new Hono()

app.route('/auth/mfa', mfaRouter(auth))
app.route('/auth', authRouter(auth))
app.route('/me', accountRouter(auth))

// An AuthError keeps its code and status; anything else is a 500 `errorResponse` logs.
app.onError(errorResponse)

const port = Number(process.env.PORT ?? 4200)
console.log(`duck-auth hono example on http://localhost:${port}`)

export default { fetch: app.fetch, port }
