import { buildEngine } from '@examples/duck-iam-shared/iam'
import { errorResponse, jsonResponse } from '@gentleduck/auth/server/generic'
import { Hono } from 'hono'
import { auth } from './auth'
import { db } from './db'
import { authRouter } from './routes/auth'
import { companiesRouter } from './routes/companies'
import { healthRouter } from './routes/health'
import { ordersRouter } from './routes/orders'
import { permissionsRouter } from './routes/permissions'
import { productsRouter } from './routes/products'
import { usersRouter } from './routes/users'
import type { AppEnv } from './session'
import { attachSession } from './session'

const engine = buildEngine(db)
const app = new Hono<AppEnv>()

app.use('*', attachSession)

app.route('/', healthRouter(engine))
app.route('/auth', authRouter(auth, engine))
app.route('/', permissionsRouter(engine))
app.route('/companies', companiesRouter(engine, auth))
app.route('/users', usersRouter(engine, auth))
app.route('/products', productsRouter(engine, auth))
app.route('/orders', ordersRouter(engine, auth))

// An AuthError (e.g. from `/auth/signup`) keeps its code and status. `c.req.json()` throws a bare
// SyntaxError on a malformed body (duck-auth's own `readBodyJson`, used by `/auth/signup`, already
// swallows this — every other route reads its body with `c.req.json()` directly), so recognize it
// before errorToHttp's generic 500 reports a client's typo as an "internal error". Anything else is
// a 500 worth logging.
app.onError((err) => {
  if (err instanceof SyntaxError) return jsonResponse(400, { error: 'invalid JSON body' })
  const res = errorResponse(err)
  if (res.status === 500) console.error(err)
  return res
})

const port = Number(process.env.PORT ?? 3200)
console.log(`duck-iam hono example on http://localhost:${port}`)

export default { fetch: app.fetch, port }
