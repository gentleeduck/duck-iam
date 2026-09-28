import { buildEngine } from '@examples/duck-iam-shared/iam'
import { errorToHttp } from '@gentleduck/auth/server/generic'
import express, { type ErrorRequestHandler } from 'express'
import { auth } from './auth'
import { db } from './db'
import { authRouter } from './routes/auth'
import { companiesRouter } from './routes/companies'
import { healthRouter } from './routes/health'
import { ordersRouter } from './routes/orders'
import { permissionsRouter } from './routes/permissions'
import { productsRouter } from './routes/products'
import { usersRouter } from './routes/users'
import { attachSession } from './session'

const engine = buildEngine(db)
const app = express()

app.use(express.json())
app.use(attachSession)

app.use(healthRouter(engine))
app.use('/auth', authRouter(auth, engine))
app.use(permissionsRouter(engine))
app.use('/companies', companiesRouter(engine, auth))
app.use('/users', usersRouter(engine, auth))
app.use('/products', productsRouter(engine, auth))
app.use('/orders', ordersRouter(engine, auth))

// Express 5 forwards a rejected handler here; an AuthError (e.g. from `/auth/signup`) keeps its code and status.
const onError: ErrorRequestHandler = (err, _req, res, _next) => {
  // `express.json()`'s own parse failure carries its real status and `type`, not an AuthError —
  // recognize it first so a malformed request body gets its actual 400 instead of errorToHttp's
  // generic 500 (which otherwise reports a client's typo as an "internal error").
  if (err instanceof SyntaxError && (err as { type?: string }).type === 'entity.parse.failed') {
    res.status(400).json({ error: 'invalid JSON body' })
    return
  }
  const { status, body } = errorToHttp(err)
  if (status === 500) console.error(err)
  res.status(status).json(body)
}
app.use(onError)

const port = Number(process.env.PORT ?? 3100)
app.listen(port, () => {
  console.log(`duck-iam express example on http://localhost:${port}`)
})
