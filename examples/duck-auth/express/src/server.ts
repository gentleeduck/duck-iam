import { buildAuth } from '@examples/duck-auth-shared/auth'
import { errorToHttp } from '@gentleduck/auth/server/generic'
import express, { type ErrorRequestHandler } from 'express'
import { db } from './db'
import { accountRouter } from './routes/account'
import { authRouter } from './routes/auth'
import { mfaRouter } from './routes/mfa'

const auth = buildAuth(db)
const app = express().disable('x-powered-by')

// A body that is malformed or too large reads as none, the way duck-auth's own `readBodyJson` treats it.
const noBody: ErrorRequestHandler = (_err, _req, _res, next) => next()
app.use(express.json(), noBody)
app.use('/auth/mfa', mfaRouter(auth))
app.use('/auth', authRouter(auth))
app.use('/me', accountRouter(auth))

// Express 5 forwards a rejected handler here; an AuthError keeps its code and status.
const onError: ErrorRequestHandler = (err, _req, res, _next) => {
  const { status, body } = errorToHttp(err)
  res.status(status).json(body)
}
app.use(onError)

const port = Number(process.env.PORT ?? 4100)
app.listen(port, () => {
  console.log(`duck-auth express example on http://localhost:${port}`)
})
