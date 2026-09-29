import { buildAuth } from '@examples/duck-auth-shared/auth'
import { errorToHttp } from '@gentleduck/auth/server/generic'
import { bodyParser } from '@koa/bodyparser'
import Koa from 'koa'
import { db } from './db'
import { accountRouter } from './routes/account'
import { authRouter } from './routes/auth'
import { mfaRouter } from './routes/mfa'

const auth = buildAuth(db)
const app = new Koa()

// An AuthError keeps its code and status; anything else is a 500 `errorToHttp` logs.
app.use(async (ctx, next) => {
  try {
    await next()
  } catch (err) {
    const { status, body } = errorToHttp(err)
    ctx.status = status
    ctx.body = body
  }
})
// An IdP answering with a form post, such as Apple, arrives as its raw text for the callback route to parse.
// A body that is malformed or too large reads as none, the way duck-auth's own `readBodyJson` treats it.
app.use(
  bodyParser({
    enableTypes: ['json', 'text'],
    extendTypes: { text: ['application/x-www-form-urlencoded'] },
    onError: () => {},
  }),
)

for (const router of [mfaRouter(auth), authRouter(auth), accountRouter(auth)]) {
  app.use(router.routes()).use(router.allowedMethods())
}

const port = Number(process.env.PORT ?? 4400)
app.listen(port, () => {
  console.log(`duck-auth koa example on http://localhost:${port}`)
})
