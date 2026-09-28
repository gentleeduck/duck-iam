/** E2E: the Nest handlers mounted as the example app mounts them, behind `NestExceptionFilter` on platform-express. */
import 'reflect-metadata'
import { Controller, type INestApplication, Module, Post, Req, Res, UseFilters } from '@nestjs/common'
import { NestFactory } from '@nestjs/core'
import { afterAll, beforeAll, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { type NestAdapter, NestExceptionFilter, nestSignIn } from '~/server/nestjs'

type Profile = { username: string; email: string }

const PASSWORD = 'correcthorsebatterystaple'
const adapter = new MemoryAdapter<Profile>()
const auth = new AuthEngine<Profile>({
  baseUrl: 'https://app.test',
  limiter: new MemoryLimiter({ max: 1_000, windowMs: 60_000 }),
  providers: [passwords({ hasher: new ScryptHasher({ keylen: 32, N: 1 << 10 }) })],
  stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
  transport: new CookieTransport({ name: 'duck-sid', secure: false }),
})

@Controller('auth')
@UseFilters(NestExceptionFilter)
class AuthController {
  @Post('signin')
  signIn(@Req() req: NestAdapter.Request, @Res() res: NestAdapter.Response) {
    return nestSignIn(auth)(req, res)
  }
}

@Module({ controllers: [AuthController] })
class AppModule {}

/** Every error Nest logged. */
const logged: unknown[] = []
let app: INestApplication
let origin = ''
beforeAll(async () => {
  const identity = await auth.identities.create({ profile: { email: 'a@x.test', username: 'a' } })
  await auth.passwords.set(identity.id, PASSWORD, adapter.credentials)
  app = await NestFactory.create(AppModule, {
    logger: { error: (message) => logged.push(message), log() {}, warn() {} },
  })
  await app.listen(0, '127.0.0.1')
  origin = await app.getUrl()
})
afterAll(() => app?.close())

const signIn = (password: string) =>
  fetch(`${origin}/auth/signin`, {
    body: JSON.stringify({ input: { email: 'a@x.test', password }, providerId: 'password' }),
    headers: { 'content-type': 'application/json', origin },
    method: 'POST',
  })

it('answers a sign-in with its cookies and no-store, set on the response Express hands the handler', async () => {
  const res = await signIn(PASSWORD)
  expect(res.status).toBe(200)
  expect(res.headers.getSetCookie()).toEqual([
    expect.stringMatching(/^duck-sid=/),
    expect.stringMatching(/^duck-csrf=/),
  ])
  expect(res.headers.get('cache-control')).toBe('no-store')
})

it('answers a refused sign-in once, and the filter it is rethrown to leaves that answer alone', async () => {
  const res = await signIn('wrong-password')
  expect(res.status).toBe(401)
  expect(await res.json()).toEqual({ error: { code: 'AUTH_INVALID_CREDENTIALS', status: 401 }, ok: false })
  expect(logged).toEqual([])
})
