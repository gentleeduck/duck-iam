/** The generated spec must describe the routes the adapters actually mount. Derived by mounting the
 *  router against a recorder, so a route added, renamed or gated on one side fails here rather than
 *  404ing in a generated client. */

import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { mountHono } from '~/server/hono'
import type { MountHono } from '~/server/hono/hono.types'
import { identityInput } from '~/test/store-inputs'
import { buildOpenApiSpec } from '../openapi'

type MyProfile = { username: string; email: string }

function buildAuth(): { auth: AuthEngine<MyProfile>; adapter: MemoryAdapter<MyProfile> } {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'https://x',
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [passwords<MyProfile>({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  return { auth, adapter }
}

/** `METHOD /path`, with Hono's `:param` written the way OpenAPI writes it. */
function mounted(opts: MountHono.Options = {}): string[] {
  const seen: string[] = []
  const record =
    (method: string) =>
    (path: string): void => {
      seen.push(`${method} ${path.replace(/:([a-zA-Z0-9_]+)/g, '{$1}')}`)
    }
  const app: MountHono.App = { get: record('GET'), post: record('POST') }
  mountHono(app, buildAuth().auth, opts)
  return seen.sort()
}

function declared(providers?: Parameters<typeof buildOpenApiSpec>[0]['providers']): string[] {
  const spec = buildOpenApiSpec({ baseUrl: 'https://x', ...(providers && { providers }) })
  return Object.entries(spec.paths)
    .flatMap(([path, ops]) => Object.keys(ops).map((method) => `${method.toUpperCase()} ${path}`))
    .sort()
}

/** A same-origin POST: layer 1 passes, and layer 2 is skipped while no session exists yet. */
function sameOrigin(path: string, body: unknown): MountHono.HonoCtx {
  const req = new Request(`https://x${path}`, {
    body: JSON.stringify(body),
    headers: { 'content-type': 'application/json', 'sec-fetch-site': 'same-origin' },
    method: 'POST',
  })
  return {
    req: {
      header: (name?: string) => (name === undefined ? {} : (req.headers.get(name) ?? undefined)),
      json: async () => body,
      method: 'POST',
      param: () => undefined,
      raw: req,
      url: path,
    },
  }
}

describe('the OpenAPI spec and the mounted router agree', () => {
  it('describes every route mounted at default config, and no route that is not', () => {
    expect(declared()).toEqual(mounted())
  })

  it('drops the same paths the adapter skips, group for group', () => {
    for (const group of ['magic-link', 'oauth', 'passkey', 'totp'] as const) {
      const others = (['magic-link', 'oauth', 'passkey', 'totp'] as const).filter((g) => g !== group)
      expect(declared(others), `skipping ${group}`).toEqual(mounted({ skip: [group] }))
    }
  })

  it('declares what a successful POST /signin actually answers: a cookie, and no body', async () => {
    const { auth, adapter } = buildAuth()
    const identity = await adapter.identities.create(
      identityInput({ profile: { email: 'a@b.com', username: 'a' }, providers: [] }),
    )
    await auth.passwords.set(identity.id, 'correct-horse-battery', adapter.credentials)

    const posts: Array<[string, (c: MountHono.HonoCtx) => Response | Promise<Response>]> = []
    mountHono({ get() {}, post: (path, handler) => void posts.push([path, handler]) }, auth)
    const signin = posts.find(([path]) => path === '/auth/signin')?.[1]
    if (!signin) throw new Error('POST /auth/signin is not mounted')

    const res = await signin(
      sameOrigin('/auth/signin', {
        input: { email: 'a@b.com', password: 'correct-horse-battery' },
        providerId: 'password',
      }),
    )

    // The wire: the session rides in the cookie and the body is empty.
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('')
    expect(res.headers.get('set-cookie') ?? '').toContain('duck-sid')

    // The spec must say that, rather than describe a payload the route has never sent.
    const ok = buildOpenApiSpec({ baseUrl: 'https://x' }).paths['/auth/signin']!.post as {
      responses: Record<string, { content?: unknown }>
    }
    expect(ok.responses['200']).toBeDefined()
    expect(ok.responses['200']!.content).toBeUndefined()
  })

  it('backs the client default paths, except the registration route that is the host own', () => {
    const paths = mounted()
    // What `client/vanilla` posts to without an override.
    expect(paths).toContain('POST /auth/signin')
    expect(paths).toContain('POST /auth/signout')
    expect(paths).toContain('GET /auth/session')
    // Registration is app-shaped, so the client `/signup` default is a placeholder for a host route.
    // Mounting one here without saying so in `SignUpOptions` would make that comment a lie.
    expect(paths).not.toContain('POST /auth/signup')
  })
})
