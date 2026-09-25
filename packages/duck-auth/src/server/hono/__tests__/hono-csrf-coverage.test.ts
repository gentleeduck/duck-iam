/** Every mutating route `mountHono` registers must refuse a cross-site request. Derived from the route
 *  table rather than a list, so a POST mounted without `csrfGuard` fails here the day it lands. */

import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'
import type { MountHono } from '../hono.types'
import { mountHono } from '../index'

type MyProfile = { username: string; email: string }

function buildAuth(): AuthEngine<MyProfile> {
  const adapter = new MemoryAdapter<MyProfile>()
  return new AuthEngine<MyProfile>({
    baseUrl: 'https://x',
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [passwords<MyProfile>({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
}

/** Mount against a recorder rather than a real Hono, which this package does not depend on. */
function postRoutes(auth: AuthEngine<MyProfile>): [string, (c: MountHono.HonoCtx) => Response | Promise<Response>][] {
  const posts: [string, (c: MountHono.HonoCtx) => Response | Promise<Response>][] = []
  const app: MountHono.App = {
    get() {},
    post(path, handler) {
      posts.push([path, handler])
    },
  }
  mountHono(app, auth)
  return posts
}

/** A cross-site POST: `sec-fetch-site` alone is enough for layer 1 to refuse, with or without a session. */
function crossSite(path: string): MountHono.HonoCtx {
  const req = new Request(`https://x${path}`, {
    body: '{}',
    headers: { 'content-type': 'application/json', 'sec-fetch-site': 'cross-site' },
    method: 'POST',
  })
  return {
    req: {
      header: (name?: string) => (name === undefined ? {} : (req.headers.get(name) ?? undefined)),
      json: async () => ({}),
      method: 'POST',
      param: () => undefined,
      raw: req,
      url: path,
    },
  }
}

/** The one POST that must not be CSRF-guarded. `response_mode=form_post` means the IdP's own form submits
 *  this callback, so it is cross-site by construction and an origin check refuses every real Apple sign-in.
 *  What authenticates it instead is the signed `state` plus the digest of the pre-auth cookie carried inside
 *  it, which is the same proof the GET callback rests on and does not depend on the request's origin. */
const CSRF_EXEMPT = '/auth/providers/:provider/callback'

describe('mountHono - CSRF covers every mutating route', () => {
  it('registers the routes this test is meant to cover', () => {
    const paths = postRoutes(buildAuth()).map(([p]) => p)
    expect(paths).toContain('/auth/signin')
    expect(paths).toContain('/auth/passkey/complete')
    expect(paths.length).toBeGreaterThanOrEqual(10)
  })

  it('every POST route refuses a cross-site request with AUTH_CSRF, bar the one exemption', async () => {
    const auth = buildAuth()
    for (const [path, handler] of postRoutes(auth)) {
      const res = await handler(crossSite(path))
      const body: unknown = await res.json()
      if (path === CSRF_EXEMPT) {
        // Refused here too, but on the provider name the recorder does not supply rather than on the
        // origin - the point of the branch is that the exemption is this path and no other.
        expect(JSON.stringify(body), `${path} accepted a forged callback`).not.toContain('"ok":true')
        continue
      }
      // An unguarded route runs its handler instead and answers with some other code entirely.
      expect(JSON.stringify(body), `${path} is not CSRF-guarded`).toContain('AUTH_CSRF')
    }
  })
})
