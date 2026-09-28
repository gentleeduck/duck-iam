/** Every mutating route `mountHono` registers must refuse a cross-site request. Derived from the route
 *  table rather than a list, so a POST mounted without `csrfGuard` fails here the day it lands. */

import { Hono } from 'hono'
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { mfaProvider } from '~/providers/mfa'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { mountHono } from '../index'

type MyProfile = { username: string; email: string }

function mounted(): Hono {
  const adapter = new MemoryAdapter<MyProfile>()
  const auth = new AuthEngine<MyProfile>({
    baseUrl: 'http://localhost',
    limiter: new MemoryLimiter({ max: 50, windowMs: 60_000 }),
    providers: [passwords<MyProfile>({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }), mfaProvider()],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  const app = new Hono()
  mountHono(app, auth)
  return app
}

/** The one POST that must not be CSRF-guarded. `response_mode=form_post` means the IdP's own form submits
 *  this callback, so it is cross-site by construction and an origin check refuses every real Apple sign-in.
 *  What authenticates it instead is the signed `state` plus the digest of the pre-auth cookie carried inside
 *  it, which is the same proof the GET callback rests on and does not depend on the request's origin. */
const CSRF_EXEMPT = '/auth/providers/:id/callback'

describe('mountHono - CSRF covers every mutating route', () => {
  const app = mounted()
  const posts = app.routes.filter((route) => route.method === 'POST').map((route) => route.path)

  it('registers the routes this test is meant to cover', () => {
    expect(posts).toContain('/auth/signin')
    expect(posts).toContain('/auth/passkey/complete')
    expect(posts.length).toBeGreaterThanOrEqual(10)
  })

  it('every POST route refuses a cross-site request with AUTH_CSRF, bar the one exemption', async () => {
    for (const path of posts) {
      // `sec-fetch-site` alone is enough for layer 1 to refuse, with or without a session.
      const res = await app.request(path.replace(':id', 'password'), {
        body: '{}',
        headers: { 'content-type': 'application/json', 'sec-fetch-site': 'cross-site' },
        method: 'POST',
      })
      const body = await res.text()
      if (path === CSRF_EXEMPT) {
        // Reaches its handler, and fails there on the provider rather than on the origin.
        expect(body, `${path} is CSRF-guarded, which refuses every form_post sign-in`).not.toContain('AUTH_CSRF')
        expect(body).toContain('AUTH_PROVIDER_FAILED')
        continue
      }
      // An unguarded route runs its handler instead and answers with some other code entirely.
      expect(body, `${path} is not CSRF-guarded`).toContain('AUTH_CSRF')
    }
  })
})
