import { Hono } from 'hono'
import { vi } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { google } from '~/providers/oauth/google'
import { passwords, ScryptHasher } from '~/providers/passwords'
import { mountHono } from '~/server/hono'

export type Profile = { email: string; username: string }

/** A real engine mounted on Hono, behind {@link browserFetch}. `a@x.com` signs in with `correct-pw`, and
 *  `oauth:google` begins. The transport is not `secure`, so the client reads its CSRF cookie as `duck-csrf`. */
export async function browserOverEngine() {
  const adapter = new MemoryAdapter<Profile>()
  const auth = new AuthEngine<Profile>({
    baseUrl: 'http://localhost',
    limiter: new MemoryLimiter({ max: 5, windowMs: 60_000 }),
    providers: [
      passwords<Profile>({ hasher: new ScryptHasher({ N: 1 << 10, keylen: 32 }) }),
      google<Profile>({
        allowStateReplay: true,
        clientId: 'client-id',
        clientSecret: 'client-secret',
        profileToIdentityProfile: (p) => ({ email: p.email ?? '', username: p.sub }),
        redirectUri: 'http://localhost/auth/providers/oauth:google/callback',
        stateCookie: { name: 'duck-oauth', secure: false },
        stateSigningSecret: 'x'.repeat(32),
      }),
    ],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
  const server = new Hono()
  mountHono(server, auth)

  const fetch = browserFetch((req) => server.fetch(req))

  const { id } = await auth.identities.create({ profile: { email: 'a@x.com', username: 'a' } })
  await auth.passwords.set(id, 'correct-pw', adapter.credentials)
  return { adapter, fetch, id }
}

/** A browser in front of `send`: a cookie jar, `document.cookie` answering from it for the client's CSRF read
 *  (stubbed outside jsdom), and the `Sec-Fetch-Site` a browser adds. A relative URL resolves against `origin`. */
export function browserFetch(
  send: (req: Request) => Response | Promise<Response>,
  origin = 'http://localhost',
): (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> {
  const jar = new Map<string, string>()
  const cookie = () => [...jar].map(([name, value]) => `${name}=${value}`).join('; ')
  if (typeof document === 'undefined') {
    vi.stubGlobal('document', {
      get cookie() {
        return cookie()
      },
    })
  } else {
    vi.spyOn(document, 'cookie', 'get').mockImplementation(cookie)
  }
  return async (input, init) => {
    const req = new Request(new URL(String(input), origin), init)
    req.headers.set('cookie', cookie())
    req.headers.set('sec-fetch-site', 'same-origin')
    const res = await send(req)
    for (const line of res.headers.getSetCookie()) {
      const pair = line.split(';')[0] ?? ''
      const eq = pair.indexOf('=')
      if (/max-age=0/i.test(line)) jar.delete(pair.slice(0, eq))
      else jar.set(pair.slice(0, eq), pair.slice(eq + 1))
    }
    return res
  }
}
