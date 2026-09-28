/** `makeGuard` is documented as sufficient on its own ("an app mounting only this guard would otherwise
 *  have no CSRF defence"), so it has to reach the same verdict as the CSRF guard beside it and as every
 *  other adapter's, which all go through `csrfGuard`. */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { AuthEngine } from '~/core/engine'
import { AuthError } from '~/core/errors'
import { BearerTransport } from '~/core/transport/bearer.transport'
import { CompositeTransport } from '~/core/transport/composite.transport'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { nestCtx } from '~/test/adapter-fakes'
import { makeCsrfGuard, makeGuard, type NestAdapter } from '../index'

/** An engine taking a session from a cookie or a bearer header, and one signed-in session on it. */
async function signedIn() {
  const adapter = new MemoryAdapter()
  const auth = new AuthEngine({
    baseUrl: 'https://app',
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
    providers: [],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CompositeTransport([
      new CookieTransport({ name: 'duck-sid', secure: false }),
      new BearerTransport(),
    ]),
  })
  const { csrfToken, sid } = await auth.sessions.create({ aal: 1, factors: [], identityId: null, kind: 'user' })
  return { auth, bearer: { authorization: `Bearer ${sid}` }, cookie: { cookie: `duck-sid=${sid}` }, csrfToken }
}

function request(headers: Record<string, string>): NestAdapter.Request {
  return { headers, identity: null, method: 'POST' }
}

/** The code the guard refused with, or `''` when it let the request through. */
async function refusal(run: Promise<unknown>): Promise<string> {
  try {
    await run
  } catch (err) {
    return err instanceof AuthError ? err.code : String(err)
  }
  return ''
}

describe('nestjs makeGuard reaches the same CSRF verdict as makeCsrfGuard', () => {
  it('lets a bearer-authenticated mutation through, as the CSRF guard beside it already does', async () => {
    const { auth, bearer } = await signedIn()
    expect(await refusal(makeCsrfGuard(auth).canActivate(nestCtx(request(bearer))))).toBe('')
    expect(await refusal(makeGuard(auth).canActivate(nestCtx(request(bearer))))).toBe('')
  })

  it('still holds a bearer request to the origin checks once a cookie rides along', async () => {
    const { auth, bearer, cookie } = await signedIn()
    const headers = { ...bearer, ...cookie, 'sec-fetch-site': 'cross-site' }
    expect(await refusal(makeCsrfGuard(auth).canActivate(nestCtx(request(headers))))).toBe('AUTH_CSRF')
    expect(await refusal(makeGuard(auth).canActivate(nestCtx(request(headers))))).toBe('AUTH_CSRF')
  })

  it('still refuses a cookie session mutation carrying no token', async () => {
    const { auth, cookie } = await signedIn()
    expect(await refusal(makeGuard(auth).canActivate(nestCtx(request(cookie))))).toBe('AUTH_CSRF')
  })

  it('still accepts a cookie session mutation carrying the right token', async () => {
    const { auth, cookie, csrfToken } = await signedIn()
    expect(await refusal(makeGuard(auth).canActivate(nestCtx(request({ ...cookie, 'x-csrf-token': csrfToken }))))).toBe(
      '',
    )
  })

  it('enforces a configured Origin allowlist, which it had nowhere to receive', async () => {
    const { auth, cookie, csrfToken } = await signedIn()
    const cfg = { allowedOrigins: ['https://app'] }
    // A token that does match, so layer 2 cannot be what refuses and the allowlist is the only thing left.
    const headers = { ...cookie, origin: 'https://evil.test', 'x-csrf-token': csrfToken }
    expect(await refusal(makeGuard(auth).canActivate(nestCtx(request(headers))))).toBe('')
    expect(await refusal(makeCsrfGuard(auth, { cfg }).canActivate(nestCtx(request(headers))))).toBe('AUTH_CSRF')
    expect(await refusal(makeGuard(auth, { cfg }).canActivate(nestCtx(request(headers))))).toBe('AUTH_CSRF')
  })

  it('reads the configured header name rather than the default', async () => {
    const { auth, cookie, csrfToken } = await signedIn()
    const cfg = { headerName: 'x-app-csrf' }
    const headers = { ...cookie, 'x-app-csrf': csrfToken }
    expect(await refusal(makeGuard(auth, { cfg }).canActivate(nestCtx(request(headers))))).toBe('')
    expect(await refusal(makeGuard(auth).canActivate(nestCtx(request(headers))))).toBe('AUTH_CSRF')
  })

  it('csrf:false still skips the check entirely', async () => {
    const { auth } = await signedIn()
    expect(
      await refusal(
        makeGuard(auth, { csrf: false, required: false }).canActivate(
          nestCtx(request({ 'sec-fetch-site': 'cross-site' })),
        ),
      ),
    ).toBe('')
  })
})
