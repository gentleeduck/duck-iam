/** `makeGuard` is documented as sufficient on its own ("an app mounting only this guard would otherwise
 *  have no CSRF defence"), so it has to reach the same verdict as the CSRF guard beside it and as every
 *  other adapter's, which all go through `csrfGuard`. */
import { describe, expect, it } from 'vitest'
import { MemoryAdapter } from '~/adapters/memory'
import { issueCsrfToken } from '~/core/csrf'
import { AuthEngine } from '~/core/engine'
import type { Sessions } from '~/core/sessions'
import { CookieTransport } from '~/core/transport/cookie.transport'
import { MemoryLimiter } from '~/limiters/memory'
import { makeCsrfGuard, makeGuard, type NestAdapter } from '../index'

function buildAuth(): AuthEngine {
  const adapter = new MemoryAdapter()
  return new AuthEngine({
    baseUrl: 'https://app',
    limiter: new MemoryLimiter({ max: 20, windowMs: 60_000 }),
    providers: [],
    stores: { credentials: adapter.credentials, identities: adapter.identities, sessions: adapter.sessions },
    transport: new CookieTransport({ name: 'duck-sid', secure: false }),
  })
}

function ctxFor(req: NestAdapter.Request) {
  return { switchToHttp: () => ({ getRequest: <T>(): T => req as T }) }
}

/** Nest runs middleware before guards, so a session resolved upstream arrives on the request itself -
 *  which is the path `makeGuard` takes rather than resolving again. */
function signedIn(csrfHash: string): Sessions.Me {
  const now = new Date()
  return {
    aal: 1,
    absoluteExpiresAt: new Date(now.getTime() + 86_400_000),
    actingAs: null,
    createdAt: now,
    csrfHash,
    expiresAt: new Date(now.getTime() + 60_000),
    factors: [],
    fingerprint: null,
    fresh: true,
    id: 'a'.repeat(64),
    identityId: 'ident-1',
    ip: null,
    kind: 'user',
    rotatedAt: now,
    tenantId: null,
    updatedAt: now,
    userAgent: null,
  }
}

function request(headers: Record<string, string>, session: Sessions.Me | null): NestAdapter.Request {
  // Left null even with a session: `makeGuard` only forwards it, and `resolved` is truthy off the
  // session alone, which is the branch under test.
  return { headers, identity: null, method: 'POST', session }
}

/** The code the guard refused with, or `''` when it let the request through. */
async function refusal(run: Promise<unknown>): Promise<string> {
  try {
    await run
  } catch (err) {
    return String((err as { code: string }).code)
  }
  return ''
}

const HASH = issueCsrfToken().hash
const BEARER = { authorization: 'Bearer opaque-token' }

describe('nestjs makeGuard reaches the same CSRF verdict as makeCsrfGuard', () => {
  it('lets a bearer-authenticated mutation through, as the CSRF guard beside it already does', async () => {
    const auth = buildAuth()
    expect(await refusal(makeCsrfGuard(auth).canActivate(ctxFor(request(BEARER, null))))).toBe('')
    expect(
      await refusal(makeGuard(auth, { required: false }).canActivate(ctxFor(request(BEARER, signedIn(HASH))))),
    ).toBe('')
  })

  it('still holds a bearer request to the origin checks once a cookie rides along', async () => {
    const auth = buildAuth()
    const headers = { ...BEARER, cookie: 'duck-sid=x', 'sec-fetch-site': 'cross-site' }
    expect(await refusal(makeCsrfGuard(auth).canActivate(ctxFor(request(headers, null))))).toBe('AUTH_CSRF')
    expect(
      await refusal(makeGuard(auth, { required: false }).canActivate(ctxFor(request(headers, signedIn(HASH))))),
    ).toBe('AUTH_CSRF')
  })

  it('still refuses a cookie session mutation carrying no token', async () => {
    const auth = buildAuth()
    expect(await refusal(makeGuard(auth, { required: false }).canActivate(ctxFor(request({}, signedIn(HASH)))))).toBe(
      'AUTH_CSRF',
    )
  })

  it('still accepts a cookie session mutation carrying the right token', async () => {
    const auth = buildAuth()
    const { token, hash } = issueCsrfToken()
    expect(
      await refusal(
        makeGuard(auth, { required: false }).canActivate(ctxFor(request({ 'x-csrf-token': token }, signedIn(hash)))),
      ),
    ).toBe('')
  })

  it('enforces a configured Origin allowlist, which it had nowhere to receive', async () => {
    const auth = buildAuth()
    const cfg = { allowedOrigins: ['https://app'] }
    // A token that does match, so layer 2 cannot be what refuses and the allowlist is the only thing left.
    const { token, hash } = issueCsrfToken()
    const headers = { origin: 'https://evil.test', 'x-csrf-token': token }
    expect(
      await refusal(makeGuard(auth, { required: false }).canActivate(ctxFor(request(headers, signedIn(hash))))),
    ).toBe('')
    expect(await refusal(makeCsrfGuard(auth, { cfg }).canActivate(ctxFor(request(headers, null))))).toBe('AUTH_CSRF')
    expect(
      await refusal(makeGuard(auth, { cfg, required: false }).canActivate(ctxFor(request(headers, signedIn(hash))))),
    ).toBe('AUTH_CSRF')
  })

  it('reads the configured header name rather than the default', async () => {
    const auth = buildAuth()
    const { token, hash } = issueCsrfToken()
    const cfg = { headerName: 'x-app-csrf' }
    expect(
      await refusal(
        makeGuard(auth, { cfg, required: false }).canActivate(ctxFor(request({ 'x-app-csrf': token }, signedIn(hash)))),
      ),
    ).toBe('')
  })

  it('csrf:false still skips the check entirely', async () => {
    const auth = buildAuth()
    expect(
      await refusal(
        makeGuard(auth, { csrf: false, required: false }).canActivate(
          ctxFor(request({ 'sec-fetch-site': 'cross-site' }, null)),
        ),
      ),
    ).toBe('')
  })
})
