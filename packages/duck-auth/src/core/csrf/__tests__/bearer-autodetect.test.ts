/** `verifyCsrf` documents the bearer exemption as its own ("a Bearer/DPoP request skips the double-submit
 *  token but is still held to the origin checks"), so it must decide it from the headers it already has
 *  rather than only when a caller remembers to say so. */
import { describe, expect, it } from 'vitest'
import { issueCsrfToken, verifyCsrf } from '~/core/csrf'

function headers(init: Record<string, string>): Headers {
  return new Headers(init)
}

/** The code the check refused with, or `''` when it passed. */
function refusal(opts: Parameters<typeof verifyCsrf>[0]): string {
  try {
    verifyCsrf(opts)
  } catch (err) {
    return String((err as { code: string }).code)
  }
  return ''
}

const SESSION_HASH = issueCsrfToken().hash

describe('verifyCsrf derives the bearer exemption from the Authorization header', () => {
  it('exempts a bearer request from the token check without being told', () => {
    expect(
      refusal({
        headers: headers({ authorization: 'Bearer opaque-token' }),
        method: 'POST',
        sessionCsrfHash: SESSION_HASH,
      }),
    ).toBe('')
  })

  it('still refuses the same request when no bearer credential is on it', () => {
    expect(refusal({ headers: headers({}), method: 'POST', sessionCsrfHash: SESSION_HASH })).toBe('AUTH_CSRF')
  })

  it('keeps holding a bearer request to the origin checks when a cookie rides along', () => {
    // The exemption's whole justification is that a header credential is not ambient. A cookie makes it
    // ambient again, so layer 1 must still run.
    expect(
      refusal({
        headers: headers({
          authorization: 'Bearer opaque-token',
          cookie: 'duck-sid=x',
          'sec-fetch-site': 'cross-site',
        }),
        method: 'POST',
        sessionCsrfHash: SESSION_HASH,
      }),
    ).toBe('AUTH_CSRF')
  })

  it('a comma disqualifies the header, matching what BearerTransport will extract', () => {
    expect(
      refusal({
        headers: headers({ authorization: 'Bearer one, Bearer two' }),
        method: 'POST',
        sessionCsrfHash: SESSION_HASH,
      }),
    ).toBe('AUTH_CSRF')
  })

  it('a non-bearer scheme is not a bearer credential', () => {
    expect(
      refusal({
        headers: headers({ authorization: 'Basic dXNlcjpwYXNz' }),
        method: 'POST',
        sessionCsrfHash: SESSION_HASH,
      }),
    ).toBe('AUTH_CSRF')
  })

  it('an explicit isBearer:false overrides the header, so a host that knows better can opt out', () => {
    expect(
      refusal({
        headers: headers({ authorization: 'Bearer opaque-token' }),
        isBearer: false,
        method: 'POST',
        sessionCsrfHash: SESSION_HASH,
      }),
    ).toBe('AUTH_CSRF')
  })

  it('a valid double-submit token still passes on a cookie request', () => {
    const { token, hash } = issueCsrfToken()
    expect(refusal({ headers: headers({ 'x-csrf-token': token }), method: 'POST', sessionCsrfHash: hash })).toBe('')
  })
})
