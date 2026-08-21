/**
 * A captcha verifier's job is to be the thing that fails closed. It sits in
 * front of sign-in and sign-up, it talks to a third party over the network, and
 * everything about that call, the timeout, the status code, the fields it
 * chooses to read, decides whether an automated client gets through.
 *
 * The existing suite covers the response-shape validation that keeps a truthy
 * non-boolean from bypassing the check. These cover what the verifiers do not
 * look at: the HTTP status, the hostname the challenge was solved on, its
 * timestamp, and how long they are willing to wait.
 *
 * Sources: Cloudflare Turnstile and Google reCAPTCHA siteverify documentation,
 * both of which return `hostname` and `challenge_ts` and both of which tell the
 * integrator to check them.
 */
import { describe, expect, it } from 'vitest'
import { AuthHCaptchaVerifier, AuthNullCaptchaVerifier, AuthRecaptchaV3Verifier, AuthTurnstileVerifier } from '../index'

/** A fetch stub that answers with one JSON body and records what it was sent. */
function stub(body: unknown, init: ResponseInit = {}) {
  const calls: Array<{ body: string; url: string }> = []
  const fetchStub = (async (url: unknown, req: unknown) => {
    calls.push({ body: String((req as RequestInit).body ?? ''), url: String(url) })
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      headers: { 'content-type': 'application/json' },
      ...init,
    })
  }) as unknown as typeof globalThis.fetch
  return { calls, fetch: fetchStub }
}

const turnstile = (body: unknown, init?: ResponseInit) => {
  const s = stub(body, init)
  return { calls: s.calls, verifier: new AuthTurnstileVerifier({ fetch: s.fetch, secret: 'sk' }) }
}

describe('the http response is trusted as far as its body parses', () => {
  it('FINDING: the status code is never consulted, so an error page carrying a success body passes', async () => {
    // `readJsonSafe` reads the body and nothing reads `res.ok`. A five hundred, a
    // four twenty-nine, or a captive-portal response that happens to serialise
    // `{"success":true}` verifies as a solved challenge.
    for (const status of [400, 429, 500, 503]) {
      const { verifier } = turnstile({ success: true }, { status })
      expect(await verifier.verify({ token: 't' })).toEqual({ success: true })
    }
  })

  it('a body that is not json fails closed as malformed', async () => {
    const { verifier } = turnstile('<html>service unavailable</html>')
    expect(await verifier.verify({ token: 't' })).toMatchObject({ errorCodes: ['malformed-response'], success: false })
  })

  it('an empty body fails closed', async () => {
    const { verifier } = turnstile('')
    expect(await verifier.verify({ token: 't' })).toMatchObject({ success: false })
  })

  it('a json array or a json null fails closed', async () => {
    for (const body of [[], null, 'true', '42']) {
      const { verifier } = turnstile(body)
      expect((await verifier.verify({ token: 't' })).success).toBe(false)
    }
  })

  it('a network throw fails closed and carries the message', async () => {
    const verifier = new AuthTurnstileVerifier({
      fetch: (async () => {
        throw new Error('econnreset')
      }) as never,
      secret: 'sk',
    })
    const result = await verifier.verify({ token: 't' })
    expect(result.success).toBe(false)
    expect(result.errorCodes).toEqual(['network-error', 'econnreset'])
  })

  it('FINDING: there is no timeout, so a hung siteverify holds the sign-in open forever', async () => {
    // Every other outbound call in this library carries an AbortController. This
    // one does not, so a provider that accepts the connection and never answers
    // parks the request until something upstream gives up. Captcha sits in front
    // of sign-in, so that is the whole login path.
    let settle: (() => void) | undefined
    const verifier = new AuthTurnstileVerifier({
      fetch: (async () =>
        new Promise<Response>((resolve) => {
          settle = () => resolve(new Response('{"success":true}'))
        })) as never,
      secret: 'sk',
    })

    const pending = verifier.verify({ token: 't' })
    const raced = await Promise.race([
      pending.then(() => 'answered'),
      new Promise((r) => setTimeout(() => r('still waiting'), 50)),
    ])
    expect(raced).toBe('still waiting')
    settle?.()
    await pending
  })
})

describe('the fields a siteverify response carries that nobody reads', () => {
  it('FINDING: the hostname the challenge was solved on is ignored', async () => {
    // Turnstile and reCAPTCHA both return the hostname the widget ran on, and both
    // sets of docs tell the integrator to compare it. A token solved on an
    // attacker's page under a leaked or shared sitekey verifies here.
    const { verifier } = turnstile({ hostname: 'evil.example', success: true })
    expect(await verifier.verify({ token: 't' })).toEqual({ success: true })
  })

  it('FINDING: challenge_ts is ignored, so age is left entirely to the provider', async () => {
    const { verifier } = turnstile({ challenge_ts: '1999-01-01T00:00:00Z', success: true })
    expect((await verifier.verify({ token: 't' })).success).toBe(true)
  })

  it('FINDING: the result drops every field except success and error codes', async () => {
    // Even a caller who wants to check the hostname itself cannot: the parsed
    // response is narrowed to two fields before it is returned.
    const { verifier } = turnstile({ action: 'login', cdata: 'x', hostname: 'app.test', success: true })
    expect(Object.keys(await verifier.verify({ token: 't' }))).toEqual(['success'])
  })
})

describe('what is sent to the provider', () => {
  it('posts the secret and the token in the body, not the query string', async () => {
    const { calls, verifier } = turnstile({ success: true })
    await verifier.verify({ token: 'the-token' })
    expect(calls[0]?.url).not.toContain('sk')
    expect(calls[0]?.body).toContain('secret=sk')
    expect(calls[0]?.body).toContain('response=the-token')
  })

  it('forwards the remote address only when one is given', async () => {
    const withIp = turnstile({ success: true })
    await withIp.verifier.verify({ remoteIp: '203.0.113.9', token: 't' })
    expect(withIp.calls[0]?.body).toContain('remoteip=203.0.113.9')

    const without = turnstile({ success: true })
    await without.verifier.verify({ token: 't' })
    expect(without.calls[0]?.body).not.toContain('remoteip')
  })

  it('encodes a hostile remote address rather than letting it add parameters', async () => {
    const { calls, verifier } = turnstile({ success: true })
    await verifier.verify({ remoteIp: '1.2.3.4&secret=attacker', token: 't' })
    expect(calls[0]?.body).toContain('remoteip=1.2.3.4%26secret%3Dattacker')
    expect(calls[0]?.body.match(/secret=/g)).toHaveLength(1)
  })

  it('short-circuits an empty token without making a request', async () => {
    const { calls, verifier } = turnstile({ success: true })
    expect(await verifier.verify({ token: '' })).toEqual({
      errorCodes: ['missing-input-response'],
      success: false,
    })
    expect(calls).toHaveLength(0)
  })

  it('FINDING: a token of any size is forwarded, so the verifier amplifies a request', async () => {
    // The empty check is the only check. A client can post a ten megabyte token
    // and the verifier relays all of it to the provider, once per attempt.
    const { calls, verifier } = turnstile({ success: true })
    await verifier.verify({ token: 'x'.repeat(2_000_000) })
    expect(calls[0]?.body.length).toBeGreaterThan(2_000_000)
  })

  it('FINDING: the endpoint is caller-configurable with no scheme or host check', async () => {
    // The secret is posted to whatever this points at. Every other outbound URL in
    // the library is validated for https and for private hosts; this one takes a
    // plaintext loopback address without comment.
    const s = stub({ success: true })
    const verifier = new AuthTurnstileVerifier({ endpoint: 'http://127.0.0.1:9/x', fetch: s.fetch, secret: 'sk' })
    await verifier.verify({ token: 't' })
    expect(s.calls[0]?.url).toBe('http://127.0.0.1:9/x')
    expect(s.calls[0]?.body).toContain('secret=sk')
  })

  it('refuses construction without a secret', () => {
    expect(() => new AuthTurnstileVerifier({ secret: '' })).toThrow()
    expect(() => new AuthHCaptchaVerifier({ secret: '' })).toThrow()
    expect(() => new AuthRecaptchaV3Verifier({ secret: '' })).toThrow()
  })
})

describe('the reCAPTCHA v3 score threshold', () => {
  const recaptcha = (body: unknown, cfg: { expectedAction?: string; minScore?: number } = {}) => {
    const s = stub(body)
    const { minScore } = cfg
    return new AuthRecaptchaV3Verifier({
      fetch: s.fetch,
      secret: 'sk',
      ...(minScore !== undefined && { minScore }),
    })
  }

  it('passes at the threshold and fails just below it', async () => {
    expect((await recaptcha({ score: 0.5, success: true }).verify({ token: 't' })).success).toBe(true)
    expect((await recaptcha({ score: 0.49, success: true }).verify({ token: 't' })).success).toBe(false)
  })

  it('a missing score is read as zero and fails closed', async () => {
    const result = await recaptcha({ success: true }).verify({ token: 't' })
    expect(result.success).toBe(false)
    expect(result.errorCodes).toContain('score-too-low')
  })

  it('FINDING: a zero threshold accepts a response with no score at all', async () => {
    // `(parsed.score ?? 0) >= 0` is always true, so configuring `minScore: 0`,
    // which reads as "accept any score", also accepts a response that reported
    // none. The distinction between a low score and an absent one disappears.
    const result = await recaptcha({ success: true }, { minScore: 0 }).verify({ token: 't' })
    expect(result.success).toBe(true)
    expect(result.score).toBeUndefined()
  })

  it('FINDING: a negative threshold is accepted and passes everything', async () => {
    expect((await recaptcha({ score: 0, success: true }, { minScore: -1 }).verify({ token: 't' })).success).toBe(true)
  })

  it('FINDING: a NaN threshold is accepted and refuses everything', async () => {
    // No validation on either side of the comparison, so a threshold read from a
    // mis-parsed environment variable silently turns captcha into a wall.
    expect(
      (await recaptcha({ score: 1, success: true }, { minScore: Number.NaN }).verify({ token: 't' })).success,
    ).toBe(false)
  })

  it('FINDING: a threshold above one refuses every possible score', async () => {
    expect((await recaptcha({ score: 1, success: true }, { minScore: 5 }).verify({ token: 't' })).success).toBe(false)
  })

  it('a non-numeric or non-finite score fails closed as malformed', async () => {
    for (const score of ['0.9', Number.NaN, null, {}]) {
      const result = await recaptcha({ score, success: true }).verify({ token: 't' })
      expect(result).toMatchObject({ errorCodes: ['malformed-response'], success: false })
    }
  })

  it('a score outside the documented range is passed through rather than rejected', async () => {
    // Worth pinning: nothing clamps to 0..1, so a provider or a proxy reporting 99
    // is a pass under any threshold.
    expect((await recaptcha({ score: 99, success: true }).verify({ token: 't' })).success).toBe(true)
  })

  it('an action mismatch fails and says so', async () => {
    const result = await recaptcha({ action: 'signup', score: 0.9, success: true }).verify({
      expectedAction: 'login',
      token: 't',
    })
    expect(result.success).toBe(false)
    expect(result.errorCodes).toContain('action-mismatch')
  })

  it('a missing action fails closed when one was expected', async () => {
    const result = await recaptcha({ score: 0.9, success: true }).verify({ expectedAction: 'login', token: 't' })
    expect(result.success).toBe(false)
  })

  it('FINDING: an action is only checked when the caller remembers to ask', async () => {
    // `expectedAction` is optional and there is no default, so the common
    // integration, verify the token and move on, accepts a token minted for any
    // action on the site. That is the reuse reCAPTCHA v3 actions exist to stop.
    const result = await recaptcha({ action: 'newsletter-signup', score: 0.9, success: true }).verify({ token: 't' })
    expect(result.success).toBe(true)
  })

  it('a failed provider response stays failed however good the score looks', async () => {
    expect((await recaptcha({ score: 1, success: false }).verify({ token: 't' })).success).toBe(false)
  })
})

describe('the null verifier', () => {
  it('FINDING: it is exported from the package and always succeeds, with nothing to stop it shipping', async () => {
    // It is documented as a test helper, and it is the reference the other
    // verifiers are compared against in wiring examples. There is no environment
    // guard and no warning, so wiring it in production silently removes captcha
    // from every path it fronts.
    const verifier = new AuthNullCaptchaVerifier()
    expect(await verifier.verify({ token: '' })).toEqual({ success: true })
    expect(await verifier.verify({ token: 'obviously-fake' })).toEqual({ success: true })
    expect(verifier.id).toBe('null')
  })
})

describe('hcaptcha behaves the same as turnstile', () => {
  const hcaptcha = (body: unknown, init?: ResponseInit) => {
    const s = stub(body, init)
    return { calls: s.calls, verifier: new AuthHCaptchaVerifier({ fetch: s.fetch, secret: 'sk' }) }
  }

  it('passes a successful response and carries the error codes on a failure', async () => {
    expect(await hcaptcha({ success: true }).verifier.verify({ token: 't' })).toEqual({ success: true })
    expect(
      await hcaptcha({ 'error-codes': ['invalid-input-response'], success: false }).verifier.verify({ token: 't' }),
    ).toEqual({ errorCodes: ['invalid-input-response'], success: false })
  })

  it('FINDING: it ignores the status code too', async () => {
    expect((await hcaptcha({ success: true }, { status: 500 }).verifier.verify({ token: 't' })).success).toBe(true)
  })

  it('rejects a non-boolean success and a non-string error code', async () => {
    expect((await hcaptcha({ success: 'true' }).verifier.verify({ token: 't' })).success).toBe(false)
    expect((await hcaptcha({ 'error-codes': [1], success: false }).verifier.verify({ token: 't' })).success).toBe(false)
  })
})
