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
  it('refuses a non-2xx however well its body parses', async () => {
    // Nothing read `res.ok`, so a five hundred, a four twenty-nine, or a captive portal that
    // happens to serialise `{"success":true}` verified as a solved challenge.
    for (const status of [400, 429, 500, 503]) {
      const { verifier } = turnstile({ success: true }, { status })
      expect(await verifier.verify({ token: 't' })).toEqual({
        errorCodes: [`provider-http-${status}`],
        success: false,
      })
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

  it('gives up on a hung siteverify instead of holding the sign-in open', async () => {
    // A provider that accepts the connection and never answers used to park the request until
    // something upstream gave up, and captcha fronts sign-in, so that was the whole login path.
    const verifier = new AuthTurnstileVerifier({
      fetch: ((_url: string, init: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init.signal?.addEventListener('abort', () => reject(new Error('aborted')))
        })) as never,
      secret: 'sk',
      timeoutMs: 20,
    })

    expect(await verifier.verify({ token: 't' })).toEqual({ errorCodes: ['timeout'], success: false })
  })

  it('refuses a timeout that could never fire', () => {
    for (const timeoutMs of [0, -1, Number.NaN]) {
      expect(() => new AuthTurnstileVerifier({ secret: 'sk', timeoutMs })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
  })
})

describe('the fields a siteverify response carries that nobody reads', () => {
  it('checks the hostname the challenge was solved on when told which one to expect', async () => {
    // Turnstile and reCAPTCHA both return the hostname the widget ran on and both sets of docs tell
    // the integrator to compare it. A token solved on an attacker's page under a leaked or shared
    // sitekey used to verify here.
    const evil = stub({ hostname: 'evil.example', success: true })
    const verifier = new AuthTurnstileVerifier({ expectedHostname: 'app.test', fetch: evil.fetch, secret: 'sk' })
    expect(await verifier.verify({ token: 't' })).toMatchObject({
      errorCodes: ['hostname-mismatch'],
      hostname: 'evil.example',
      success: false,
    })

    const good = stub({ hostname: 'app.test', success: true })
    const ok = new AuthTurnstileVerifier({
      expectedHostname: ['app.test', 'www.app.test'],
      fetch: good.fetch,
      secret: 'sk',
    })
    expect((await ok.verify({ token: 't' })).success).toBe(true)
  })

  it('a per-call expected hostname overrides the configured one', async () => {
    const s = stub({ hostname: 'admin.app.test', success: true })
    const verifier = new AuthTurnstileVerifier({ expectedHostname: 'app.test', fetch: s.fetch, secret: 'sk' })
    expect((await verifier.verify({ expectedHostname: 'admin.app.test', token: 't' })).success).toBe(true)
  })

  it('refuses an expected hostname that names nothing', () => {
    for (const expectedHostname of ['', [], ['app.test', '']]) {
      expect(() => new AuthTurnstileVerifier({ expectedHostname, secret: 'sk' })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
  })

  it('refuses a challenge older than the providers keep one valid', async () => {
    // Turnstile and hCaptcha both expire a token after 300s, so an older one was never going to
    // pass anyway; leaving the age entirely to the provider meant not noticing when it did.
    const { verifier } = turnstile({ challenge_ts: '1999-01-01T00:00:00Z', success: true })
    expect(await verifier.verify({ token: 't' })).toMatchObject({
      challengeTs: '1999-01-01T00:00:00Z',
      errorCodes: ['challenge-expired'],
      success: false,
    })

    const fresh = turnstile({ challenge_ts: new Date().toISOString(), success: true })
    expect((await fresh.verifier.verify({ token: 't' })).success).toBe(true)
  })

  it('allows the small forward skew two clocks produce, and refuses more', async () => {
    const near = turnstile({ challenge_ts: new Date(Date.now() + 30_000).toISOString(), success: true })
    expect((await near.verifier.verify({ token: 't' })).success).toBe(true)

    const far = turnstile({ challenge_ts: new Date(Date.now() + 3_600_000).toISOString(), success: true })
    expect((await far.verifier.verify({ token: 't' })).errorCodes).toEqual(['challenge-in-future'])
  })

  it('an unparseable challenge_ts fails closed, and a non-string is malformed', async () => {
    expect(
      (await turnstile({ challenge_ts: 'not-a-date', success: true }).verifier.verify({ token: 't' })).errorCodes,
    ).toEqual(['malformed-challenge-ts'])
    expect(
      (await turnstile({ challenge_ts: 12345, success: true }).verifier.verify({ token: 't' })).errorCodes,
    ).toEqual(['malformed-response'])
  })

  it('a zero max age turns the check off for a provider that does not send one', async () => {
    const s = stub({ challenge_ts: '1999-01-01T00:00:00Z', success: true })
    const verifier = new AuthTurnstileVerifier({ fetch: s.fetch, maxChallengeAgeMs: 0, secret: 'sk' })
    expect((await verifier.verify({ token: 't' })).success).toBe(true)
  })

  it('carries the fields the provider sent rather than narrowing them away', async () => {
    // A caller who wants to apply its own hostname or action rule could not: the parsed response
    // was cut to two fields before it was returned.
    const { verifier } = turnstile({ challenge_ts: new Date().toISOString(), hostname: 'app.test', success: true })
    expect(await verifier.verify({ token: 't' })).toMatchObject({ hostname: 'app.test', success: true })
    expect((await verifier.verify({ token: 't' })).challengeTs).toBeDefined()
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

  it('refuses an oversized token without relaying it to the provider', async () => {
    // The empty check was the only check, so a client could post a ten megabyte token and the
    // verifier relayed all of it to the provider, once per attempt.
    const { calls, verifier } = turnstile({ success: true })
    expect(await verifier.verify({ token: 'x'.repeat(2_000_000) })).toEqual({
      errorCodes: ['invalid-input-response', 'token-too-large'],
      success: false,
    })
    expect(calls).toHaveLength(0)
  })

  it('refuses an endpoint that is plaintext or points inside the network', async () => {
    // The secret is posted to whatever this points at. Every other outbound URL in the library is
    // validated for https and for private hosts; this one took a plaintext loopback address without
    // comment. It is now the same guard the webhook deliverer uses.
    for (const endpoint of [
      'http://127.0.0.1:9/x',
      'https://169.254.169.254/latest',
      'http://siteverify.test',
      'nonsense',
    ]) {
      expect(() => new AuthTurnstileVerifier({ endpoint, secret: 'sk' })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
  })

  it('still allows a loopback endpoint when a dev deployment asks for one', async () => {
    const s = stub({ success: true })
    const verifier = new AuthTurnstileVerifier({
      allowInsecureEndpoint: true,
      endpoint: 'http://siteverify.test/x',
      fetch: s.fetch,
      secret: 'sk',
    })
    await verifier.verify({ token: 't' })
    expect(s.calls[0]?.url).toBe('http://siteverify.test/x')
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

  it('an absent score is refused as its own thing, not read as zero', async () => {
    const result = await recaptcha({ success: true }).verify({ token: 't' })
    expect(result.success).toBe(false)
    expect(result.errorCodes).toContain('missing-score')
  })

  it('a zero threshold accepts any score the provider reports and still refuses none at all', async () => {
    // `(score ?? 0) >= 0` is always true, so `minScore: 0` - which reads as "accept any score" -
    // also accepted a response that reported none, and the two stopped being distinguishable.
    expect((await recaptcha({ score: 0, success: true }, { minScore: 0 }).verify({ token: 't' })).success).toBe(true)
    const none = await recaptcha({ success: true }, { minScore: 0 }).verify({ token: 't' })
    expect(none.success).toBe(false)
    expect(none.errorCodes).toContain('missing-score')
  })

  it('refuses a threshold outside the range a score can take', async () => {
    // Below zero passes every bot, above one walls out every human, and a NaN read from a
    // mis-parsed environment variable did the second silently. None of the three was validated.
    for (const minScore of [-1, 5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => recaptcha({ success: true }, { minScore })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
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

  it('an action can be pinned once at wiring rather than on every call', async () => {
    // `expectedAction` was per-call only, so the common integration - verify the token and move on -
    // accepted a token minted for any action on the site, which is the reuse v3 actions exist to
    // stop. Set on the verifier it applies to every call; the per-call value still overrides it.
    const s = stub({ action: 'newsletter-signup', score: 0.9, success: true })
    const pinned = new AuthRecaptchaV3Verifier({ expectedAction: 'login', fetch: s.fetch, secret: 'sk' })
    const result = await pinned.verify({ token: 't' })
    expect(result.success).toBe(false)
    expect(result.errorCodes).toContain('action-mismatch')
    // Reported either way, so a caller that would rather judge for itself now can.
    expect(result.action).toBe('newsletter-signup')

    const s2 = stub({ action: 'newsletter-signup', score: 0.9, success: true })
    const overridden = new AuthRecaptchaV3Verifier({ expectedAction: 'login', fetch: s2.fetch, secret: 'sk' })
    expect((await overridden.verify({ expectedAction: 'newsletter-signup', token: 't' })).success).toBe(true)
  })

  it('without an expected action on either side the action is reported, not enforced', async () => {
    // Left deliberate: the verifier cannot invent which action a call belongs to. What it can do is
    // stop silently discarding the one the provider sent.
    const result = await recaptcha({ action: 'newsletter-signup', score: 0.9, success: true }).verify({ token: 't' })
    expect(result).toMatchObject({ action: 'newsletter-signup', success: true })
  })

  it('a failed provider response stays failed however good the score looks', async () => {
    expect((await recaptcha({ score: 1, success: false }).verify({ token: 't' })).success).toBe(false)
  })
})

describe('the null verifier', () => {
  it('still passes everything, because that is what it is for', async () => {
    const verifier = new AuthNullCaptchaVerifier()
    expect(await verifier.verify({ token: '' })).toEqual({ success: true })
    expect(await verifier.verify({ token: 'obviously-fake' })).toEqual({ success: true })
    expect(verifier.id).toBe('null')
  })

  it('refuses to construct under NODE_ENV=production', () => {
    // It is documented as a test helper and it is the reference the other verifiers are compared
    // against in wiring examples. With no guard, wiring it in production silently removed captcha
    // from every path it fronted, and a thing that cannot fail looks exactly like a thing that
    // works. Same escape hatch as MemoryIdempotency, for a deployment that means it.
    const before = process.env.NODE_ENV
    process.env.NODE_ENV = 'production'
    try {
      expect(() => new AuthNullCaptchaVerifier()).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
      expect(() => new AuthNullCaptchaVerifier({ development: true })).not.toThrow()
    } finally {
      process.env.NODE_ENV = before
    }
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

  it('refuses a non-2xx for the same reason turnstile does', async () => {
    const result = await hcaptcha({ success: true }, { status: 500 }).verifier.verify({ token: 't' })
    expect(result).toEqual({ errorCodes: ['provider-http-500'], success: false })
  })

  it('rejects a non-boolean success and a non-string error code', async () => {
    expect((await hcaptcha({ success: 'true' }).verifier.verify({ token: 't' })).success).toBe(false)
    expect((await hcaptcha({ 'error-codes': [1], success: false }).verifier.verify({ token: 't' })).success).toBe(false)
  })
})
