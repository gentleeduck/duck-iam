/** A captcha verifier fronts sign-in, so every way the provider call can go wrong must fail closed. */
import { describe, expect, it } from 'vitest'
import type { AuthCaptcha } from '../captcha.types'
import { AuthHCaptchaVerifier, AuthNullCaptchaVerifier, AuthRecaptchaV3Verifier, AuthTurnstileVerifier } from '../index'

/** A fetch stub that answers with one JSON body and records what it was sent. */
function stub(body: unknown, init: ResponseInit = {}) {
  const calls: Array<{ body: string; redirect: RequestRedirect | undefined; url: string }> = []
  const fetch: typeof globalThis.fetch = async (url, req) => {
    calls.push({ body: String(req?.body ?? ''), redirect: req?.redirect, url: String(url) })
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), {
      headers: { 'content-type': 'application/json' },
      ...init,
    })
  }
  return { calls, fetch }
}

const turnstile = (body: unknown, init?: ResponseInit) => {
  const s = stub(body, init)
  return { calls: s.calls, verifier: new AuthTurnstileVerifier({ fetch: s.fetch, secret: 'sk' }) }
}

const PROVIDERS: Array<{
  name: string
  make: (fetch: typeof globalThis.fetch) => AuthCaptcha.IVerifier
  passing: Record<string, unknown>
}> = [
  {
    make: (fetch) => new AuthTurnstileVerifier({ fetch, secret: 'sk' }),
    name: 'turnstile',
    passing: { success: true },
  },
  { make: (fetch) => new AuthHCaptchaVerifier({ fetch, secret: 'sk' }), name: 'hcaptcha', passing: { success: true } },
  {
    make: (fetch) => new AuthRecaptchaV3Verifier({ fetch, secret: 'sk' }),
    name: 'recaptcha v3',
    passing: { score: 0.9, success: true },
  },
]

describe('the http response is trusted as far as its body parses', () => {
  it('refuses a non-2xx however well its body parses', async () => {
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

  it('a network throw fails closed, with the message beside the code rather than in it', async () => {
    const verifier = new AuthTurnstileVerifier({
      fetch: async () => {
        throw new Error('econnreset')
      },
      secret: 'sk',
    })
    const result = await verifier.verify({ token: 't' })
    expect(result.success).toBe(false)
    expect(result.errorCodes).toEqual(['network-error'])
    expect(result.detail).toBe('econnreset')
  })

  it('gives up on a hung siteverify instead of holding the sign-in open', async () => {
    const verifier = new AuthTurnstileVerifier({
      fetch: (_url, init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error('aborted')))
        }),
      secret: 'sk',
      timeoutMs: 20,
    })

    expect(await verifier.verify({ token: 't' })).toEqual({ errorCodes: ['timeout'], success: false })
  })

  it('refuses a timeout that could never fire, or would fire at once', async () => {
    // Past 2^31-1, `setTimeout` fires after 1ms, so every token would come back `timeout`.
    for (const timeoutMs of [0, -1, Number.NaN, 2 ** 31]) {
      expect(() => new AuthTurnstileVerifier({ secret: 'sk', timeoutMs })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
    const slow: typeof globalThis.fetch = async () => {
      await new Promise((r) => setTimeout(r, 20))
      return Response.json({ success: true })
    }
    const verifier = new AuthTurnstileVerifier({ fetch: slow, secret: 'sk', timeoutMs: 2 ** 31 - 1 })
    expect(await verifier.verify({ token: 't' })).toEqual({ success: true })
  })
})

describe.each(PROVIDERS)('$name reads the body by type, not by truthiness', ({ make, passing }) => {
  it('passes a well-formed success', async () => {
    expect((await make(stub(passing).fetch).verify({ token: 't' })).success).toBe(true)
  })

  it.each(['true', 1, {}])('refuses success: %j as malformed', async (success) => {
    expect(await make(stub({ ...passing, success }).fetch).verify({ token: 't' })).toMatchObject({
      errorCodes: ['malformed-response'],
      success: false,
    })
  })

  it.each(['should-be-array', ['valid', 42]])(
    'refuses error-codes: %j as malformed beside a success',
    async (codes) => {
      expect(await make(stub({ ...passing, 'error-codes': codes }).fetch).verify({ token: 't' })).toMatchObject({
        errorCodes: ['malformed-response'],
        success: false,
      })
    },
  )
})

describe('the fields a siteverify response carries beyond success', () => {
  it('checks the hostname the challenge was solved on when told which one to expect', async () => {
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

  it.each([
    ['expectedHostname', { action: 'login' }, 'invalid-expected-hostname'],
    ['expectedAction', { action: '', hostname: 'app.test' }, 'invalid-expected-action'],
  ] as const)(
    'refuses a per-call %s of nothing unsent, since the token solved without one would match',
    async (field, solved, code) => {
      const s = stub({ ...solved, success: true })
      const verifier = new AuthTurnstileVerifier({
        expectedAction: 'login',
        expectedHostname: 'app.test',
        fetch: s.fetch,
        secret: 'sk',
      })
      expect((await verifier.verify({ token: 't' })).success).toBe(false)
      expect(await verifier.verify({ [field]: '', token: 't' })).toEqual({ errorCodes: [code], success: false })
      expect(s.calls).toHaveLength(1)
    },
  )

  it('refuses an expected hostname that names nothing', () => {
    for (const expectedHostname of ['', [], ['app.test', '']]) {
      expect(() => new AuthTurnstileVerifier({ expectedHostname, secret: 'sk' })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
  })

  it('refuses a wired expected action of nothing, which a widget mounted without one would match', () => {
    expect(() => new AuthTurnstileVerifier({ expectedAction: '', secret: 'sk' })).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
    expect(() => new AuthTurnstileVerifier({ expectedAction: 'login', secret: 'sk' })).not.toThrow()
  })

  it('refuses a challenge older than the providers keep one valid', async () => {
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

  it('refuses a max age that is negative or not a finite number', () => {
    for (const maxChallengeAgeMs of [-1, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => new AuthTurnstileVerifier({ maxChallengeAgeMs, secret: 'sk' })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
  })

  it('carries the fields the provider sent rather than narrowing them away', async () => {
    const { verifier } = turnstile({ challenge_ts: new Date().toISOString(), hostname: 'app.test', success: true })
    expect(await verifier.verify({ token: 't' })).toMatchObject({ hostname: 'app.test', success: true })
    expect((await verifier.verify({ token: 't' })).challengeTs).toBeDefined()
  })
})

describe('what is sent to the provider', () => {
  it('posts the secret and the token in the body, and follows no redirect with them', async () => {
    const { calls, verifier } = turnstile({ success: true })
    await verifier.verify({ token: 'the-token' })
    expect(calls[0]?.url).not.toContain('sk')
    expect(calls[0]?.body).toContain('secret=sk')
    expect(calls[0]?.body).toContain('response=the-token')
    // A 307 re-posts the body, secret included, to a host the endpoint guard never saw.
    expect(calls[0]?.redirect).toBe('error')
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
    const { calls, verifier } = turnstile({ success: true })
    expect(await verifier.verify({ token: 'x'.repeat(2_000_000) })).toEqual({
      errorCodes: ['invalid-input-response', 'token-too-large'],
      success: false,
    })
    expect(calls).toHaveLength(0)
  })

  it('refuses a token that is not a string, which a parsed body can hand over, without relaying it', async () => {
    const { calls, verifier } = turnstile({ success: true })
    for (const raw of [`["${'x'.repeat(100_000)}"]`, '{"a":1}', '42']) {
      const body = JSON.parse(`{"token":${raw}}`)
      expect(await verifier.verify({ token: body.token })).toEqual({
        errorCodes: ['invalid-input-response'],
        success: false,
      })
    }
    expect(calls).toHaveLength(0)
    await verifier.verify({ token: 'x'.repeat(8_192) })
    expect(calls).toHaveLength(1)
  })

  it('refuses an endpoint that is plaintext or points inside the network', async () => {
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

  it('allows a plaintext endpoint when asked, but never a loopback or private one', async () => {
    const s = stub({ success: true })
    const verifier = new AuthTurnstileVerifier({
      allowInsecureEndpoint: true,
      endpoint: 'http://siteverify.test/x',
      fetch: s.fetch,
      secret: 'sk',
    })
    await verifier.verify({ token: 't' })
    expect(s.calls[0]?.url).toBe('http://siteverify.test/x')
    for (const endpoint of ['http://127.0.0.1:8080/x', 'http://localhost:8080/x', 'http://10.0.0.5/x']) {
      expect(() => new AuthTurnstileVerifier({ allowInsecureEndpoint: true, endpoint, secret: 'sk' })).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
    // Marked, so `strict()` refuses it in production.
    expect(verifier.__insecureCaptchaEndpoint).toBe(true)
  })

  it('refuses construction without a secret', () => {
    for (const make of [
      () => new AuthTurnstileVerifier({ secret: '' }),
      () => new AuthHCaptchaVerifier({ secret: '' }),
      () => new AuthRecaptchaV3Verifier({ secret: '' }),
    ]) {
      expect(make).toThrow(expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }))
    }
  })
})

describe('the reCAPTCHA v3 score threshold', () => {
  const recaptcha = (body: unknown, minScore?: number) =>
    new AuthRecaptchaV3Verifier({ fetch: stub(body).fetch, secret: 'sk', ...(minScore !== undefined && { minScore }) })

  it('passes at the threshold and fails just below it, reporting the score either way', async () => {
    expect(await recaptcha({ score: 0.5, success: true }).verify({ token: 't' })).toMatchObject({
      score: 0.5,
      success: true,
    })
    expect(await recaptcha({ score: 0.49, success: true }).verify({ token: 't' })).toMatchObject({
      errorCodes: ['score-too-low'],
      score: 0.49,
      success: false,
    })
  })

  it('an absent score is refused as its own thing, not read as zero', async () => {
    const result = await recaptcha({ success: true }).verify({ token: 't' })
    expect(result.success).toBe(false)
    expect(result.errorCodes).toContain('missing-score')
  })

  it('a zero threshold accepts any score the provider reports and still refuses none at all', async () => {
    expect((await recaptcha({ score: 0, success: true }, 0).verify({ token: 't' })).success).toBe(true)
    const none = await recaptcha({ success: true }, 0).verify({ token: 't' })
    expect(none.success).toBe(false)
    expect(none.errorCodes).toContain('missing-score')
  })

  it('refuses a threshold outside the range a score can take', async () => {
    for (const minScore of [-1, 5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => recaptcha({ success: true }, minScore)).toThrow(
        expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
      )
    }
  })

  it('a non-numeric or non-finite score fails closed as malformed', async () => {
    // JSON has no NaN, but `1e999` parses to Infinity.
    for (const body of [
      { score: '0.9', success: true },
      { score: null, success: true },
      '{"score":1e999,"success":true}',
    ]) {
      const result = await recaptcha(body).verify({ token: 't' })
      expect(result).toMatchObject({ errorCodes: ['malformed-response'], success: false })
    }
  })

  it('a score outside the documented range is passed through rather than rejected', async () => {
    // Nothing clamps to 0..1, so a provider or a proxy reporting 99 passes any threshold.
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
    const s = stub({ action: 'newsletter-signup', score: 0.9, success: true })
    const pinned = new AuthRecaptchaV3Verifier({ expectedAction: 'login', fetch: s.fetch, secret: 'sk' })
    const result = await pinned.verify({ token: 't' })
    expect(result.success).toBe(false)
    expect(result.errorCodes).toContain('action-mismatch')
    expect(result.action).toBe('newsletter-signup')

    const s2 = stub({ action: 'newsletter-signup', score: 0.9, success: true })
    const overridden = new AuthRecaptchaV3Verifier({ expectedAction: 'login', fetch: s2.fetch, secret: 'sk' })
    expect((await overridden.verify({ expectedAction: 'newsletter-signup', token: 't' })).success).toBe(true)
  })

  it('without an expected action on either side the action is reported, not enforced', async () => {
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
  const hcaptcha = (body: unknown, init?: ResponseInit) =>
    new AuthHCaptchaVerifier({ fetch: stub(body, init).fetch, secret: 'sk' })

  it('passes a successful response and carries the error codes on a failure', async () => {
    expect(await hcaptcha({ success: true }).verify({ token: 't' })).toEqual({ success: true })
    expect(
      await hcaptcha({ 'error-codes': ['invalid-input-response'], success: false }).verify({ token: 't' }),
    ).toEqual({
      errorCodes: ['invalid-input-response'],
      success: false,
    })
  })

  it('refuses a non-2xx for the same reason turnstile does', async () => {
    const result = await hcaptcha({ success: true }, { status: 500 }).verify({ token: 't' })
    expect(result).toEqual({ errorCodes: ['provider-http-500'], success: false })
  })

  it('refuses an expected action, which hCaptcha never returns, when wired and on a call', async () => {
    expect(() => new AuthHCaptchaVerifier(Object.assign({ secret: 'sk' }, { expectedAction: 'login' }))).toThrow(
      expect.objectContaining({ code: 'AUTH_MISCONFIGURED' }),
    )
    const s = stub({ success: true })
    const verifier = new AuthHCaptchaVerifier({ fetch: s.fetch, secret: 'sk' })
    expect(await verifier.verify({ expectedAction: 'login', token: 't' })).toEqual({
      errorCodes: ['expected-action-unsupported'],
      success: false,
    })
    expect(s.calls).toHaveLength(0)
    expect(await verifier.verify({ token: 't' })).toEqual({ success: true })
  })
})
