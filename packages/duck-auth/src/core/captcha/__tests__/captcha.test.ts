import { describe, expect, it, vi } from 'vitest'
import { AuthHCaptchaVerifier, AuthNullCaptchaVerifier, AuthRecaptchaV3Verifier, AuthTurnstileVerifier } from '../index'

function makeFetch(response: Record<string, unknown>, ok = true): typeof globalThis.fetch {
  return vi.fn(async () => ({
    ok,
    json: async () => response,
  })) as unknown as typeof globalThis.fetch
}

describe('AuthTurnstileVerifier', () => {
  it('refuses construction without secret', () => {
    expect(() => new AuthTurnstileVerifier({ secret: '' })).toThrowError(
      expect.objectContaining({ code: 'AUTH/MISCONFIGURED' }),
    )
  })

  it('verify true when siteverify returns success', async () => {
    const v = new AuthTurnstileVerifier({ secret: 'x', fetch: makeFetch({ success: true }) })
    expect(await v.verify({ token: 'abc' })).toEqual({ success: true })
  })

  it('verify false + carries error-codes', async () => {
    const v = new AuthTurnstileVerifier({
      secret: 'x',
      fetch: makeFetch({ success: false, 'error-codes': ['invalid-input-response'] }),
    })
    const result = await v.verify({ token: 'abc' })
    expect(result.success).toBe(false)
    expect(result.errorCodes).toEqual(['invalid-input-response'])
  })

  it('empty token returns missing-input-response without network call', async () => {
    const fetchSpy = makeFetch({ success: true })
    const v = new AuthTurnstileVerifier({ secret: 'x', fetch: fetchSpy })
    const result = await v.verify({ token: '' })
    expect(result.success).toBe(false)
    expect(result.errorCodes).toEqual(['missing-input-response'])
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it('network throw surfaces as network-error', async () => {
    const v = new AuthTurnstileVerifier({
      secret: 'x',
      fetch: vi.fn(async () => {
        throw new Error('econnreset')
      }) as unknown as typeof globalThis.fetch,
    })
    const result = await v.verify({ token: 'abc' })
    expect(result.success).toBe(false)
    expect(result.errorCodes?.[0]).toBe('network-error')
  })

  it('forwards remoteip when supplied', async () => {
    const spy = makeFetch({ success: true })
    const v = new AuthTurnstileVerifier({ secret: 'x', fetch: spy })
    await v.verify({ token: 'abc', remoteIp: '1.2.3.4' })
    const body = (spy as unknown as ReturnType<typeof vi.fn>).mock.calls[0]![1]!.body as string
    expect(body).toContain('remoteip=1.2.3.4')
  })
})

describe('AuthHCaptchaVerifier', () => {
  it('verify true when siteverify returns success', async () => {
    const v = new AuthHCaptchaVerifier({ secret: 'x', fetch: makeFetch({ success: true }) })
    expect(await v.verify({ token: 'abc' })).toEqual({ success: true })
  })
})

describe('AuthRecaptchaV3Verifier', () => {
  it('success requires success + score >= minScore', async () => {
    const v = new AuthRecaptchaV3Verifier({
      secret: 'x',
      minScore: 0.7,
      fetch: makeFetch({ success: true, score: 0.9, action: 'signin' }),
    })
    const result = await v.verify({ token: 'abc' })
    expect(result.success).toBe(true)
    expect(result.score).toBe(0.9)
  })

  it('success false when score below threshold', async () => {
    const v = new AuthRecaptchaV3Verifier({
      secret: 'x',
      minScore: 0.7,
      fetch: makeFetch({ success: true, score: 0.3, action: 'signin' }),
    })
    const result = await v.verify({ token: 'abc' })
    expect(result.success).toBe(false)
    expect(result.errorCodes).toContain('score-too-low')
  })

  it('success false when action mismatches expectedAction', async () => {
    const v = new AuthRecaptchaV3Verifier({
      secret: 'x',
      fetch: makeFetch({ success: true, score: 0.9, action: 'submit' }),
    })
    const result = await v.verify({ token: 'abc', expectedAction: 'signin' })
    expect(result.success).toBe(false)
    expect(result.errorCodes).toContain('action-mismatch')
  })
})

describe('AuthNullCaptchaVerifier', () => {
  it('always succeeds (test helper)', async () => {
    const v = new AuthNullCaptchaVerifier()
    expect(await v.verify({ token: '' })).toEqual({ success: true })
  })
})

describe('siteverify response validation (bot-defense bypass defense)', () => {
  it('Turnstile rejects success as a string (would have been truthy-bypassed previously)', async () => {
    const v = new AuthTurnstileVerifier({ secret: 'x', fetch: makeFetch({ success: 'true' }) })
    const result = await v.verify({ token: 'abc' })
    expect(result.success).toBe(false)
    expect(result.errorCodes).toContain('malformed-response')
  })

  it('Turnstile rejects success as a non-empty object (was truthy -> bypass)', async () => {
    const v = new AuthTurnstileVerifier({ secret: 'x', fetch: makeFetch({ success: { evil: true } }) })
    const result = await v.verify({ token: 'abc' })
    expect(result.success).toBe(false)
  })

  it('Turnstile rejects success as the number 1 (truthy)', async () => {
    const v = new AuthTurnstileVerifier({ secret: 'x', fetch: makeFetch({ success: 1 }) })
    const result = await v.verify({ token: 'abc' })
    expect(result.success).toBe(false)
  })

  it('hCaptcha rejects non-boolean success', async () => {
    const v = new AuthHCaptchaVerifier({ secret: 'x', fetch: makeFetch({ success: 'yes' }) })
    expect((await v.verify({ token: 'abc' })).success).toBe(false)
  })

  it('reCAPTCHA v3 rejects non-boolean success even when score+action look reasonable', async () => {
    const v = new AuthRecaptchaV3Verifier({
      secret: 'x',
      fetch: makeFetch({ success: 'true', score: 0.9, action: 'signin' }),
    })
    const result = await v.verify({ token: 'abc' })
    expect(result.success).toBe(false)
    expect(result.errorCodes).toContain('malformed-response')
  })

  it('reCAPTCHA v3 rejects non-numeric score (string-coercion bypass at threshold check)', async () => {
    const v = new AuthRecaptchaV3Verifier({
      secret: 'x',
      fetch: makeFetch({ success: true, score: '0.9', action: 'signin' }),
    })
    const result = await v.verify({ token: 'abc' })
    expect(result.success).toBe(false)
  })

  it('Turnstile rejects non-array error-codes', async () => {
    const v = new AuthTurnstileVerifier({
      secret: 'x',
      fetch: makeFetch({ success: true, 'error-codes': 'should-be-array' }),
    })
    expect((await v.verify({ token: 'abc' })).success).toBe(false)
  })

  it('Turnstile rejects array of non-strings in error-codes', async () => {
    const v = new AuthTurnstileVerifier({
      secret: 'x',
      fetch: makeFetch({ success: true, 'error-codes': ['valid', 42] }),
    })
    expect((await v.verify({ token: 'abc' })).success).toBe(false)
  })
})
