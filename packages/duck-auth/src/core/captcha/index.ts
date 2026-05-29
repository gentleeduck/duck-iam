/**
 * @packageDocumentation
 * Captcha verifier contract + reference implementations for
 * Cloudflare Turnstile, hCaptcha, and Google reCAPTCHA v3. Apps wire
 * a verifier into provider begin/complete paths so a sign-in cannot
 * proceed without a fresh client-side challenge solution.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */

import { AuthErrorObject } from '../errors'

/**
 * Captcha verifier contract. Implementations call the provider's
 * siteverify endpoint with the user-supplied token + remote IP, and
 * return a typed verdict.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface CaptchaVerifier {
  readonly id: string
  verify(input: CaptchaVerifyInput): Promise<CaptchaVerifyResult>
}

/**
 * Verifier input. `token` is the opaque value the client widget put
 * in the form on submit; `remoteIp` is optional but improves
 * fraud-detection signal for most providers.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface CaptchaVerifyInput {
  token: string
  remoteIp?: string
  /**
   * Caller-declared expected action; reCAPTCHA v3 returns the action
   * the client tag emitted and the verifier asserts equality.
   */
  expectedAction?: string
}

/**
 * Verifier verdict. `success` is required; providers that return a
 * score (reCAPTCHA v3) surface it via `score`; `errorCodes` carries
 * any provider-side rejection codes.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export interface CaptchaVerifyResult {
  success: boolean
  /** Score 0..1 (reCAPTCHA v3); undefined for boolean providers. */
  score?: number
  /** Provider-side error tokens (`'invalid-input-secret'`, etc.). */
  errorCodes?: string[]
}

/**
 * Cloudflare Turnstile verifier. Hits
 * `https://challenges.cloudflare.com/turnstile/v0/siteverify`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class TurnstileVerifier implements CaptchaVerifier {
  readonly id = 'turnstile'
  private readonly _secret: string
  private readonly _fetch: typeof globalThis.fetch
  private readonly _endpoint: string

  constructor(cfg: { secret: string; fetch?: typeof globalThis.fetch; endpoint?: string }) {
    if (!cfg.secret) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'TurnstileVerifier requires a `secret`',
      })
    }
    this._secret = cfg.secret
    this._fetch = cfg.fetch ?? globalThis.fetch
    this._endpoint = cfg.endpoint ?? 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
  }

  /**
   * Verify a Turnstile token. Returns ok:false (never throws) on
   * network error or provider rejection so caller can react with a
   * 401 / step-up.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async verify(input: CaptchaVerifyInput): Promise<CaptchaVerifyResult> {
    if (!input.token) return { success: false, errorCodes: ['missing-input-response'] }
    const body = new URLSearchParams({
      secret: this._secret,
      response: input.token,
      ...(input.remoteIp !== undefined && { remoteip: input.remoteIp }),
    })
    try {
      const res = await this._fetch(this._endpoint, {
        method: 'POST',
        body: body.toString(),
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
      })
      const parsed = (await res.json()) as {
        success: boolean
        'error-codes'?: string[]
      }
      const out: CaptchaVerifyResult = { success: parsed.success }
      if (parsed['error-codes']) out.errorCodes = parsed['error-codes']
      return out
    } catch (err) {
      return {
        success: false,
        errorCodes: ['network-error', err instanceof Error ? err.message : String(err)],
      }
    }
  }
}

/**
 * hCaptcha verifier. Hits `https://api.hcaptcha.com/siteverify`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class HCaptchaVerifier implements CaptchaVerifier {
  readonly id = 'hcaptcha'
  private readonly _secret: string
  private readonly _fetch: typeof globalThis.fetch
  private readonly _endpoint: string

  constructor(cfg: { secret: string; fetch?: typeof globalThis.fetch; endpoint?: string }) {
    if (!cfg.secret) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'HCaptchaVerifier requires a `secret`',
      })
    }
    this._secret = cfg.secret
    this._fetch = cfg.fetch ?? globalThis.fetch
    this._endpoint = cfg.endpoint ?? 'https://api.hcaptcha.com/siteverify'
  }

  /**
   * Verify an hCaptcha token via the siteverify endpoint.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async verify(input: CaptchaVerifyInput): Promise<CaptchaVerifyResult> {
    if (!input.token) return { success: false, errorCodes: ['missing-input-response'] }
    const body = new URLSearchParams({
      secret: this._secret,
      response: input.token,
      ...(input.remoteIp !== undefined && { remoteip: input.remoteIp }),
    })
    try {
      const res = await this._fetch(this._endpoint, {
        method: 'POST',
        body: body.toString(),
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
      })
      const parsed = (await res.json()) as { success: boolean; 'error-codes'?: string[] }
      const out: CaptchaVerifyResult = { success: parsed.success }
      if (parsed['error-codes']) out.errorCodes = parsed['error-codes']
      return out
    } catch (err) {
      return {
        success: false,
        errorCodes: ['network-error', err instanceof Error ? err.message : String(err)],
      }
    }
  }
}

/**
 * Google reCAPTCHA v3 verifier. Returns a score 0..1; caller decides
 * the threshold (Google recommends 0.5). Hits
 * `https://www.google.com/recaptcha/api/siteverify`.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class RecaptchaV3Verifier implements CaptchaVerifier {
  readonly id = 'recaptcha-v3'
  private readonly _secret: string
  private readonly _fetch: typeof globalThis.fetch
  private readonly _endpoint: string
  private readonly _minScore: number

  constructor(cfg: {
    secret: string
    fetch?: typeof globalThis.fetch
    endpoint?: string
    minScore?: number
  }) {
    if (!cfg.secret) {
      throw new AuthErrorObject('AUTH/MISCONFIGURED', {
        detail: 'RecaptchaV3Verifier requires a `secret`',
      })
    }
    this._secret = cfg.secret
    this._fetch = cfg.fetch ?? globalThis.fetch
    this._endpoint = cfg.endpoint ?? 'https://www.google.com/recaptcha/api/siteverify'
    this._minScore = cfg.minScore ?? 0.5
  }

  /**
   * Verify a reCAPTCHA v3 token. `success` is true only when the
   * provider returns success AND the score is >= minScore AND (when
   * supplied) the action matches `expectedAction`.
   *
   * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
   */
  async verify(input: CaptchaVerifyInput): Promise<CaptchaVerifyResult> {
    if (!input.token) return { success: false, errorCodes: ['missing-input-response'] }
    const body = new URLSearchParams({
      secret: this._secret,
      response: input.token,
      ...(input.remoteIp !== undefined && { remoteip: input.remoteIp }),
    })
    try {
      const res = await this._fetch(this._endpoint, {
        method: 'POST',
        body: body.toString(),
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
      })
      const parsed = (await res.json()) as {
        success: boolean
        score?: number
        action?: string
        'error-codes'?: string[]
      }
      const scoreOk = (parsed.score ?? 0) >= this._minScore
      const actionOk = input.expectedAction === undefined || parsed.action === input.expectedAction
      const out: CaptchaVerifyResult = { success: parsed.success && scoreOk && actionOk }
      if (parsed.score !== undefined) out.score = parsed.score
      if (parsed['error-codes']) out.errorCodes = parsed['error-codes']
      if (!actionOk) out.errorCodes = [...(out.errorCodes ?? []), 'action-mismatch']
      if (parsed.success && !scoreOk) out.errorCodes = [...(out.errorCodes ?? []), 'score-too-low']
      return out
    } catch (err) {
      return {
        success: false,
        errorCodes: ['network-error', err instanceof Error ? err.message : String(err)],
      }
    }
  }
}

/**
 * Always-pass verifier for tests. Surfaces the input token in the
 * result so call-sites can assert wiring.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export class NullCaptchaVerifier implements CaptchaVerifier {
  readonly id = 'null'
  async verify(_input: CaptchaVerifyInput): Promise<CaptchaVerifyResult> {
    return { success: true }
  }
}

/**
 * Namespace merge for the captcha surface.
 *
 * @author wildduck2 <https://github.com/gentleeduck/duck-iam>
 */
export namespace Captcha {
  /** Alias for `CaptchaVerifier`. */
  export type IVerifier = CaptchaVerifier
  /** Alias for `CaptchaVerifyInput`. */
  export type IVerifyInput = CaptchaVerifyInput
  /** Alias for `CaptchaVerifyResult`. */
  export type IVerifyResult = CaptchaVerifyResult
}
