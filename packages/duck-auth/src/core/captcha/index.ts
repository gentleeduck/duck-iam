/**
 * AuthCaptcha verifier contract + reference implementations for
 * Cloudflare Turnstile, hCaptcha, and Google reCAPTCHA v3. Apps wire
 * a verifier into provider begin/complete paths so a sign-in cannot
 * proceed without a fresh client-side challenge solution.
 */

import { AuthError } from '../errors'

/**
 * Cloudflare Turnstile verifier. Hits
 * `https://challenges.cloudflare.com/turnstile/v0/siteverify`.
 */
export class AuthTurnstileVerifier implements AuthCaptcha.IVerifier {
  readonly id = 'turnstile'
  private readonly _secret: string
  private readonly _fetch: typeof globalThis.fetch
  private readonly _endpoint: string

  constructor(cfg: { secret: string; fetch?: typeof globalThis.fetch; endpoint?: string }) {
    if (!cfg.secret) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthTurnstileVerifier requires a `secret`',
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
   */
  async verify(input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
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
      const parsed = parseSiteVerifyBasic(await readJsonSafe(res))
      if (!parsed) {
        return { success: false, errorCodes: ['malformed-response'] }
      }
      const out: AuthCaptcha.IVerifyResult = { success: parsed.success }
      if (parsed.errorCodes !== undefined) out.errorCodes = parsed.errorCodes
      return out
    } catch (err) {
      return {
        success: false,
        errorCodes: ['network-error', err instanceof Error ? err.message : String(err)],
      }
    }
  }
}

/** hCaptcha verifier. Hits `https://api.hcaptcha.com/siteverify`. */
export class AuthHCaptchaVerifier implements AuthCaptcha.IVerifier {
  readonly id = 'hcaptcha'
  private readonly _secret: string
  private readonly _fetch: typeof globalThis.fetch
  private readonly _endpoint: string

  constructor(cfg: { secret: string; fetch?: typeof globalThis.fetch; endpoint?: string }) {
    if (!cfg.secret) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthHCaptchaVerifier requires a `secret`',
      })
    }
    this._secret = cfg.secret
    this._fetch = cfg.fetch ?? globalThis.fetch
    this._endpoint = cfg.endpoint ?? 'https://api.hcaptcha.com/siteverify'
  }

  /** Verify an hCaptcha token via the siteverify endpoint. */
  async verify(input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
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
      const parsed = parseSiteVerifyBasic(await readJsonSafe(res))
      if (!parsed) {
        return { success: false, errorCodes: ['malformed-response'] }
      }
      const out: AuthCaptcha.IVerifyResult = { success: parsed.success }
      if (parsed.errorCodes !== undefined) out.errorCodes = parsed.errorCodes
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
 * `https://www.authGoogle.com/recaptcha/api/siteverify`.
 */
export class AuthRecaptchaV3Verifier implements AuthCaptcha.IVerifier {
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
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthRecaptchaV3Verifier requires a `secret`',
      })
    }
    this._secret = cfg.secret
    this._fetch = cfg.fetch ?? globalThis.fetch
    this._endpoint = cfg.endpoint ?? 'https://www.authGoogle.com/recaptcha/api/siteverify'
    this._minScore = cfg.minScore ?? 0.5
  }

  /**
   * Verify a reCAPTCHA v3 token. `success` is true only when the
   * provider returns success AND the score is >= minScore AND (when
   * supplied) the action matches `expectedAction`.
   */
  async verify(input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
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
      const parsed = parseSiteVerifyRecaptchaV3(await readJsonSafe(res))
      if (!parsed) {
        return { success: false, errorCodes: ['malformed-response'] }
      }
      const scoreOk = (parsed.score ?? 0) >= this._minScore
      const actionOk = input.expectedAction === undefined || parsed.action === input.expectedAction
      const out: AuthCaptcha.IVerifyResult = { success: parsed.success && scoreOk && actionOk }
      if (parsed.score !== undefined) out.score = parsed.score
      if (parsed.errorCodes !== undefined) out.errorCodes = parsed.errorCodes
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
 */
export class AuthNullCaptchaVerifier implements AuthCaptcha.IVerifier {
  readonly id = 'null'
  async verify(_input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
    return { success: true }
  }
}

/** Validators for siteverify provider responses. */
interface ParsedSiteVerifyBasic {
  success: boolean
  errorCodes?: string[]
}

interface ParsedSiteVerifyRecaptchaV3 extends ParsedSiteVerifyBasic {
  score?: number
  action?: string
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

async function readJsonSafe(res: Response): Promise<unknown> {
  try {
    return await res.json()
  } catch {
    return null
  }
}

function parseErrorCodes(raw: unknown): string[] | null | undefined {
  if (raw === undefined) return undefined
  if (!Array.isArray(raw)) return null
  const out: string[] = []
  for (const c of raw) {
    if (typeof c !== 'string') return null
    out.push(c)
  }
  return out
}

function parseSiteVerifyBasic(raw: unknown): ParsedSiteVerifyBasic | null {
  if (!isPlainObject(raw)) return null
  if (typeof raw.success !== 'boolean') return null
  const errorCodes = parseErrorCodes(raw['error-codes'])
  if (errorCodes === null) return null
  const out: ParsedSiteVerifyBasic = { success: raw.success }
  if (errorCodes !== undefined) out.errorCodes = errorCodes
  return out
}

function parseSiteVerifyRecaptchaV3(raw: unknown): ParsedSiteVerifyRecaptchaV3 | null {
  const base = parseSiteVerifyBasic(raw)
  if (!base) return null
  // base parsed successfully -> raw is also a plain object
  if (!isPlainObject(raw)) return null
  const out: ParsedSiteVerifyRecaptchaV3 = base
  if (raw.score !== undefined) {
    if (typeof raw.score !== 'number' || !Number.isFinite(raw.score)) return null
    out.score = raw.score
  }
  if (raw.action !== undefined) {
    if (typeof raw.action !== 'string') return null
    out.action = raw.action
  }
  return out
}

export namespace AuthCaptcha {
  export interface IVerifier {
    readonly id: string
    verify(input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult>
  }

  export interface IVerifyInput {
    token: string
    remoteIp?: string
    /**
     * Caller-declared expected action; reCAPTCHA v3 returns the action
     * the client tag emitted and the verifier asserts equality.
     */
    expectedAction?: string
  }

  export interface IVerifyResult {
    success: boolean
    /** Score 0..1 (reCAPTCHA v3); undefined for boolean providers. */
    score?: number
    /** AuthProvider-side error tokens (`'invalid-input-secret'`, etc.). */
    errorCodes?: string[]
  }
}
