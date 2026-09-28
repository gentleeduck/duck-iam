/** The verifiers behind `auth.captcha`. Nothing in this package calls one: configuring `cfg.captcha`
 *  makes a verifier reachable, and the host is what puts `verify` in front of a sign-in. */

import { env } from 'node:process'
import { AuthError } from '../errors'
import {
  HCAPTCHA_ENDPOINT,
  RECAPTCHA_ENDPOINT,
  RECAPTCHA_MIN_SCORE_DEFAULT,
  TURNSTILE_ENDPOINT,
} from './captcha.constants'
import {
  parseSiteVerifyBasic,
  parseSiteVerifyRecaptchaV3,
  type ResolvedCaptchaCfg,
  resolveCaptchaCfg,
  siteVerify,
  toResult,
} from './captcha.siteverify'
import type { AuthCaptcha } from './captcha.types'

/** Cloudflare Turnstile verifier. */
export class AuthTurnstileVerifier implements AuthCaptcha.IVerifier {
  readonly id = 'turnstile'
  /** Read by `strict()`, which refuses a plaintext endpoint in production: the secret would go in the clear. */
  readonly __insecureCaptchaEndpoint: boolean
  private readonly _cfg: ResolvedCaptchaCfg

  constructor(cfg: AuthCaptcha.ICfgBase & { expectedAction?: string }) {
    this._cfg = resolveCaptchaCfg(cfg, 'AuthTurnstileVerifier', TURNSTILE_ENDPOINT)
    this.__insecureCaptchaEndpoint = this._cfg.endpoint.startsWith('http:')
  }

  async verify(input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
    const outcome = await siteVerify(this._cfg, input, parseSiteVerifyBasic)
    if (!outcome.ok) return outcome.result
    return toResult(outcome.parsed, outcome.parsed.success)
  }
}

/** hCaptcha verifier. */
export class AuthHCaptchaVerifier implements AuthCaptcha.IVerifier {
  readonly id = 'hcaptcha'
  /** Read by `strict()`, which refuses a plaintext endpoint in production: the secret would go in the clear. */
  readonly __insecureCaptchaEndpoint: boolean
  private readonly _cfg: ResolvedCaptchaCfg

  constructor(cfg: AuthCaptcha.ICfgBase) {
    // hCaptcha returns no `action`, so expecting one would refuse every call. The type omits it; this
    // catches a widened object.
    if (Reflect.get(cfg, 'expectedAction') !== undefined) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthHCaptchaVerifier takes no expectedAction; hCaptcha does not return one',
      })
    }
    this._cfg = resolveCaptchaCfg(cfg, 'AuthHCaptchaVerifier', HCAPTCHA_ENDPOINT)
    this.__insecureCaptchaEndpoint = this._cfg.endpoint.startsWith('http:')
  }

  async verify(input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
    // The shared input type allows one, so it is refused by name rather than as a mismatch.
    if (input.expectedAction !== undefined) {
      return { errorCodes: ['expected-action-unsupported'], success: false }
    }
    const outcome = await siteVerify(this._cfg, input, parseSiteVerifyBasic)
    if (!outcome.ok) return outcome.result
    return toResult(outcome.parsed, outcome.parsed.success)
  }
}

/** reCAPTCHA v3 verifier: passes only at or above `minScore`, by default Google's suggested 0.5. */
export class AuthRecaptchaV3Verifier implements AuthCaptcha.IVerifier {
  readonly id = 'recaptcha-v3'
  /** Read by `strict()`, which refuses a plaintext endpoint in production: the secret would go in the clear. */
  readonly __insecureCaptchaEndpoint: boolean
  private readonly _cfg: ResolvedCaptchaCfg
  private readonly _minScore: number

  constructor(cfg: AuthCaptcha.ICfgBase & { minScore?: number; expectedAction?: string }) {
    this._cfg = resolveCaptchaCfg(cfg, 'AuthRecaptchaV3Verifier', RECAPTCHA_ENDPOINT)
    this.__insecureCaptchaEndpoint = this._cfg.endpoint.startsWith('http:')
    const minScore = cfg.minScore ?? RECAPTCHA_MIN_SCORE_DEFAULT
    // Outside 0..1 is a mistake with a direction: below passes every bot, above or NaN refuses every human.
    if (!Number.isFinite(minScore) || minScore < 0 || minScore > 1) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthRecaptchaV3Verifier minScore must be a finite number between 0 and 1',
      })
    }
    this._minScore = minScore
  }

  /** Refuses an absent score, or one under `minScore`. */
  async verify(input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
    const outcome = await siteVerify(this._cfg, input, parseSiteVerifyRecaptchaV3)
    if (!outcome.ok) return outcome.result
    const parsed = outcome.parsed

    // An absent score is not a low one: under `minScore: 0`, `score ?? 0` passed a response carrying none.
    if (parsed.success && parsed.score === undefined) {
      return { ...toResult(parsed, false), errorCodes: [...(parsed.errorCodes ?? []), 'missing-score'] }
    }
    const scoreOk = (parsed.score ?? 0) >= this._minScore
    const out = toResult(parsed, parsed.success && scoreOk)
    if (parsed.success && !scoreOk) out.errorCodes = [...(out.errorCodes ?? []), 'score-too-low']
    return out
  }
}

/** Always-pass verifier for tests. Refuses to construct under `NODE_ENV=production` without
 *  `development`: a verifier that cannot fail looks exactly like one that works. */
export class AuthNullCaptchaVerifier implements AuthCaptcha.IVerifier {
  readonly id = 'null'
  /** Read by `strict()`: `id` is a caller-visible string a foreign verifier may also use. */
  readonly __isNullCaptcha = true as const

  constructor(cfg?: { development?: boolean }) {
    if (env.NODE_ENV === 'production' && !cfg?.development) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthNullCaptchaVerifier passes every challenge and is not production ready',
      })
    }
  }

  /** Always succeeds. */
  async verify(_input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
    return { success: true }
  }
}

/** What `auth.captcha` is when `cfg.captcha` was not supplied: every call fails `captcha-not-configured`. */
export class AuthUnconfiguredCaptchaVerifier implements AuthCaptcha.IVerifier {
  readonly id = 'unconfigured'
  async verify(_input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
    return { success: false, errorCodes: ['captcha-not-configured'] }
  }
}
