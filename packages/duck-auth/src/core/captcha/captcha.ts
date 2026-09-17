/**
 * Verifier contract implementations for Cloudflare Turnstile, hCaptcha and Google reCAPTCHA v3.
 * Apps wire one into provider begin/complete paths so a sign-in cannot proceed without a fresh
 * client-side challenge solution.
 */

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
} from './captcha.siteverify'
import type { AuthCaptcha } from './captcha.types'

/** Cloudflare Turnstile verifier. */
export class AuthTurnstileVerifier implements AuthCaptcha.IVerifier {
  readonly id = 'turnstile'
  private readonly _cfg: ResolvedCaptchaCfg

  constructor(cfg: AuthCaptcha.ICfgBase) {
    this._cfg = resolveCaptchaCfg(cfg, 'AuthTurnstileVerifier', TURNSTILE_ENDPOINT)
  }

  /** Never throws: a network error or a provider rejection is `success: false` for the caller to react to. */
  async verify(input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
    const outcome = await siteVerify(this._cfg, input, parseSiteVerifyBasic)
    if (!outcome.ok) return outcome.result
    return toResult(outcome.parsed, outcome.parsed.success)
  }
}

/** hCaptcha verifier. */
export class AuthHCaptchaVerifier implements AuthCaptcha.IVerifier {
  readonly id = 'hcaptcha'
  private readonly _cfg: ResolvedCaptchaCfg

  constructor(cfg: AuthCaptcha.ICfgBase) {
    this._cfg = resolveCaptchaCfg(cfg, 'AuthHCaptchaVerifier', HCAPTCHA_ENDPOINT)
  }

  async verify(input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
    const outcome = await siteVerify(this._cfg, input, parseSiteVerifyBasic)
    if (!outcome.ok) return outcome.result
    return toResult(outcome.parsed, outcome.parsed.success)
  }
}

/**
 * Google reCAPTCHA v3 verifier. Returns a score 0..1 and passes only at or above `minScore`
 * (Google recommends 0.5).
 */
export class AuthRecaptchaV3Verifier implements AuthCaptcha.IVerifier {
  readonly id = 'recaptcha-v3'
  private readonly _cfg: ResolvedCaptchaCfg
  private readonly _minScore: number
  private readonly _expectedAction: string | undefined

  constructor(cfg: AuthCaptcha.ICfgBase & { minScore?: number; expectedAction?: string }) {
    this._cfg = resolveCaptchaCfg(cfg, 'AuthRecaptchaV3Verifier', RECAPTCHA_ENDPOINT)
    const minScore = cfg.minScore ?? RECAPTCHA_MIN_SCORE_DEFAULT
    // A threshold outside the range reCAPTCHA can report is not a policy, it is a mistake with a
    // direction: below zero passes every bot, above one walls out every human, and a NaN read from
    // a mis-parsed environment variable does the second silently.
    if (!Number.isFinite(minScore) || minScore < 0 || minScore > 1) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthRecaptchaV3Verifier minScore must be a finite number between 0 and 1',
      })
    }
    this._minScore = minScore
    this._expectedAction = cfg.expectedAction
  }

  async verify(input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
    const outcome = await siteVerify(this._cfg, input, parseSiteVerifyRecaptchaV3)
    if (!outcome.ok) return outcome.result
    const parsed = outcome.parsed

    // An absent score is not a low score. `(score ?? 0) >= minScore` collapsed the two, so
    // `minScore: 0`, which reads as "accept any score", also accepted a response reporting none.
    if (parsed.success && parsed.score === undefined) {
      return { ...toResult(parsed, false), errorCodes: [...(parsed.errorCodes ?? []), 'missing-score'] }
    }
    const scoreOk = (parsed.score ?? 0) >= this._minScore
    const expectedAction = input.expectedAction ?? this._expectedAction
    const actionOk = expectedAction === undefined || parsed.action === expectedAction

    const out = toResult(parsed, parsed.success && scoreOk && actionOk)
    if (!actionOk) out.errorCodes = [...(out.errorCodes ?? []), 'action-mismatch']
    if (parsed.success && !scoreOk) out.errorCodes = [...(out.errorCodes ?? []), 'score-too-low']
    return out
  }
}

/**
 * Always-pass verifier for tests. Refuses to construct under `NODE_ENV=production`, following
 * `MemoryIdempotency`: wiring it there silently removes captcha from every path it fronts, and a
 * thing that cannot fail is indistinguishable from a thing that works.
 */
export class AuthNullCaptchaVerifier implements AuthCaptcha.IVerifier {
  readonly id = 'null'

  constructor(cfg?: { development?: boolean }) {
    if (env.NODE_ENV === 'production' && !cfg?.development) {
      throw new AuthError('AUTH_MISCONFIGURED', {
        detail: 'AuthNullCaptchaVerifier passes every challenge and is not production ready',
      })
    }
  }

  async verify(_input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
    return { success: true }
  }
}

/**
 * What `auth.captcha` is when `cfg.captcha` was not supplied. Every call fails with
 * `captcha-not-configured`.
 *
 * The alternative - defaulting to {@link AuthNullCaptchaVerifier} - makes the common wiring mistake
 * invisible: a host writes `if (!(await auth.captcha.verify(...)).success) throw`, ships with the
 * secret unset, and the challenge passes every bot in production while the code reads as though a
 * captcha is enforced. A host that never calls `auth.captcha` is unaffected either way, so the only
 * behaviour this changes is the one that was wrong.
 */
export class AuthUnconfiguredCaptchaVerifier implements AuthCaptcha.IVerifier {
  readonly id = 'unconfigured'
  async verify(_input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult> {
    return { success: false, errorCodes: ['captcha-not-configured'] }
  }
}

/**
 * Carry the fields the provider sent through to the caller. They used to be narrowed away, so a
 * caller wanting to apply its own hostname or action rule could not: it was told only pass or fail.
 */
function toResult(
  parsed: { errorCodes?: string[]; hostname?: string; challengeTs?: string; score?: number; action?: string },
  success: boolean,
): AuthCaptcha.IVerifyResult {
  const out: AuthCaptcha.IVerifyResult = { success }
  if (parsed.score !== undefined) out.score = parsed.score
  if (parsed.errorCodes !== undefined) out.errorCodes = parsed.errorCodes
  if (parsed.hostname !== undefined) out.hostname = parsed.hostname
  if (parsed.action !== undefined) out.action = parsed.action
  if (parsed.challengeTs !== undefined) out.challengeTs = parsed.challengeTs
  return out
}
