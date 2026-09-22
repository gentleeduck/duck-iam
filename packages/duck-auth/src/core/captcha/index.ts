/**
 * AuthCaptcha verifier contract + reference implementations for Cloudflare Turnstile, hCaptcha and
 * Google reCAPTCHA v3.
 */

export {
  AuthHCaptchaVerifier,
  AuthNullCaptchaVerifier,
  AuthRecaptchaV3Verifier,
  AuthTurnstileVerifier,
  AuthUnconfiguredCaptchaVerifier,
} from './captcha'
export {
  CAPTCHA_MAX_AGE_DEFAULT_MS,
  CAPTCHA_TIMEOUT_DEFAULT_MS,
  CAPTCHA_TOKEN_MAX_LENGTH,
} from './captcha.constants'
export type { AuthCaptcha } from './captcha.types'

import {
  AuthHCaptchaVerifier,
  AuthNullCaptchaVerifier,
  AuthRecaptchaV3Verifier,
  AuthTurnstileVerifier,
  AuthUnconfiguredCaptchaVerifier,
} from './captcha'

/** Cloudflare Turnstile verifier. */
export function authTurnstileVerifier(
  ...args: ConstructorParameters<typeof AuthTurnstileVerifier>
): AuthTurnstileVerifier {
  return new AuthTurnstileVerifier(...args)
}

/** hCaptcha verifier. */
export function authHCaptchaVerifier(
  ...args: ConstructorParameters<typeof AuthHCaptchaVerifier>
): AuthHCaptchaVerifier {
  return new AuthHCaptchaVerifier(...args)
}

/** reCAPTCHA v3 verifier, passing only at or above the configured `minScore`. */
export function authRecaptchaV3Verifier(
  ...args: ConstructorParameters<typeof AuthRecaptchaV3Verifier>
): AuthRecaptchaV3Verifier {
  return new AuthRecaptchaV3Verifier(...args)
}

/** Always-passing verifier for tests; refuses to construct in production. */
export function authNullCaptchaVerifier(
  ...args: ConstructorParameters<typeof AuthNullCaptchaVerifier>
): AuthNullCaptchaVerifier {
  return new AuthNullCaptchaVerifier(...args)
}

/** What `auth.captcha` is when none was configured: every call fails `captcha-not-configured`. */
export function authUnconfiguredCaptchaVerifier(
  ...args: ConstructorParameters<typeof AuthUnconfiguredCaptchaVerifier>
): AuthUnconfiguredCaptchaVerifier {
  return new AuthUnconfiguredCaptchaVerifier(...args)
}
