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

/** Factory around {@link AuthTurnstileVerifier}, for callers who prefer functions to `new`. */
export function authTurnstileVerifier(
  ...args: ConstructorParameters<typeof AuthTurnstileVerifier>
): AuthTurnstileVerifier {
  return new AuthTurnstileVerifier(...args)
}

/** Factory around {@link AuthHCaptchaVerifier}, for callers who prefer functions to `new`. */
export function authHCaptchaVerifier(
  ...args: ConstructorParameters<typeof AuthHCaptchaVerifier>
): AuthHCaptchaVerifier {
  return new AuthHCaptchaVerifier(...args)
}

/** Factory around {@link AuthRecaptchaV3Verifier}, for callers who prefer functions to `new`. */
export function authRecaptchaV3Verifier(
  ...args: ConstructorParameters<typeof AuthRecaptchaV3Verifier>
): AuthRecaptchaV3Verifier {
  return new AuthRecaptchaV3Verifier(...args)
}

/** Factory around {@link AuthNullCaptchaVerifier}, for callers who prefer functions to `new`. */
export function authNullCaptchaVerifier(
  ...args: ConstructorParameters<typeof AuthNullCaptchaVerifier>
): AuthNullCaptchaVerifier {
  return new AuthNullCaptchaVerifier(...args)
}

/** Factory around {@link AuthUnconfiguredCaptchaVerifier}, for callers who prefer functions to `new`. */
export function authUnconfiguredCaptchaVerifier(
  ...args: ConstructorParameters<typeof AuthUnconfiguredCaptchaVerifier>
): AuthUnconfiguredCaptchaVerifier {
  return new AuthUnconfiguredCaptchaVerifier(...args)
}
