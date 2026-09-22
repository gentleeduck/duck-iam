export const TURNSTILE_ENDPOINT = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
export const HCAPTCHA_ENDPOINT = 'https://api.hcaptcha.com/siteverify'
export const RECAPTCHA_ENDPOINT = 'https://www.google.com/recaptcha/api/siteverify'

export const CAPTCHA_TIMEOUT_DEFAULT_MS = 5_000

/** Every provider's token is under 4 KiB; the cap stops a client relaying megabytes through us. */
export const CAPTCHA_TOKEN_MAX_LENGTH = 8_192

/** Turnstile and hCaptcha both expire a token after 300s, so an older one was never going to pass. */
export const CAPTCHA_MAX_AGE_DEFAULT_MS = 300_000

/**
 * A `challenge_ts` slightly in the future is two clocks disagreeing, not a forgery. Wider than this
 * is not skew.
 */
export const CAPTCHA_FORWARD_SKEW_MS = 60_000

export const RECAPTCHA_MIN_SCORE_DEFAULT = 0.5
