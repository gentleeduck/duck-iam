/** The verifier contract every built-in captcha implementation satisfies. */
export namespace AuthCaptcha {
  /** One captcha provider. `auth.captcha` is whichever of these was configured. */
  export interface IVerifier {
    /** Stable per implementation - `'turnstile'`, `'hcaptcha'`, `'recaptcha-v3'`, `'null'`,
     *  `'unconfigured'`. A caller-visible string, so it is not what `strict()` keys its null check on. */
    readonly id: string
    /** Never throws: a network fault, a timeout and a provider rejection are all `success: false`. */
    verify(input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult>
  }

  /** One challenge to check. */
  export interface IVerifyInput {
    /** The solution the widget handed the browser. Refused unsent when not a string, or over
     *  `CAPTCHA_TOKEN_MAX_LENGTH`. */
    token: string
    /** The client address, passed to the provider as `remoteip` when supplied. */
    remoteIp?: string
    /**
     * Expected action, asserted against the one Turnstile and reCAPTCHA v3 echo back. Overrides the
     * verifier's own when both are set, so one wiring distinguishes sign-in from sign-up.
     *
     * WARN: hCaptcha answers with no `action`, so asking for one there refuses every call.
     */
    expectedAction?: string
    /**
     * Overrides the verifier's `expectedHostname` for this one call.
     *
     * WARN: it replaces the configured list rather than narrowing it, so a value read off the request —
     * the `Host` header, a body field — turns the operator's policy off for that call.
     */
    expectedHostname?: string
  }

  /** What the verifier concluded, and what the provider said. */
  export interface IVerifyResult {
    /** Whether the challenge passed every check: the provider's own verdict, the hostname, the action,
     *  the challenge age, and the score where there is one. */
    success: boolean
    /** Score 0..1 (reCAPTCHA v3); undefined for boolean providers. */
    score?: number
    /** Why it failed: the provider's own wire codes and this package's, in one array. Not
     *  `AuthError.Code` - a verifier never throws, and most of these are the provider's strings. */
    errorCodes?: string[]
    /** The thrown message behind `network-error`. Not for display: it can name the endpoint or a proxy. */
    detail?: string
    /** Reported whether or not it was checked. */
    hostname?: string
    /** The action the widget was mounted with, for the providers that echo one. */
    action?: string
    /** When the challenge was solved, as the provider spelled it. */
    challengeTs?: string
  }

  /** What every siteverify-style verifier accepts. */
  export interface ICfgBase {
    /** The provider's secret key. Posted to `endpoint`, so that URL gets the outbound-URL guard. */
    secret: string
    /** Override the global `fetch`, for a test double or an agent with a proxy configured. */
    fetch?: typeof globalThis.fetch
    /** Override the provider's siteverify URL. Refused unless it passes `assertSafeOutboundUrl`. */
    endpoint?: string
    /** Wall-clock ceiling on the provider call. Default 5s, at most 2^31-1ms. */
    timeoutMs?: number
    /** Host the widget is expected to have run on. Unset means the result reports it unchecked.
     *  Compared case-insensitively, since a hostname is. */
    expectedHostname?: string | string[]
    /** Ceiling on `challenge_ts` age. Default 5 minutes; 0 disables the check. */
    maxChallengeAgeMs?: number
    /** Dev-only: permit a plaintext `http:` endpoint, for a mock reachable by name - loopback and
     *  private hosts stay refused. `strict()` refuses it in production. */
    allowInsecureEndpoint?: boolean
  }
}
