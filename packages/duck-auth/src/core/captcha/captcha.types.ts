/** The verifier contract every built-in captcha implementation satisfies. */
export namespace AuthCaptcha {
  export interface IVerifier {
    readonly id: string
    verify(input: AuthCaptcha.IVerifyInput): Promise<AuthCaptcha.IVerifyResult>
  }

  export interface IVerifyInput {
    token: string
    remoteIp?: string
    /**
     * Expected action, asserted against the one Turnstile and reCAPTCHA v3 echo back. Overrides the
     * verifier's own when both are set, so one wiring distinguishes sign-in from sign-up.
     *
     * WARN: hCaptcha answers with no `action`, so asking for one there refuses every call.
     */
    expectedAction?: string
    /** Overrides the verifier's `expectedHostname` for this one call. */
    expectedHostname?: string
  }

  export interface IVerifyResult {
    success: boolean
    /** Score 0..1 (reCAPTCHA v3); undefined for boolean providers. */
    score?: number
    /** Provider-side error tokens (`'invalid-input-secret'`, etc.). */
    errorCodes?: string[]
    /** Surfaced whether or not this verifier was configured to check them, so a caller can apply its own
     *  rule rather than being told only pass or fail. */
    hostname?: string
    action?: string
    challengeTs?: string
  }

  /** What every siteverify-style verifier accepts. */
  export interface ICfgBase {
    secret: string
    fetch?: typeof globalThis.fetch
    endpoint?: string
    /** Wall-clock ceiling on the provider call. Default 5s. */
    timeoutMs?: number
    /** Host the widget is expected to have run on. Unset means the result reports it unchecked. */
    expectedHostname?: string | string[]
    /** Ceiling on `challenge_ts` age. Default 5 minutes; 0 disables the check. */
    maxChallengeAgeMs?: number
    /** Dev-only: permit a plaintext `http:` `endpoint`. A loopback or private host stays refused
     *  either way — the SSRF guard does not read this flag. */
    allowInsecureEndpoint?: boolean
  }
}
