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
     * Caller-declared expected action; reCAPTCHA v3 returns the action the client tag emitted and
     * the verifier asserts equality. Overrides the verifier's own `expectedAction` when both are
     * set, so one wiring can still distinguish sign-in from sign-up.
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
    /** Dev-only: permit a plaintext or loopback `endpoint`. */
    allowInsecureEndpoint?: boolean
  }
}
