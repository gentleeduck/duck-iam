/** Session-drift policy: what each request is compared against, and the reaction a verdict carries. */
export namespace Hijack {
  /** How the hijack check reacts to each kind of drift. */
  export interface Cfg {
    /** Reaction on IP change. Default 'rotate'. */
    onIpChange?: Hijack.Reaction
    /**
     * What to do when the request omits a value the session recorded. Default `'soften'`, which
     * drops a `'revoke'` or `'mfa'` to `'rotate'` so a proxy that strips a header cannot revoke every
     * session behind it.
     *
     * SECURITY: sending no header is entirely the caller's choice, so `'soften'` is also a free way
     * for an attacker holding a stolen session to turn a `revoke` into a `rotate`. A deployment
     * whose proxies are known to preserve these headers should set `'strict'`, which carries the
     * configured reaction in full. A missing *baseline* is softened either way: a session recorded
     * before the value was captured is a deployment artifact no caller can influence.
     */
    onMissingSignal?: 'soften' | 'strict'
    /** Reaction on User-Agent change. Default 'mfa'. */
    onUserAgentChange?: Hijack.Reaction
  }

  /** `'revoke'` ends the session and refuses, `'mfa'` refuses with a step-up, `'rotate'` is the caller's to
   *  perform, and `'ignore'` records the drift alone. `'mfa'` refuses every request an actor wrapper covers, so
   *  the route completing the step-up sits outside it and hands `completeStepUp` the request's fingerprint. */
  export type Reaction = 'ignore' | 'rotate' | 'mfa' | 'revoke'

  /** One request's verdict: ok, or what drifted and the reaction. */
  export type Evaluation =
    | { ok: true }
    | {
        ok: false
        reaction: Hijack.Reaction
        /** Which baseline drifted. */
        signal: 'ip-change' | 'user-agent-change'
        from: string
        to: string
      }
}
