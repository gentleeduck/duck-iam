/** Session-drift policy: what each request is compared against, and the reaction a verdict carries. */
export namespace Hijack {
  export interface Cfg {
    /** Reaction on IP change. Default 'rotate'. */
    onIpChange?: Hijack.Reaction
    /**
     * What to do when the request omits a value the session recorded. Default `'soften'`, which
     * drops the configured reaction one notch so a proxy that strips a header cannot revoke every
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

  export type Reaction = 'ignore' | 'rotate' | 'mfa' | 'revoke'

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
