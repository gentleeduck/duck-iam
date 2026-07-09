export namespace Hijack {
  export interface Config {
    /** Reaction on IP change. Default 'rotate'. */
    onIpChange?: Hijack.Reaction
    /** Reaction on User-Agent change. Default 'mfa'. */
    onUserAgentChange?: Hijack.Reaction
  }

  export type Reaction = 'ignore' | 'rotate' | 'mfa' | 'revoke'

  export type Evaluation =
    | { ok: true }
    | {
        ok: false
        reaction: Hijack.Reaction
        signal: 'ip-change' | 'user-agent-change'
        from: string
        to: string
      }
}
