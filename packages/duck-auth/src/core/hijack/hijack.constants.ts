import type { Hijack } from './hijack.types'

export const DEFAULT_HIJACK_POLICY: Required<Hijack.Cfg> = {
  onIpChange: 'rotate',
  onMissingSignal: 'soften',
  onUserAgentChange: 'mfa',
}

/** How a reaction outranks another when both baselines drift: revoke > mfa > rotate > ignore. */
export const HIJACK_REACTION_SEVERITY: Record<Hijack.Reaction, number> = { ignore: 0, mfa: 2, revoke: 3, rotate: 1 }
