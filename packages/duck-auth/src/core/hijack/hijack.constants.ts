import type { Hijack } from './hijack.types'

export const DEFAULT_HIJACK_POLICY: Required<Hijack.Cfg> = {
  onIpChange: 'rotate',
  onMissingSignal: 'soften',
  onUserAgentChange: 'mfa',
}
