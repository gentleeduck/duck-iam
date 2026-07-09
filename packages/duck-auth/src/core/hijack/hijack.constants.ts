import type { Hijack } from './hijack.types'

export const DEFAULT_HIJACK_POLICY: Required<Hijack.Config> = {
  onIpChange: 'rotate',
  onUserAgentChange: 'mfa',
}
