import type { Identities } from './identities.types'

export const DEFAULT_IDENTITIES_CONFIG: Identities.Cfg = {
  softDeleteGracePeriodMs: 7 * 24 * 60 * 60 * 1000,
  profileMaxBytes: 16 * 1024,
}
