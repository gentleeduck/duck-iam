import type { Sessions } from './sessions.types'

export const DEFAULT_SESSION_CONFIG: Sessions.Cfg = {
  ttlMs: 7 * 24 * 60 * 60 * 1000,
  absoluteTtlMs: 30 * 24 * 60 * 60 * 1000,
  freshnessMs: 5 * 60 * 1000,
}
