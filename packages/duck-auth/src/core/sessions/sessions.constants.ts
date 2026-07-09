import type { SessionsFacet } from './sessions.facet'

export const DEFAULT_SESSION_CONFIG: SessionsFacet.Config = {
  ttlMs: 7 * 24 * 60 * 60 * 1000,
  absoluteTtlMs: 30 * 24 * 60 * 60 * 1000,
  freshnessMs: 5 * 60 * 1000,
}
