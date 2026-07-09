import type { IdentitiesFacet } from './identities.facet'

export const DEFAULT_IDENTITIES_CONFIG: IdentitiesFacet.Config = {
  softDeleteGracePeriodMs: 7 * 24 * 60 * 60 * 1000,
  profileMaxBytes: 16 * 1024,
}
