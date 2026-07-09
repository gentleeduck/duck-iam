import type { FlowsFacet } from './flows.facet'

/** Default flows facet config; overridden via `new FlowsFacet(..., cfg)`. */
export const DEFAULT_FLOWS_CONFIG: FlowsFacet.Config = {
  signInPurpose: 'signin',
}
