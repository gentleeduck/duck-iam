import type { Flows } from './flows.types'

/** Default flows facet config; overridden via `new Flows(..., cfg)`. */
export const DEFAULT_FLOWS_CONFIG: Flows.Cfg = {
  signInPurpose: 'signin',
}
