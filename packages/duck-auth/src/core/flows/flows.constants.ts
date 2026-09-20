import type { Flows } from './flows.types'

/** Overridden through `new Flows(..., cfg)`. */
export const DEFAULT_FLOWS_CONFIG: Flows.Cfg = {
  signInPurpose: 'signin',
}
