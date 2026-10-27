import type { Flows } from './flows.types'

/** Overridden through `new Flows(..., cfg)`. */
export const DEFAULT_FLOWS_CONFIG: Flows.Cfg = {
  signInPurpose: 'signin',
}

/** How long a sign-in stopped at its second factor waits for it. */
export const SIGN_IN_CHALLENGE_TTL_MS = 5 * 60 * 1000
