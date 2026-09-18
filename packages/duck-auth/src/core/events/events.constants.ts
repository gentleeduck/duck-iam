import type { Events } from './events.types'

/**
 * Keyed rather than a bare array so the compiler proves it exhaustive: a name added to `EventMap`
 * and not here is TS2739 at this declaration, which is how a wildcard subscriber stopped silently
 * receiving a set that differed from the map.
 */
const EVERY_EVENT_KEYED: Record<Events.EventName, true> = {
  'authz.revoked': true,
  'identity.impersonated': true,
  'identity.linked': true,
  'identity.unlinked': true,
  lockout: true,
  'maintenance.off': true,
  'maintenance.on': true,
  'readonly.off': true,
  'readonly.on': true,
  'mfa.enrolled': true,
  'mfa.removed': true,
  'recovery.mfa.escalated': true,
  'recovery.password.completed': true,
  'recovery.password.requested': true,
  'session.created': true,
  'session.revoked': true,
  'session.rotated': true,
  'signin.failed': true,
  'signin.success': true,
  'signup.completed': true,
  suspicious: true,
}

/** Every name in `Events.EventMap`, for materialising a `'*'` subscription. */
export const EVERY_EVENT = Object.keys(EVERY_EVENT_KEYED) as Events.EventName[]
