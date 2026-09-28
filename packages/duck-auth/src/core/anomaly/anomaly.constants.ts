import type { Anomaly, AuthImpossibleTravel } from './anomaly.types'

/* The ladder ------------------------------------------------------------------------------------ */

/** Step up at 0.7, deny at 0.95, report from 0.7, and abandon a detector after one second. */
export const DEFAULT_ANOMALY_CONFIG: Anomaly.Cfg = {
  denyAt: 0.95,
  detectorTimeoutMs: 1_000,
  stepUpAt: 0.7,
  threshold: 0.7,
}

/** `setTimeout` overflows past this and silently uses 1ms instead, which abandons every detector. */
export const DETECTOR_TIMEOUT_MAX_MS = 2_147_483_647

/** How a `reactions` override outranks another when two signals force different decisions. */
export const DECISION_SEVERITY: Record<Anomaly.Decision, number> = { allow: 0, deny: 2, 'step-up': 1 }

/** The `reactions` slot meaning "any detector that emits this kind". Reserved, so no detector may
 *  register under it. */
export const REACTION_ANY_DETECTOR = '*'

/* Scoring ------------------------------------------------------------------------------------ */

/** Combine independent signals, saturating at 1. */
export function combineScores(scores: number[]): number {
  let remainder = 1
  for (const score of scores) remainder *= 1 - score
  // Rounded: the complement arithmetic turns a lone 0.2 into 0.19999999999999996, which misses a 0.2.
  return Number((1 - remainder).toFixed(10))
}

/** Into 0..1: a detector outside the range is a bug, not a veto. */
export function clampScore(score: number): number {
  return Math.min(1, Math.max(0, score))
}

/* Device fingerprint ------------------------------------------------------------------------- */

/** Emitted on first sight of a device, unless `Cfg.score` overrides it. */
export const FINGERPRINT_SCORE_DEFAULT = 0.7

/** Devices one identity may be remembered on before the least recently seen is evicted. */
export const FINGERPRINT_MAX_PER_IDENTITY = 50

/** How long a sighting counts as recent. 90 days, matching the usual "remember this device" span. */
export const FINGERPRINT_TTL_DEFAULT_MS = 90 * 24 * 60 * 60 * 1000

/** Bound on the User-Agent that is hashed; a longer one is truncated, not refused. */
export const FINGERPRINT_UA_MAX_LENGTH = 1024

/** Bound on the address; a longer one cannot be parsed and lands in {@link FINGERPRINT_UNPARSED}. */
export const FINGERPRINT_IP_MAX_LENGTH = 64

/** The bucket for a request with no User-Agent or no address.
 *  SECURITY: never `null`, which would switch the detector off for whoever sends neither. */
export const FINGERPRINT_ABSENT = '\u0000absent'

/** The bucket for an address that does not parse, shared so junk cannot mint a new device per request. */
export const FINGERPRINT_UNPARSED = '\u0000unparsed'

/* Impossible travel ---------------------------------------------------------------------------- */

/** Defaults for {@link AuthImpossibleTravel.Cfg}; both are refused unless finite and positive. */
export const DEFAULT_IMPOSSIBLE_TRAVEL_CONFIG: AuthImpossibleTravel.Cfg = {
  maxKmPerHour: 900,
  minElapsedMs: 60_000,
}

/** How many times over `maxKmPerHour` scores a 1. Twice the limit is as suspicious as it gets. */
export const IMPOSSIBLE_TRAVEL_FULL_SCORE_OVERSHOOT = 2

/** Mean radius, km, for the haversine distance. */
export const EARTH_RADIUS_KM = 6371

/** For km/h from a millisecond interval. */
export const MS_PER_HOUR = 3_600_000
