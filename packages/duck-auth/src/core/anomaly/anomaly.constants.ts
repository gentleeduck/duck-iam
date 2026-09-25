import type { Anomaly, AuthImpossibleTravel } from './anomaly.types'

/* The ladder ------------------------------------------------------------------------------------ */

/** Conservative defaults. Step-up at 0.7; deny at 0.95. */
export const DEFAULT_ANOMALY_CONFIG: Anomaly.Cfg = {
  denyAt: 0.95,
  detectorTimeoutMs: 1_000,
  stepUpAt: 0.7,
  threshold: 0.7,
}

/** `setTimeout` overflows past this and silently uses 1ms instead, which abandons every detector. */
export const DETECTOR_TIMEOUT_MAX_MS = 2_147_483_647

/** The `reactions` slot meaning "any detector that emits this kind". Reserved, so no detector may
 *  register under it. */
export const REACTION_ANY_DETECTOR = '*'

/* Scoring ------------------------------------------------------------------------------------ */

/** Combine independent signals, saturating at 1. */
export function combineScores(scores: number[]): number {
  let remainder = 1
  for (const score of scores) remainder *= 1 - score
  // Rounded because the complement arithmetic leaves 0.19999999999999996 where a lone 0.2 went in,
  // and the score is compared against operator-written thresholds and written to an audit record.
  return Number((1 - remainder).toFixed(10))
}

/** Signals are documented as 0..1; a detector outside that range is a bug, not a veto. */
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

/** Bound on the User-Agent that goes into the hash, so a client cannot make us digest megabytes per
 *  request. Over it the header is truncated, not refused: bounding the input does not require
 *  declining to fingerprint the request. */
export const FINGERPRINT_UA_MAX_LENGTH = 1024

/** The same bound for the address. Over it there is nothing to parse a subnet out of, so the request
 *  lands in {@link FINGERPRINT_UNPARSED}. */
export const FINGERPRINT_IP_MAX_LENGTH = 64

/** The bucket a request that declines to identify itself lands in.
 *  SECURITY: never `null` from the default composer, which would switch the detector off for exactly
 *  the caller who chose to send no User-Agent. One shared bucket instead, so the first such request is
 *  a new device and the rest are the same one. */
export const FINGERPRINT_ABSENT = '\u0000absent'

/** The bucket an address we could not parse lands in, for the same reason and shared for the same one:
 *  hashing junk as-is made two unparseable strings two devices, which mints a `new-device` signal on
 *  demand wherever the ip comes from a header. */
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

/** The haversine gives km and the threshold is km/h, so the interval is converted once. */
export const MS_PER_HOUR = 3_600_000
