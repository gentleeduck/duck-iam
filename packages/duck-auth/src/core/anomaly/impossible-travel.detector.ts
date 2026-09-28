import { AuthError } from '~/core/errors'
import {
  DEFAULT_IMPOSSIBLE_TRAVEL_CONFIG,
  EARTH_RADIUS_KM,
  IMPOSSIBLE_TRAVEL_FULL_SCORE_OVERSHOOT,
  MS_PER_HOUR,
} from './anomaly.constants'
import type { Anomaly, AuthImpossibleTravel } from './anomaly.types'

/** Whether a pair is a place on earth, within ±90 / ±180. NaN and Infinity fail both bounds. */
function isCoordinate(lat: number, lon: number): boolean {
  return Math.abs(lat) <= 90 && Math.abs(lon) <= 180
}

/** Haversine distance in km between two (lat, lon) pairs. */
function haversineKm(a: { lat: number; lon: number }, b: { lat: number; lon: number }): number {
  const toRad = (x: number): number => (x * Math.PI) / 180
  const dLat = toRad(b.lat - a.lat)
  const dLon = toRad(b.lon - a.lon)
  const s = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(a.lat)) * Math.cos(toRad(b.lat)) * Math.sin(dLon / 2) ** 2
  return 2 * EARTH_RADIUS_KM * Math.asin(Math.sqrt(s))
}

/**
 * Emits `impossible-travel` when the distance from the last position over the time since implies a
 * speed above `maxKmPerHour`. It reads positions and never writes them: `getLastSeen` answers from
 * wherever the host records one, and `req.geo` arrives through `getCaller`.
 *
 * WARN: never record a position from a denied request. It moves "last seen" to the attacker, and their
 * next request is no travel at all.
 */
export function authImpossibleTravelDetector(opts: {
  /** The last position the host recorded for the identity. `at` is epoch ms, like `req.now`: seconds read
   *  as a trip of decades, and nothing ever scores. */
  getLastSeen: (identityId: string) => Promise<{ lat: number; lon: number; at: number } | null>
  config?: Partial<AuthImpossibleTravel.Cfg>
}): Anomaly.Detector {
  const cfg: AuthImpossibleTravel.Cfg = {
    maxKmPerHour: opts.config?.maxKmPerHour ?? DEFAULT_IMPOSSIBLE_TRAVEL_CONFIG.maxKmPerHour,
    minElapsedMs: opts.config?.minElapsedMs ?? DEFAULT_IMPOSSIBLE_TRAVEL_CONFIG.minElapsedMs,
  }
  if (!Number.isFinite(cfg.maxKmPerHour) || cfg.maxKmPerHour <= 0) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `authImpossibleTravelDetector: maxKmPerHour must be a finite positive number (got ${cfg.maxKmPerHour})`,
    })
  }
  // Zero divides by zero, and the finite check below would discard the fastest trip there is.
  if (!Number.isFinite(cfg.minElapsedMs) || cfg.minElapsedMs <= 0) {
    throw new AuthError('AUTH_MISCONFIGURED', {
      detail: `authImpossibleTravelDetector: minElapsedMs must be a finite positive number (got ${cfg.minElapsedMs})`,
    })
  }
  return {
    id: 'impossible-travel',
    async evaluate({ identity, req }) {
      // `=== undefined` rather than truthiness, so a lat or lon of 0 stays a valid signal.
      if (req.geo?.lat === undefined || req.geo?.lon === undefined) return []
      if (!isCoordinate(req.geo.lat, req.geo.lon)) return []
      const last = await opts.getLastSeen(identity.id)
      if (!last) return []
      if (!isCoordinate(last.lat, last.lon) || !Number.isFinite(last.at)) return []
      // A floor, not a skip: a teleport inside it still scores, and a last-seen in the future loses to it.
      const elapsedMs = req.now - last.at
      const intervalMs = Math.max(elapsedMs, cfg.minElapsedMs)
      const distanceKm = haversineKm({ lat: last.lat, lon: last.lon }, { lat: req.geo.lat, lon: req.geo.lon })
      const speedKmH = distanceKm / (intervalMs / MS_PER_HOUR)
      // Reachable only through `req.now`, the one number here nothing has validated.
      if (!Number.isFinite(speedKmH)) return []
      if (speedKmH <= cfg.maxKmPerHour) return []
      const overshoot = speedKmH / cfg.maxKmPerHour
      const score = Math.min(1, overshoot / IMPOSSIBLE_TRAVEL_FULL_SCORE_OVERSHOOT)
      return [
        {
          kind: 'impossible-travel',
          score,
          evidence: {
            distanceKm: Math.round(distanceKm),
            // Both: they differ when the reading is odd (a gap under the floor, a future last-seen), and
            // `speedKmH` is over `intervalMs`.
            elapsedMs,
            intervalMs,
            speedKmH: Math.round(speedKmH),
            threshold: cfg.maxKmPerHour,
          },
        },
      ]
    },
  }
}
